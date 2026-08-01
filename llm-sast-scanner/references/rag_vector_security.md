---
name: rag_vector_security
version: "0.1"
description: RAG / vector & embedding weaknesses — permission-blind retrieval, cross-tenant leakage in shared vector stores, indirect injection via embedded documents, and embedding exposure (OWASP LLM08, CWE-285/863/200)
---

# RAG / Vector & Embedding Security (LLM08)

Retrieval-Augmented Generation puts a vector database between users and an LLM. The database holds document chunks whose access controls are often *weaker than the source documents* — and whose contents are fed straight into the model. Static analysis checks that retrieval is permission- and tenant-scoped, that indexed documents are validated before embedding, and that raw embeddings are not exposed.

The core pattern: *a similarity search runs without the requesting user's authorization/tenant filter, an attacker-supplied document is embedded and later retrieved into a prompt, or raw embedding vectors are returned to clients.*

## What It Is (and Is Not)

**What it IS**
- **Permission-blind retrieval**: `similarity_search` over the whole index regardless of who is asking → users receive chunks from documents they cannot read
- **Cross-tenant leakage**: all tenants share one collection/namespace with no `tenant_id` filter, or the filter is applied client-side and bypassable
- **Indirect injection via RAG**: untrusted documents are embedded without validation; retrieved chunks carry hidden instructions/zero-width text that reach the model (chains with `prompt_injection.md`)
- **Embedding exposure / inversion**: API returns raw embedding vectors, enabling reconstruction of sensitive source text
- **Knowledge-base poisoning**: an attacker who can add documents biases or backdoors future answers
- **Retrieval-ranking / top-k poisoning**: a crafted chunk (keyword stuffing, embedding-space crafting) outranks legitimate sources into the top-k — ranking by raw similarity alone, with no per-source trust/authority weighting, lets a poisoned doc dominate the context
- **Context-window exhaustion**: a flood of retrieved chunks (many or oversized) pushes the system prompt / safety instructions out of the window — no per-source context-share cap, and retrieved content placed ahead of the system prompt
- **Citation spoofing**: the model emits fabricated or mismatched citations rendered to the user without verifying the cited claim against the actual retrieved span

**What it is NOT**
- The downstream prompt-following behavior itself — see `prompt_injection.md` (RAG is the *delivery channel*)
- Generic IDOR/authZ on REST endpoints unrelated to vector retrieval — see `idor.md` / `privilege_escalation.md`
- In-process shared client/cache leaks not specific to vector stores — see `shared_client_cache_leak.md`
- Model/training-data supply chain — see `ml_supply_chain_poisoning.md`

## Source -> Sink Pattern

**Sources** — user query + identity (`user_id`, `tenant_id`, roles); ingested documents (uploads, crawled pages, tickets) destined for embedding.

**Sinks** — `vector_db.similarity_search` / `.query` / `.search` (retrieval into prompt context); the embedding endpoint returning vectors; the prompt assembled from retrieved chunks.

**Barriers**
- Metadata permission filter applied **at query time** (`owner_id`/`allowed_roles`/`access_level`) plus a post-retrieval authorization re-check (defense in depth)
- Per-tenant collections/namespaces, or a mandatory `tenant_id` filter verified server-side
- Document validation before embedding (length, injection patterns, zero-width/hidden chars), provenance tracking
- Return only content + scores from search APIs — never raw embeddings; add noise/quantize if vectors must leave
- Trust/authority-weighted ranking plus a per-source context-share cap, so no single (possibly poisoned) source dominates the top-k or the window; keep the system prompt fixed and positioned so retrieved data cannot displace it
- Verify model-emitted citations against the retrieved spans (claim-to-source grounding) before rendering them to the user

## Recon Indicators

| Signal | Grep / structural targets |
|--------|----------------------------|
| Vector store usage | `similarity_search`, `\.query\(`, `vector_db`, `VectorStore`, `chromadb`, `pinecone`, `weaviate`, `qdrant`, `faiss`, `pgvector`, `Milvus`, `as_retriever` |
| Retrieval without filter | `similarity_search(` / `.query(` calls with no `filter=`/`where=`/`namespace=`/`tenant` argument and no surrounding authz check |
| Embedding ingestion | `embed`, `encode(`, `add_documents`, `upsert(`, `\.add\(`, `from_documents` on user/crawled content |
| Raw embedding egress | endpoint returning `embedding`, `.tolist()`, `vector`, `embeddings` in a JSON response |
| Shared collection | single `create_collection(`/`Index(` reused for all tenants; `tenant_id` only in app code, not in the query filter |
| Score-gated decision | a threshold compared against a retrieval score — `similarity_threshold`, `min_score`, `score >`/`distance <`, `np.max(`/`np.min(` over `.search()`/`distances` output — sitting near `IndexFlatL2`, `hnsw:space`, `<->`/`<=>` |

## Vulnerable Conditions

- `similarity_search(query, k)` runs with no permission/tenant filter; results are placed in the prompt for any user.
- Multi-tenant data shares one collection and retrieval does not constrain by tenant (or the constraint is client-side only).
- User-supplied or crawled documents are embedded without scanning for injection markers or hidden characters.
- An `/embed` endpoint returns raw vectors for arbitrary input.
- Any user with write access to the index can insert documents that later steer answers for other users.
- Top-k ranks by raw similarity only (no trust/authority weight, no per-source cap), so a crafted high-similarity chunk outranks legitimate sources.
- Retrieved chunks are concatenated unbounded — and ahead of the system prompt — so a flood of retrieved content displaces the system/safety instructions.
- Model-emitted citations are rendered without checking that the cited span actually supports the claim.
- A security decision (block / admit / auto-dismiss) is gated on a retrieval score whose **polarity, range or reducer** disagrees with the index's metric — an L2 *distance* read as if it were a 0–1 similarity — which inverts the control rather than breaking it.

## Score-gated decisions: metric polarity, range & aggregation

When a **security decision** rides on a vector score — refuse a prompt close to a known-attack corpus, auto-dismiss a finding matching a known false positive, admit a login whose voice/face/answer embedding is close enough, drop an upload matching a known-abuse set — the guard is only as correct as its reading of the metric. **Distance and similarity run in opposite directions, and many vector APIs return a distance while being named `similarity`.** One wrong comparison operator inverts the control instead of breaking it: nothing raises, the scores look plausible, and the gate admits precisely the inputs it exists to stop. Resolve three things at the call site — all decidable statically.

**1. Polarity — what does the number actually mean?**

| API | Returns | Closest match is |
|-----|---------|------------------|
| `faiss.IndexFlatL2`, `IndexIVFFlat(…, METRIC_L2)` `.search()` | squared L2 **distance** | **lowest** |
| `faiss.IndexFlatIP` on L2-normalized vectors | inner product = cosine **similarity** | highest |
| LangChain `similarity_search_with_score` | the store's **native** metric — a distance for FAISS-L2/Chroma, despite the name | depends on store |
| LangChain `similarity_search_with_relevance_scores` | normalized **similarity**, 0–1 | highest |
| Chroma `.query()` → `distances` | **distance** (L2 or cosine distance per `hnsw:space`) | lowest |
| pgvector `<->` / `<=>` / `<#>` | L2 **distance** / cosine **distance** (1−cos) / **negative** inner product | lowest |
| Qdrant, Pinecone, Weaviate `score` (Weaviate also exposes `distance`) | **similarity** / **distance** | highest / lowest |
| `sklearn` `cosine_similarity` vs `cosine_distances`; `scipy.spatial.distance.cosine` | **similarity** vs **distance** | highest / lowest |

**2. Comparison direction — does the operator match the polarity?** "Close enough" is `distance <= threshold` **or** `similarity >= threshold`. A `distance < threshold` branch that means *safe / no match* is the inversion.

**3. Aggregation — does the reducer match?** The nearest neighbour is `min(distances)` or `max(similarities)`. Mixing them (`max` over a distance array) reads the *worst* neighbour as the best match. Fixing the reducer alone does **not** fix a wrong operator: with `min(distances) < threshold` still meaning "safe", a verbatim corpus entry scores ≈ 0 and passes every time.

**The static tell** is a disagreement between the index's metric and the threshold's documented range or comparison: an `IndexFlatL2` index whose threshold is commented "1.0 = identical", a distance clamped by `min(score, 1.0)` and rendered as a percentage, or a field named `similarity_threshold` fed from a `distances` array. Ranges corroborate it — cosine similarity ∈ [−1, 1], cosine distance ∈ [0, 2], squared L2 on normalized vectors ∈ [0, 4], raw L2 unbounded — so a threshold documented as 0–1 cannot be a raw L2 distance.

**Report the failure direction, not "a tuning bug".** Which way the control fails determines severity:

- **Blocklist gate** (refuse when close — injection/jailbreak screens, banned-content matching, known-abuse dedup): inversion **admits every known-bad input**, verbatim corpus entries included, while refusing unrelated benign traffic. A complete bypass of the control; severity follows whatever sits behind it.
- **Allowlist gate** (admit when close — biometric/voice/security-answer matching, fuzzy identity proofing): inversion **admits arbitrary non-matching input** — authentication bypass.
- **Auto-dismiss gate** (suppress when close — known-false-positive filters, alert/ticket dedup): inversion **suppresses novel unrelated events** and re-surfaces known-benign ones, deleting real signal silently.

The same defect appears outside RAG wherever a threshold gates on a computed score: an anomaly/fraud model assumed to emit a risk score when it emits a normality score, and perceptual-hash or edit-distance matching (`Levenshtein` **distance** vs `ratio`).

## Vector-store data-plane & infrastructure

The conditions above are retrieval-*logic* flaws; the vector store is also a **database and a deployable service** with its own sinks — statically detectable and frequently missed:

- **Metadata-filter / query-language injection** — user input concatenated into the store's **structured filter** rather than bound: a Mongo-style selector (`collection.query(where=request.json["filter"])`), a Qdrant/Weaviate `where`/payload filter, **pgvector raw SQL** (`f"… ORDER BY embedding <=> '{user}'"`), or a Redis-Stack `EVAL`/Lua body. Bypasses the tenant/permission scoping or dumps the collection — the *filter expression itself* is an injection sink (cross-ref `nosql_injection.md`, `sql_injection.md`).
- **Store deployment exposure** — the vector DB reachable with **no auth / default credentials**, bound to `0.0.0.0`/public, or client TLS disabled: `chromadb.HttpClient(host="0.0.0.0")` with no auth token, `QdrantClient(url=…, api_key=None)`, `verify=False`/`ssl_verify=False`, compose exposing `6333`/`8080`/`19530`, or a security group opening the vector port to `0.0.0.0/0`. Anonymous read enables inversion/MIA, write enables poisoning, delete enables destruction (cross-ref `cleartext_transmission.md`, `certificate_validation.md`). Also flag a **client endpoint built from request input** (`QdrantClient(url=f"https://{tenant_host}")`) — attacker redirects the client to a malicious store (cross-ref `ssrf.md`).
- **ANN index-file unsafe deserialization (RCE)** — loading a serialized index from an untrusted/unvalidated path executes pickle: `FAISS.load_local(path, allow_dangerous_deserialization=True)` (the flag is the exact signal), `pickle.load` of a `.faiss`/`.ann`/`.pkl` index, or hnswlib/Annoy binaries from a user-supplied path (cross-ref `insecure_deserialization.md`).
- **Ingestion-loader SSRF** — document loaders that **fetch the source URL carried in document metadata** during indexing (LangChain `WebBaseLoader`, `from_documents` following a metadata `source`/`url`) let an attacker plant an internal URL (`169.254.169.254`, `file://`, internal hosts) to pivot/exfiltrate at index time (cross-ref `ssrf.md`).
- **Auto-reindex self-poisoning** — a pipeline that writes its **own LLM output / agent memory back into the indexed corpus** with no human review (`vectorstore.add_texts(llm_response)`, online-learning/auto-update config) creates a self-amplifying poison loop where one injection compounds across cycles.
- **Store-destruction / unbounded-retrieval DoS** — `delete_collection`/`drop`/`truncate` reachable from a low-privilege caller (vector DBs have no recycle-bin/MVCC), or a user-controlled `n_results`/`top_k`/batch-upsert size with no cap (cross-ref `denial_of_service.md`).

## Safe Patterns

```python
# SAFE — permission-aware retrieval: filter at query time + re-verify after
perm_filter = {"$or": [
    {"access_level": "public"},
    {"owner_id": user_id},
    {"allowed_roles": {"$in": user_roles}},
]}
hits = db.similarity_search(embed(query), k=k*2, filter=perm_filter)
results = [h for h in hits if user_authorized(user_id, user_roles, h.metadata)][:k]
```

```python
# SAFE — strict tenant isolation via per-tenant collection, verified on read
def collection(tenant_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", tenant_id): raise ValueError("bad tenant")
    return client.get_or_create_collection(f"tenant_{tenant_id}_docs")
res = collection(tenant_id).query(query_texts=[q], n_results=k)
res = [d for d, m in zip(res["documents"][0], res["metadatas"][0]) if m.get("tenant_id") == tenant_id]
```

```python
# SAFE — validate documents before embedding (injection + hidden chars)
INJ = [r"ignore\s+(previous|all)\s+instructions", r"<\|.*?\|>", r"\[/?INST\]", r"system\s*:"]
def safe_to_index(text: str) -> bool:
    if any(re.search(p, text, re.I) for p in INJ): return False
    if re.search(r"[\u200b-\u200f\u2060-\u206f]", text): return False   # zero-width
    return 10 <= len(text) <= 50000
```

```python
# SAFE — search API returns content + score only, never raw vectors
return jsonify({"results": [{"content": r.content, "score": float(r.score)} for r in hits]})
```

```python
# SAFE — polarity, operator and reducer agree; the threshold's range is asserted, not assumed
index = faiss.IndexFlatL2(dim)                     # L2 => DISTANCE, 0.0 == identical
MAX_DISTANCE = 0.35                                # squared L2 on normalized vectors, range [0, 4]

def is_blocked(prompt: str) -> bool:
    distances, _ = index.search(embed([prompt]), NEIGHBOURS)
    nearest = float(np.min(distances[0]))          # nearest == smallest distance
    return nearest <= MAX_DISTANCE                 # close to a known attack => refuse
```

```python
# SAFE — trust-weighted ranking + per-source context cap; system prompt fixed, retrieved data after it
hits = db.similarity_search(embed(query), k=k*4, filter=perm_filter)
ranked = sorted(hits, key=lambda h: h.score * SOURCE_TRUST.get(h.metadata["source"], 0.5), reverse=True)
budget, per_source = [], {}
for h in ranked:                                  # cap any one source's share of the window
    s = h.metadata["source"]
    if per_source.get(s, 0) >= MAX_PER_SOURCE: continue
    per_source[s] = per_source.get(s, 0) + 1
    budget.append(h)
    if len(budget) >= k: break
# system prompt is fixed and the message role keeps it out of reach of retrieved data
messages = [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{datamark([h.content for h in budget])}\n\nQ: {query}"}]
```

```python
# SAFE — verify each citation is grounded in its retrieved span before rendering
for marker, span_id in parse_citations(resp):
    if span_id not in retrieved or not claim_supported_by(resp, marker, retrieved[span_id]):
        raise CitationError(f"unsupported/spoofed citation {marker}")   # NLI or span-overlap check
```

## Severity & Triage

- Cross-tenant / cross-user retrieval of sensitive chunks: **High/Critical** (treat as data exposure / IDOR-class).
- Indirect injection via unvalidated indexed documents that reach the model: **High** (chain with `prompt_injection`; impact follows what the agent can then do — see `excessive_agency.md`).
- Raw embedding exposure of sensitive corpora: **Medium** (inversion risk).
- Inverted polarity/operator on a score that gates a security decision: severity of the bypassed control, not of the score bug — a blocklist screen that admits its whole corpus is **High/Critical**; a ranking-only score is **Info**.
- Downgrade when the corpus is fully public/non-sensitive, or when a query-time filter plus post-retrieval authz check provably scope results.

## Common False Alarms

- A single-tenant or wholly public knowledge base with no per-user authorization requirement.
- Retrieval filtered server-side by an enforced `tenant_id`/permission predicate with a post-check.
- Embedding endpoints that are internal-only and never expose vectors to untrusted callers.
- Document ingestion limited to trusted, authenticated internal sources (verify the ingestion path's trust).
- A score whose metric genuinely is a similarity — `IndexFlatIP` on normalized vectors, `similarity_search_with_relevance_scores`, a Qdrant/Pinecone `score` — reduced with `max` and compared with `>=`. Polarity and operator agree; flag only the disagreement.
- A retrieval score used solely for ranking, ordering or display with no threshold gating a decision: polarity affects result quality, not a control.

## References

- OWASP LLM08:2025 Vector and Embedding Weaknesses
- CWE-285 (Improper Authorization), CWE-863 (Incorrect Authorization), CWE-200 (Information Exposure), CWE-697 (Incorrect Comparison)
- Related: `prompt_injection.md`, `idor.md`, `shared_client_cache_leak.md`, `ml_supply_chain_poisoning.md`
