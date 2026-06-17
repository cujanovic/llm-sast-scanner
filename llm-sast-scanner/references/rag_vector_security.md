---
name: rag_vector_security
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

## Recon Indicators

| Signal | Grep / structural targets |
|--------|----------------------------|
| Vector store usage | `similarity_search`, `\.query\(`, `vector_db`, `VectorStore`, `chromadb`, `pinecone`, `weaviate`, `qdrant`, `faiss`, `pgvector`, `Milvus`, `as_retriever` |
| Retrieval without filter | `similarity_search(` / `.query(` calls with no `filter=`/`where=`/`namespace=`/`tenant` argument and no surrounding authz check |
| Embedding ingestion | `embed`, `encode(`, `add_documents`, `upsert(`, `\.add\(`, `from_documents` on user/crawled content |
| Raw embedding egress | endpoint returning `embedding`, `.tolist()`, `vector`, `embeddings` in a JSON response |
| Shared collection | single `create_collection(`/`Index(` reused for all tenants; `tenant_id` only in app code, not in the query filter |

## Vulnerable Conditions

- `similarity_search(query, k)` runs with no permission/tenant filter; results are placed in the prompt for any user.
- Multi-tenant data shares one collection and retrieval does not constrain by tenant (or the constraint is client-side only).
- User-supplied or crawled documents are embedded without scanning for injection markers or hidden characters.
- An `/embed` endpoint returns raw vectors for arbitrary input.
- Any user with write access to the index can insert documents that later steer answers for other users.

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

## Severity & Triage

- Cross-tenant / cross-user retrieval of sensitive chunks: **High/Critical** (treat as data exposure / IDOR-class).
- Indirect injection via unvalidated indexed documents that reach the model: **High** (chain with `prompt_injection`; impact follows what the agent can then do — see `excessive_agency.md`).
- Raw embedding exposure of sensitive corpora: **Medium** (inversion risk).
- Downgrade when the corpus is fully public/non-sensitive, or when a query-time filter plus post-retrieval authz check provably scope results.

## Common False Alarms

- A single-tenant or wholly public knowledge base with no per-user authorization requirement.
- Retrieval filtered server-side by an enforced `tenant_id`/permission predicate with a post-check.
- Embedding endpoints that are internal-only and never expose vectors to untrusted callers.
- Document ingestion limited to trusted, authenticated internal sources (verify the ingestion path's trust).

## References

- OWASP LLM08:2025 Vector and Embedding Weaknesses
- CWE-285 (Improper Authorization), CWE-863 (Incorrect Authorization), CWE-200 (Information Exposure)
- Related: `prompt_injection.md`, `idor.md`, `shared_client_cache_leak.md`, `ml_supply_chain_poisoning.md`
