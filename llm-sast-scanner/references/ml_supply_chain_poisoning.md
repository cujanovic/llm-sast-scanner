---
name: ml_supply_chain_poisoning
description: ML/AI model supply chain and data/model poisoning — unsafe model deserialization (pickle/torch.load), remote-code model loading, unverified models & adapters, unpinned ML deps, and unvalidated training/fine-tuning data (OWASP LLM03/LLM04, CWE-502/494/1357/829)
---

# ML Supply Chain & Data/Model Poisoning (LLM03 / LLM04)

AI systems pull in pre-trained models, adapters, datasets, and ML libraries from external registries. Two adjacent risks live here: the **supply chain** (a model file or dependency that executes code or is tampered) and **poisoning** (training/fine-tuning/RAG data manipulated to implant bias or backdoors). Static analysis flags unsafe model loading, remote-code execution paths during model init, unverified/unpinned artifacts, and ingestion of unvalidated training data.

The core pattern: *a model, adapter, or dataset from an untrusted/unverified source is loaded via a code-executing deserializer or with remote code enabled, or training/fine-tuning data is consumed with no integrity or content validation.*

## What It Is (and Is Not)

**What it IS**
- **Unsafe model deserialization**: `pickle.load`, `torch.load(...)` without `weights_only=True`, `joblib.load`, `numpy.load(allow_pickle=True)`, `dill`, Keras `.h5`/Lambda layers — pickle executes arbitrary code on load (CWE-502)
- **Remote-code model loading**: `from_pretrained(..., trust_remote_code=True)` runs repo-hosted Python at import
- **Unverified artifacts**: models/LoRA-PEFT adapters/datasets loaded by name from arbitrary orgs with no hash/signature/allowlist (CWE-494/829)
- **Unpinned ML dependencies**: `transformers`, `torch`, `langchain`, etc. with no version pin / hash, enabling substitution (see also `supply_chain_security.md`, `dependency_confusion.md`)
- **Data/model poisoning**: training/fine-tuning/RAG ingestion with no source verification, checksum, or content scan (backdoor triggers, injected instructions, anomalous examples)

**What it is NOT**
- Generic application dependency integrity (lockfiles/SRI/lifecycle scripts) — see `supply_chain_security.md`
- Internal-package shadowing by a public registry — see `dependency_confusion.md`
- Untrusted documents poisoning a live RAG index at query time — see `rag_vector_security.md`
- Insecure deserialization of ordinary app data (not model artifacts) — see `insecure_deserialization.md`

## Source -> Sink Pattern

**Sources** — externally-sourced model/adapter/dataset references (Hub IDs, URLs, paths), uploaded or crawled training data, third-party fine-tuning corpora.

**Sinks** — model/artifact load via a code-executing deserializer or `trust_remote_code=True`; training loop / fine-tuning consuming unvalidated data; embedding ingestion of unvalidated documents.

**Barriers**
- Safe serialization formats: `safetensors` for weights; `torch.load(..., weights_only=True)`; `numpy.load(allow_pickle=False)`
- `trust_remote_code=False` (default-deny on repo code execution)
- Artifact allowlist + checksum/signature verification before load; pin orgs to a trusted set
- Pinned, hash-verified ML dependencies; ML-BOM tracking
- Training-data provenance: trusted-source registry, checksums/versioning, content scanning for poisoning indicators, sandboxed processing of untrusted data

## Recon Indicators

| Signal | Grep / structural targets |
|--------|----------------------------|
| Unsafe model load | `pickle\.load`, `torch\.load\(` without `weights_only=True`, `joblib\.load`, `numpy\.load\(.*allow_pickle\s*=\s*True`, `dill\.load`, `keras\.models\.load_model` |
| Remote-code load | `from_pretrained\([^)]*trust_remote_code\s*=\s*True`, `AutoModel.*trust_remote_code=True`, `AutoTokenizer.*trust_remote_code=True` |
| Unverified artifacts | `from_pretrained\("` / `PeftModel\.from_pretrained\(` / `hf_hub_download\(` with a non-allowlisted/variable org; `revision` absent (no commit pin) |
| Unpinned ML deps | `transformers`, `torch`, `langchain`, `sentence-transformers`, `vllm` in requirements with no `==`/hash |
| Data ingestion | `load_dataset(`, `prepare_fine_tuning_data`, `train(` consuming files/URLs with no checksum/validation step nearby |

## Vulnerable Conditions

- A model/adapter/checkpoint is loaded with `pickle`/`torch.load` (default) / `joblib` / `allow_pickle=True` from a source that is not fully trusted.
- `from_pretrained(..., trust_remote_code=True)` (or equivalent) executes arbitrary repository code.
- Models/datasets are fetched by name from arbitrary orgs with no hash/signature check or org allowlist, and without a pinned `revision`.
- ML dependencies are unpinned/unhashed (substitution / confusion risk).
- Training, fine-tuning, or knowledge-base data is ingested with no provenance, checksum, or content validation.

## Safe Patterns

```python
# SAFE — safetensors / weights-only loading (no arbitrary code execution)
from safetensors.torch import load_file
weights = load_file("model.safetensors")
# or, for torch checkpoints:
state = torch.load("model.pt", weights_only=True)
```

```python
# SAFE — verified, allowlisted model load with no remote code, pinned revision
TRUSTED_ORGS = {"meta-llama", "google", "mistralai"}
def load_model(name: str, revision: str):
    org = name.split("/", 1)[0]
    if org not in TRUSTED_ORGS:
        raise ValueError(f"untrusted model org: {org}")
    return AutoModel.from_pretrained(
        name, revision=revision,          # pin to a commit/tag
        trust_remote_code=False,          # never execute repo code
        use_safetensors=True,
    )
```

```text
# SAFE — pinned, hash-verified ML dependencies (requirements.txt)
transformers==4.36.0 --hash=sha256:...
torch==2.1.0 --hash=sha256:...
```

```python
# SAFE — training data: trusted source + checksum + content validation before use
def load_training(source: str) -> list[dict]:
    src = TRUSTED_SOURCES[source]                 # KeyError on unknown source
    if compute_sha256(src.path) != src.checksum:
        raise ValueError("dataset checksum mismatch")
    return [ex for ex in read(src.path) if not poisoning_indicators(ex)]  # scan triggers/hidden chars
```

Additional barriers: maintain an ML-BOM; verify LoRA/PEFT adapters against a trusted registry and base-model compatibility; process untrusted data in a network-isolated sandbox; monitor training loss/gradient norms for anomalies.

## Severity & Triage

- `pickle`/`torch.load`(default)/`trust_remote_code=True` on an untrusted or remotely-fetched artifact: **Critical** (RCE on load).
- Unverified model/adapter from arbitrary org without pin/hash: **High** (tamper/backdoor).
- Unpinned ML deps: **Medium** (substitution risk) — corroborate with `supply_chain_security.md`/`dependency_confusion.md`.
- Unvalidated training/fine-tuning data: **Medium/High** depending on how the model is used downstream; pure static detectability is limited — flag the missing validation/provenance.
- Downgrade when the artifact is loaded from a verified internal store with checksum and `safetensors`/`weights_only`.

## Common False Alarms

- `safetensors` / `weights_only=True` / `allow_pickle=False` loads — safe by construction.
- Models/datasets loaded from a verified internal registry with checksum and pinned revision.
- `trust_remote_code=False` (or unset where the default is false) — not a finding.
- First-party models the team trained and stored themselves (still prefer safetensors, but lower risk).

## References

- OWASP LLM03:2025 Supply Chain; OWASP LLM04:2025 Data and Model Poisoning
- CWE-502 (Deserialization of Untrusted Data), CWE-494 (Download of Code Without Integrity Check), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), CWE-1357 (Reliance on Insufficiently Trustworthy Component)
- Related: `insecure_deserialization.md`, `supply_chain_security.md`, `dependency_confusion.md`, `rag_vector_security.md`
