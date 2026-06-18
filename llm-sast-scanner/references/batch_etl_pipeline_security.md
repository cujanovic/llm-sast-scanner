---
name: batch-etl-pipeline-security
description: Security flaws in batch / ETL / mainframe-migrated data pipelines — file-in → transform → file-out jobs driven by scheduler params, upstream records, or shared landing dirs (CWE-22, CWE-78, CWE-367, CWE-119/125, CWE-1236, CWE-707)
---

# Batch / ETL / Mainframe Data-Pipeline Security

Batch and ETL jobs (mainframe-migrated COBOL/JCL, Python/Java/Spark/Spring-Batch pipelines, scheduler-driven cron/Airflow/Autosys/Control-M tasks) are a distinct attack surface from interactive web apps. The data flow is **file-in → transform → file-out**, and the attacker is **not** a browser user — it is an *upstream producer*, a *scheduler/operator parameter*, or *any writer to a shared landing/spool directory*. Because these jobs typically run with a privileged batch service account and process financially material records, an injected path, command, or malformed record can read/overwrite arbitrary files, run commands, or silently corrupt/duplicate transactions.

## What This IS vs IS NOT

**This class IS:**
- Externally-influenced job parameters, env vars, JCL `PARM=`, or scheduler variables reaching a path / command / SQL / output record without validation.
- Output paths or staging directories derived from *input record fields* (account number, merchant id, filename).
- Untrusted-producer / TOCTOU issues on shared landing or spool directories (`glob('*.dat')`, "pick newest by mtime").
- Fixed-width / packed-decimal (COMP-3) / EBCDIC parsing flaws: length taken from a record header and used to slice/seek without bounds; unvalidated sign/zone nibbles; 1-based PIC vs 0-based slice off-by-one.
- Missing integrity controls: record-count / hash-total trailers not verified against the body.
- Restart / idempotency flaws: world-writable checkpoint or "processed" markers; rerun double-posts records.

**This class IS NOT:**
- Interactive web/API request-driven traversal or injection — use `path_traversal_lfi_rfi.md`, `rce.md`, `sql_injection.md`. (Those sources are HTTP; here the source is a job param / record field.)
- Spreadsheet formula injection in a web export — use `csv_injection.md` (this file cross-references it for batch-emitted CSV/report files).
- Generic memory corruption in C/C++ — use `memory_safety_c_cpp.md` (this file covers parser-level slice/seek-from-record-length specifically).
- Producer and consumer in the *same* trust domain where the value cannot be set by a lower-privileged party → not a finding.

## Threat Model (read first)

A finding requires both of:
1. An **externally-influenced value** — a job parameter, env var, upstream record field, or a filename in a watched/shared directory writable by a lower-privileged party.
2. A **sink reached without validation** — the value flows into a path, command, SQL, parser offset, or output record at a cited `file:line`, with no fixed base-directory + canonicalization check, bounds cap, or integrity gate.

If the value can only be set by an equally-or-higher-privileged party inside the same trust boundary, DROP it.

## Recon Indicators (where to look first)

- **Job entry points:** `sys.argv` / `argparse`, `os.environ`, JCL `PARM=`, `Control-M`/`Autosys`/`Airflow` variables, Spring Batch `JobParameters`, `@Value` from job context.
- **Path sinks fed by params/records:** `open()`, `pathlib.Path()`, `shutil.*`, `os.remove`/`os.rename`, `java.io.File`, `Files.*`, COBOL `ASSIGN TO` dynamic dataset names — built from a job param or record field with no fixed base + `realpath`/`Path.resolve()` containment check.
- **Shared landing / spool dirs:** `glob('*.dat')`, `os.listdir` + sort-by-mtime, watched-directory pollers (`watchdog`, `inotify`) — any process that can write the dir can plant or overwrite an ingested file (TOCTOU between "list/select" and "open").
- **Fixed-width / COMP-3 / EBCDIC parsers:** `struct.unpack`, manual `record[off:off+ln]` slicing where `off`/`ln` come from a header field; `codecs.decode(..., 'cp037'/'cp500')`; packed-decimal decoders reading sign/zone nibbles.
- **External process invocation:** `subprocess`/`os.system`/`ProcessBuilder` calling `sort`, `sftp`, `gpg`, `sqlldr`/`db2 load`/`bcp`, `awk`, with args built from job params or record fields.
- **DB bulk loaders:** loader control files or `LOAD DATA INFILE` / `COPY FROM` whose source path or column mapping is parameter-driven.
- **Checkpoint / restart logic:** `*.ckpt`, `.processed`, offset files, "high-water mark" timestamps stored in world-writable or shared dirs.

## Source → Sink Patterns

**Sources (batch context):**
- Job parameters / CLI args / env vars / JCL `PARM=` / scheduler variables.
- Upstream record fields (account no, merchant id, filename, length/offset headers, trailer counts).
- Filenames and contents in a shared landing/spool directory writable by a lower-privileged producer.

**Sinks:**
- Filesystem path operations (read/write/delete/rename) — **CWE-22** path traversal.
- Shell / external loader invocation — **CWE-78** command / argument injection.
- Select-then-open on a shared dir — **CWE-367** TOCTOU / untrusted producer.
- Slice/seek offset & length from record header into a fixed buffer — **CWE-119 / CWE-125 / CWE-787** over-read/over-write; sign-nibble mishandling → logic / **CWE-840**.
- Emitted CSV/report cells — **CWE-1236** formula injection (see `csv_injection.md`).
- Missing trailer/hash-total verification — **CWE-707 / CWE-354** improper integrity check → undetected truncation/injection.

**Sanitizers / barriers (rule SAFE when present):**
- Fixed base directory + `os.path.realpath`/`Path.resolve()` containment check before any param/record-derived path is used; reject absolute paths and `..`.
- Allow-list of expected filenames / strict `^[A-Za-z0-9._-]+$` validation on record-derived names.
- Atomic claim of input files (`os.rename` into a private per-worker dir, or `O_EXCL` lock) before processing — closes the landing-dir TOCTOU.
- Length capped to remaining buffer before slice/seek; sign/zone nibbles validated; explicit 1-based→0-based offset conversion.
- Trailer record-count and hash/control-total verified against the parsed body before commit; reject on mismatch.
- Loader/process args passed as an argv array (never a shell string); identifiers validated against an allow-list.
- Checkpoint/marker files written to a non-shared, mode-`0700` directory; idempotency key enforced so reruns are safe.

## Vulnerable vs Safe

```python
# VULNERABLE — output path built from an upstream record field (path traversal as the
# batch service account: a crafted "merchant_id" of ../../etc/cron.d/x overwrites system files)
def write_settlement(record, out_root="/data/settlement"):
    merchant = record["merchant_id"]            # attacker-influenced upstream field
    path = os.path.join(out_root, merchant + ".csv")
    with open(path, "w") as f:                   # CWE-22: no containment check
        f.write(render(record))
```

```python
# SAFE — allow-list the identifier, then confirm the resolved path stays under the base
import os, re
def write_settlement(record, out_root="/data/settlement"):
    merchant = record["merchant_id"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", merchant):
        raise ValueError("invalid merchant id")
    base = os.path.realpath(out_root)
    path = os.path.realpath(os.path.join(base, merchant + ".csv"))
    if os.path.commonpath([base, path]) != base:
        raise ValueError("path escapes base directory")
    with open(path, "w") as f:
        f.write(render(record))
```

```python
# VULNERABLE — fixed-width/COMP-3 parse trusts a length from the record header
def parse_field(buf, offset):
    length = buf[offset]                          # length byte from the record itself
    return buf[offset + 1: offset + 1 + length]   # CWE-125: over-read past buffer end
```

```python
# SAFE — cap the length to the remaining buffer before slicing
def parse_field(buf, offset):
    if offset >= len(buf):
        raise ValueError("offset past end of record")
    length = buf[offset]
    end = offset + 1 + length
    if end > len(buf):
        raise ValueError("declared length exceeds record buffer")
    return buf[offset + 1: end]
```

```python
# VULNERABLE — pick "newest" file from a shared landing dir, then open it (TOCTOU /
# untrusted producer: any writer to /landing can plant a file the job ingests)
files = sorted(glob.glob("/landing/*.dat"), key=os.path.getmtime)
process(open(files[-1]))                          # CWE-367
```

```python
# SAFE — atomically claim the file into a private per-worker dir before processing
src = sorted(glob.glob("/landing/*.dat"), key=os.path.getmtime)[-1]
claimed = os.path.join("/work/%d" % os.getpid(), os.path.basename(src))
os.rename(src, claimed)                           # atomic move = exclusive claim
process(open(claimed))
```

## Severity & Triage

- **Critical / High:** param/record-derived path traversal that can overwrite executables, cron, or other jobs' input under a privileged batch account; command/argument injection into a loader/SFTP/GPG call; integrity-control bypass that silently injects or duplicates financial records.
- **Medium:** buffer over-read in fixed-width/COMP-3 parsing (info leak / crash); landing-dir TOCTOU requiring an existing local writer; restart double-posting requiring a partial-failure window.
- **Low:** missing hash-total verification with no demonstrated injection path; formula-injection into a report consumed only internally.

## Common False Alarms

- Path or filename derived from a value only a trusted/equal-privilege operator can set (e.g., a deploy-time constant) — not externally influenced.
- Landing directory that is mode-`0700` and writable only by the same service account — no lower-privileged producer.
- Length/offset already bounds-checked or read from a trusted schema constant rather than the record body.
- CSV emitted to a strictly internal, machine-only consumer that never opens it in a spreadsheet (still note if it may reach Excel).

## Dynamic Test / PoC

Use only against jobs you own / are authorized to test, in a staging environment.

- **Path traversal via record field:** craft an input record whose path-bearing field is `../../../tmp/poc_$(date +%s)` (and an absolute variant `/tmp/poc_abs`); run the job and check whether a file appears outside the intended output root.
- **Job parameter traversal:** invoke with `--out ../../tmp/poc` / set the env var or `PARM=` to a traversal string; confirm containment rejection vs. escape.
- **Landing-dir TOCTOU:** as a lower-privileged user, drop a `*.dat` file (or symlink) into the watched dir between job cycles; verify whether the job ingests or follows it.
- **Fixed-width over-read:** submit a record whose length/offset header exceeds the actual record size; watch for crash, over-read bytes in output, or a leaked adjacent field.
- **Trailer integrity:** append an extra record after the trailer, or change the body without updating the record-count/hash-total trailer; confirm the job rejects vs. silently processes.
- **Loader arg injection:** set a parameter/field consumed by a `sqlldr`/`sftp`/`gpg` argv to a value containing an extra flag (e.g., `; ` or `--option`) and confirm it is passed literally, not interpreted.
- **Restart double-post:** kill the job mid-run after a partial commit, then rerun; verify records are not posted twice (idempotency key enforced).

## Cross-References

- `path_traversal_lfi_rfi.md` — traversal mechanics and canonicalization barriers.
- `rce.md` — command/argument injection sinks and argv-array remediation.
- `race_conditions.md` — TOCTOU patterns and atomic-claim techniques.
- `memory_safety_c_cpp.md` — buffer over-read/over-write fundamentals for native parsers.
- `csv_injection.md` — formula-injection neutralization for batch-emitted CSV/report files.
