#!/usr/bin/env python3
"""llm-sast-scanner-full-scan-loop — shipped recheck.

Recomputes every STEP 3 recheck item of the wrapper skill from the run's artifacts
and prints one `recheck:` line per item, then a `recheck: mismatches` summary.
It is copied unchanged from the skill directory into `.llm-sast-scanner-cache/` and
run from the target directory. A run reads the artifacts and writes nothing:

    python3 .llm-sast-scanner-cache/recheck.py

The session records a set — after the writer returns, after a repair — with
`--record`, which appends the set to the scan plan itself and prints one
`recorded:` line; a run without it whose output is redirected into the plan
writes nothing there:

    python3 .llm-sast-scanner-cache/recheck.py --record

Exit status 1 when any item mismatches, 0 otherwise. Every number printed is
computed here; nothing on a line is copied from the report except the value it
is compared against, which appears after `vs reported`.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

CMD = "python3 .llm-sast-scanner-cache/recheck.py"
# a file reader cuts a line longer than this many UTF-8 bytes: a line past it is read only up to it (one fresh run wrote
# every worker prompt as one line of 6,800 characters, and thirteen workers were re-run). The limit is bytes, not
# characters: Devin's reader keeps exactly 2,000 bytes of a longer line — 1,982 to 1,994 characters on lines with em
# dashes, three bytes each — and Claude Code's 2,000-character limit is never the tighter of the two
LINE_LIMIT = 2000
FENCE_RX = re.compile(r"^\s*(?:```|~~~)")  # a fence line as `unfenced()` reads one, at any indentation


def long_lines(text: str) -> list[tuple[int, int]]:
    """The lines of a prompt longer than LINE_LIMIT bytes (UTF-8), as (line number, bytes)."""
    return [(i + 1, len(l.encode("utf-8"))) for i, l in enumerate(text.split("\n")) if len(l.encode("utf-8")) > LINE_LIMIT]


def long_text_lines(text: str) -> list[tuple[int, int]]:
    """The lines of a worker file or report longer than LINE_LIMIT bytes outside a fenced code block, as (line number,
    bytes): a fenced line is a verbatim copy of source, which a wrap would make no copy, and every other line can be
    shortened or broken. Fences are read as `unfenced()` reads them — a ``` or ~~~ line at any indentation opens or
    closes one — except that a fence still open at the end of the text is none."""
    lines = text.split("\n")
    marks = [i for i, l in enumerate(lines) if FENCE_RX.match(l)]
    if len(marks) % 2:
        marks = marks[:-1]  # a fence never closed is no fence: one left open would exempt every line after it
    fenced = set()
    for a, b in zip(marks[::2], marks[1::2]):
        fenced.update(range(a, b + 1))
    return [(i + 1, len(l.encode("utf-8"))) for i, l in enumerate(lines)
            if i not in fenced and len(l.encode("utf-8")) > LINE_LIMIT]
VERDICT_RX = re.compile(r"(DOWNGRADED|DISPUTED) — [^—]*(`[^`]+`|[A-Za-z0-9_./-]+:[0-9]+)")
VOIDED_RX = re.compile(r"STANDING — previous downgrade voided: [^—]*(`[^`]+`|[A-Za-z0-9_./-]+:[0-9]+)")
LEDGER_RX = re.compile(r"^([a-z][a-z0-9_]*) \| ([^|]+:[0-9]+(?:-[0-9]+)?) \|(.*)$")
ENTRY_LINE_RX = re.compile(r"^\|?\s*`?[^|`\s]+:\d+`?\s*\|")  # an entry line opens with its file:line, table pipe allowed
RECORD_RX = re.compile(r"^(?:#+ )?\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\] (VULN-[A-Za-z0-9-]*\d)", re.I)
ANY_RECORD_RX = re.compile(r"^(?:#+ )?\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*|CONFIRMED|LIKELY)\] (VULN-[A-Za-z0-9-]*\d)", re.I)
CONFIG_PHRASES = re.compile(
    r"disabled by default|enabled by default|default configuration|environment-gated|"
    r"non-production|only when the flag|unless configured", re.I)
CLEARANCE_MARK = re.compile(r"\bSAFE\b|clearance|cleared|not exploitable|not a finding|no finding|dismiss", re.I)
FILE_LINE_RX = re.compile(r"[A-Za-z0-9_./-]+\.[A-Za-z0-9]+:[0-9]+")
REQUIRED_PREFIXES = [
    "Maturity:", "checks:", "contracts checked:", "stale worker files moved:", "dispatch lines late:",
    "earlier reports:", "entry points dispositioned", "config clearances rewritten:", "class clearances",
    "ledger rows before", "ledger:", "verdicts carried", "close-out:", "maturity:",
]
SKILLS = ["llm-sast-scanner-full-scan-loop", "llm-sast-scanner-convergence-loop", "llm-sast-scanner"]

LINES: list[str] = []
MISMATCHES: list[str] = []
PLAN_CUT: dict[str, str] = {}  # a printed line whose hint carries it past LINE_LIMIT -> the line as the plan records it


# one definition of a recorded gate line and of its verdict, shared by item 29 and by --prompt's precondition
GATE_LINE_RX = re.compile(r"^gate: ([a-z-]+/p\d+) — header (ok|fail) \| pinned (ok|fail) \| phrase (ok|fail) \| sentinel (absent|files ([\d,]+)/([\d,]+) lines ([\d,]+)/([\d,]+) passes (\d+)) \| paths (\d+)/(\d+) resolve \| headings (\d+)/(\d+) \| absolute (\d+) \| references (\d+)/(\d+)(?: \| entry pipes (\d+))?(?: \| copied (?:(\d+)%(?: from \S+)?|n/a))?(?: \| digest ([0-9a-f]{12}|unreadable))?(?: \| long lines (\d+))?(?: \| groups (\d+)/(\d+))?", re.M)
COPY_CAP = 80  # a worker file whose prose is this share of an earlier run's file of its pair is that file, not this run's


def gate_line_passes(line: str) -> bool | None:
    """A recorded `gate:` line's verdict by the gate rule (None when the line does not parse): every field `ok`, the sentinel
    at full coverage with passes, paths all resolving (`0/0` failing on a file with records), headings and references full,
    and, on a line that carries them, a `copied` share below COPY_CAP, `long lines 0` and `groups` at its full count."""
    g = GATE_LINE_RX.match(line.strip())
    if not g:
        return None
    n_ = lambda s: int(s.replace(",", ""))
    if "fail" in (g.group(2), g.group(3), g.group(4)) or g.group(5) == "absent":
        return False
    if n_(g.group(6)) < n_(g.group(7)) or n_(g.group(8)) < n_(g.group(9)) or int(g.group(10)) == 0:
        return False
    k, km, s, sm, r, rm_ = (int(g.group(i)) for i in (11, 12, 13, 14, 16, 17))
    # the later fields: a line written before them has none, and its verdict reads as it did; `entry pipes` is a count, not a fail
    if g.group(19) and int(g.group(19)) >= COPY_CAP:
        return False
    if g.group(21) and int(g.group(21)) > 0:
        return False  # a line over the reader's limit: the writer reads only its start
    if g.group(22) and int(g.group(22)) < int(g.group(23)):
        return False  # a group's `Also at:` line naming another record's own sink at its class and entry point
    return not ((km > 0 and k < km) or (km == 0 and s > 0) or s < sm or r < rm_)

def gate_line_diff(recorded: str, now: str) -> list[str]:
    """What a recorded `gate:` line read in its worker file that the file's gate line now does not — the file changed after
    it was gated. Read: the file's digest (its bytes' SHA-256), then the counts its text decides, which say what changed —
    its sentinel, records (`m`), headings, absolute paths, references, entry pipes and long lines. Not read: the header, pinning and
    phrase, which follow the skills and the plan, the resolving paths, which follow the checkout, `copied`, which
    follows the earlier runs' directories, and `groups`, which follows the plan's entry list and the skills' references —
    within one run these do not move, and a later reading under other skills or another checkout would name a change the
    file never had; the digest names any change of the text. A line written before a field existed is read by the
    fields it has."""
    a, b = GATE_LINE_RX.match(recorded.strip()), GATE_LINE_RX.match(now.strip())
    if not a or not b:
        return []  # a line the gate rule does not parse is read by its verdict elsewhere
    out = []
    if a.group(20) and b.group(20) and a.group(20) != b.group(20):
        out.append(f"its text (digest {a.group(20)} now {b.group(20)})")
    if a.group(5) != b.group(5):
        out.append(f"sentinel {a.group(5)} now {b.group(5)}".replace("sentinel sentinel ", "sentinel "))
    if a.group(12) != b.group(12):
        out.append(f"records {a.group(12)} now {b.group(12)}")
    if (a.group(13), a.group(14)) != (b.group(13), b.group(14)):
        out.append(f"headings {a.group(13)}/{a.group(14)} now {b.group(13)}/{b.group(14)}")
    if a.group(15) != b.group(15):
        out.append(f"absolute {a.group(15)} now {b.group(15)}")
    if (a.group(16), a.group(17)) != (b.group(16), b.group(17)):
        out.append(f"references {a.group(16)}/{a.group(17)} now {b.group(16)}/{b.group(17)}")
    if a.group(18) is not None and b.group(18) is not None and a.group(18) != b.group(18):
        out.append(f"entry pipes {a.group(18)} now {b.group(18)}")
    if a.group(21) is not None and b.group(21) is not None and a.group(21) != b.group(21):
        out.append(f"long lines {a.group(21)} now {b.group(21)}")
    return out


def gate_line_as(recorded: str, now: str) -> str:
    """The file's gate line now, read by the fields the recorded line has: a line written before `long lines` or
    `groups` existed is judged without it, as every later field is."""
    a = GATE_LINE_RX.match(recorded.strip())
    if not a:
        return now
    now_ = now.strip()
    if a.group(22) is None:
        now_ = re.sub(r" \| groups \d+/\d+\s*$", "", now_)
    if a.group(21) is None:
        now_ = re.sub(r" \| long lines \d+\s*$", "", now_)
    return now_ if now_ != now.strip() else now


def pathlib_name(name) -> str:
    """A worker file named as a hint shows it: its base name, whatever form the key held."""
    return Path(str(name)).name

RECORD = {"on": False, "plan": None}  # set by main: --record, and the scan plan the set is recorded in


def count_sets(text: str) -> tuple[int, list[int]]:
    """Every `recheck: mismatches` line closes a set; a lone one — no other `recheck:` line before it — is a subagent's own
    run, never a set. Returns (mismatches lines, the lone lines' numbers), lines numbered as `grep -n` numbers them."""
    lone, sets, prev = [], 0, ""
    for i, l in enumerate(text.split("\n"), 1):
        if l.startswith("recheck: mismatches"):
            sets += 1
            if not (prev.startswith("recheck: ") and not prev.startswith("recheck: mismatches")):
                lone.append(i)
        if l.strip():
            prev = l
    return sets, lone


def put_set(lines: list[str]) -> None:
    """Print a set, and record it when the session asked: a run with `--record` appends its lines to the scan plan itself;
    a run without it whose output is redirected into the plan (a writer's `>> scan-plan.md`) writes nothing there, so a
    self-check can never become a recorded set."""
    text = "\n".join(lines)
    plan_p = RECORD["plan"]
    into_plan = False
    try:
        into_plan = bool(plan_p) and plan_p.exists() and os.path.samestat(os.fstat(sys.stdout.fileno()), os.stat(plan_p))
    except (OSError, ValueError, AttributeError):
        into_plan = False
    if RECORD["on"] and plan_p and plan_p.exists():
        try:
            raw = plan_p.read_bytes()
            partial = bool(raw) and not raw.endswith(b"\n")  # a plan without its last newline gets one first
            first = raw.count(b"\n") + (1 if partial else 0) + 1
            with open(plan_p, "ab") as fh:
                fh.write((b"\n" if partial else b"") + ("\n".join(PLAN_CUT.get(l, l) for l in lines) + "\n").encode("utf-8"))
            sets, lone = count_sets(plan_p.read_bytes().decode("utf-8", "replace"))
        except OSError as exc:
            sys.stderr.write(f"recorded: nothing — the set could not be appended to .llm-sast-scanner-cache/scan-plan.md ({type(exc).__name__}: {exc}); its lines follow, unrecorded\n")
            print(text)
            return
        # the set is in the plan; what is printed is never a set, so a redirect or a tee of it records nothing twice
        summary = (f"recorded: set {sets - len(lone)} appended to .llm-sast-scanner-cache/scan-plan.md, lines {first}-{first + len(lines) - 1} — "
                   + lines[-1].split(" — python3", 1)[0][len("recheck: "):]
                   + (" | repair none: every mismatch reads a STEP 1 or STEP 2 line" if any(l.startswith("recheck: repair none") for l in lines) else ""))
        if into_plan:
            sys.stderr.write(summary + "\n")
        else:
            print(summary)
        return
    if RECORD["on"]:
        sys.stderr.write(f"recorded: nothing — no scan plan at {plan_p}; the set below was not recorded\n")
    if into_plan:
        # the note is no `recheck:` line, so written into the plan by a `2>&1` it reads as no set
        sys.stderr.write("recorded: nothing — this run's output was redirected into .llm-sast-scanner-cache/scan-plan.md and dropped; "
                         "a run without --record reads the report (run it with nothing after it to see its lines), and a set is recorded only by the session's `recheck.py --record`\n")
        return
    print(text)


def emit(item: str, recomputed: str, reported: str | None, ok: bool, fix: str | None = None) -> None:
    rep = f" vs reported {reported}" if reported is not None else ""
    hint = f" | fix: {fix}" if fix and not ok else ""
    head, tail = f"recheck: {item} {recomputed}{rep}", f" — {CMD}"
    LINES.append(head + hint + tail)
    # a recorded set is read with a file reader, which cuts a line at LINE_LIMIT bytes: the plan's copy of a line whose
    # hint carries it past the limit has the hint cut, at a character, with `…` — what was recomputed, what was reported
    # and the command are never cut, and a line whose other parts leave no room for ` | fix: …` is recorded whole. The
    # printed line keeps its whole hint: the writer and a repair read the printed lines
    room = LINE_LIMIT - len((head + tail).encode("utf-8", "replace"))
    if len(hint.encode("utf-8", "replace")) > room >= len(" | fix: …".encode("utf-8")):
        PLAN_CUT[head + hint + tail] = head + hint.encode("utf-8", "replace")[:room - len("…".encode("utf-8"))].decode("utf-8", "ignore") + "…" + tail
    if not ok:
        MISMATCHES.append(item)


def read(p: Path) -> str:
    try:
        return p.read_text(errors="replace") if p.exists() else ""
    except OSError:
        return ""  # an unreadable file reads as empty: the item that needs it says so, and no item is lost to a script error


def read_raw(p: Path) -> str:
    """A file's text with its newlines as written — no universal-newline translation — so line numbers are `grep -n`'s."""
    return p.read_bytes().decode("utf-8", "replace") if p.exists() else ""


def row(text: str, name: str) -> str | None:
    m = re.search(r"^" + re.escape(name) + r"\s*(.*)$", text, re.M)
    return m.group(1).strip() if m else None


def ints(pattern: str, text: str) -> list[int] | None:
    m = re.search(pattern, text, re.M)
    return [int(g) for g in m.groups()] if m else None


def closeout_of(text: str) -> list[int] | None:
    """A report's close-out line as [table rows, file records, body rows, promoted, body blocks, linked blocks, invalid cells,
    carried] — `carried` 0 when the line predates the field (2.17.x reports)."""
    m = re.search(r"^close-out: table rows (\d+) \| file records (\d+) \| body rows (\d+) \| promoted (\d+) (?:\| carried (\d+) )?\| body blocks (\d+) \| linked blocks (\d+) \| invalid cells (\d+)", text, re.M)
    if not m:
        return None
    return [int(m.group(i)) for i in (1, 2, 3, 4, 6, 7, 8)] + [int(m.group(5)) if m.group(5) is not None else 0]


def corrected_str(text: str, name: str) -> str:
    """A scan-plan row's value as the run last stated it: the last ` → corrected <value>` append, else the row itself."""
    r_ = row(text, name) or ""
    fixes = re.findall(r"→ corrected (.+?)(?:\s+at\s+\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})?\s*(?=→|$)", r_)
    return (fixes[-1] if fixes else r_).replace("`", "").strip()


# a worker's refutation of a ledger finding (STEP 2a): `ledger refuted: <class> | <sink file:line> — <the guard>`, read
# wherever a line holds it — its own line, a list item, a table cell, a per-sink bullet — in bold or backticks, any
# letter case, a range sink, a `:column` after the line, an em or en dash or a spaced hyphen for the dash
REFUTE_AT = re.compile(r"(?i)ledger refuted[`*_]*:[`*_]*")
REFUTE_BODY = re.compile(r"^[ \t]*[`*_]*([A-Za-z][A-Za-z0-9_]*)[`*_]*[ \t]*\|[ \t]*`?([^|`\s]+?)`?:(\d+(?:[-\u2013]\d+)?)(?::\d+)?`?(?:[ \t]*[\u2014\u2013][ \t]*|[ \t]+-{1,2}[ \t]+)(.*\S)")
# what may stand before a claim, back to the line's start or the last `|`, `;` or dash: markup only — a word there
# quotes, negates or supposes it (`considered … but rejected`, `not …`, `e.g. … would apply`), and it is no claim
REFUTE_LEAD = re.compile(r"^[\s>*_`+\-\d.)#]*$")


def refute_lines(text: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """A worker file's `ledger refuted:` claims outside fenced code: (class, sink, guard) of each that parses, and the
    lines holding one that looks like a claim (a `|` or a `:line` after the colon) and does not parse. A mention with a
    word before it, or followed by a placeholder (`<class>`), by `none`, `n/a` or `0`, or by prose, is no claim; so is a
    claim whose guard is `none`, `n/a`, `nothing` or a dash."""
    ok_, bad_ = [], []
    for l in unfenced(text).splitlines():
        hits = list(REFUTE_AT.finditer(l))
        unread = False
        for i, h in enumerate(hits):
            lead = re.split(r"[|;\u2014\u2013]", l[:h.start()])[-1]
            if not REFUTE_LEAD.match(lead):
                continue
            seg = l[h.end():hits[i + 1].start() if i + 1 < len(hits) else len(l)]
            body = seg.strip()
            if not body or body.startswith(("<", "`<")) or re.match(r"(?i)[`*_ ]*(?:none|n/a|0)(?![\w/])", body):
                continue
            m = REFUTE_BODY.match(seg)
            guard = m.group(4).strip(" `*|;,") if m else ""
            if m and guard and not re.fullmatch(r"(?i)(?:none|n/a|nothing|[-\u2014\u2013]+)\.?", guard):
                ok_.append((m.group(1).lower(), f"{m.group(2)}:{m.group(3).replace(chr(0x2013), '-')}", guard))
            elif not m and ("|" in body or re.search(r":\d", body)):
                unread = True
        if unread:
            bad_.append(l.strip()[:160])
    return ok_, bad_


def plan_base_sha(plan: str) -> str | None:
    """The scan-plan's base-sha as the run last stated it — its last `→ corrected` value, else the row — the sha alone: a
    full sha, else the first run of seven or more hex digits, else `unknown`; a `(HEAD)`, a word such as `to`, a note or
    a comma around it, and backticks, are not the sha."""
    v = corrected_str(plan, "base-sha:")
    for rx in (r"(?<![0-9A-Za-z])([0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9A-Za-z])", r"(?<![0-9A-Za-z])([0-9a-fA-F]{7,64})(?![0-9A-Za-z])",
               r"(?<![0-9A-Za-z])(unknown)(?![0-9A-Za-z])"):
        m = re.search(rx, v, re.I)
        if m:
            return m.group(1)
    return None


def unfenced(text: str) -> str:
    """The text with every line inside a fenced code block blanked, line numbers kept: a `## ` line in a quoted Makefile
    is the snippet's, never the report's heading."""
    out, fence = [], False
    for l in text.split("\n"):
        if re.match(r"^\s*(?:```|~~~)", l):
            fence = not fence
            out.append("")
        else:
            out.append("" if fence else l)
    return "\n".join(out)


PLAN_ONLY: set = set()  # items whose failing part this run is a STEP 1 or STEP 2 line only


def corrected(text: str, name: str) -> int | None:
    """The value of a scan-plan row, taking the last ` → corrected <value>` append when the row carries one."""
    m = re.search(r"^" + re.escape(name) + r"\s*(\d+)(.*)$", text, re.M)
    if not m:
        return None
    fixes = re.findall(r"→ corrected (\d+)", m.group(2))
    return int(fixes[-1]) if fixes else int(m.group(1))


TARGET_PREFIX = ""


def rel(path: str) -> str:
    """A path under the target written absolute is compared as the target-relative path the ledger uses."""
    return path[len(TARGET_PREFIX):] if TARGET_PREFIX and path.startswith(TARGET_PREFIX) else path


def strip_cell(s: str) -> str:
    return rel(s.strip().strip("*").strip().strip("`").strip())


def canon(sink: str) -> str:
    """A sink's line is its first line: `Dockerfile:45-55` is the sink `Dockerfile:45`, whichever side of a comparison it is on."""
    return re.sub(r"(-\d+)+$", "", sink.strip())


def key_of(cls: str, sink: str) -> str:
    return f"{cls}|{canon(rel(sink))}"


def file_of(block: str) -> str | None:
    m = re.search(r"^\**File:\**\s*`?([^`\s|]+:\d+(?:-\d+)?)", block, re.M)
    return canon(rel(m.group(1))) if m else None


def adversarial(block: str) -> str | None:
    m = re.search(r"^\**Adversarial:\**\s*(.*)$", block, re.M)
    return m.group(1).strip() if m else None


CITE_SPLIT_RX = re.compile(r"\s+|->|=>|<-|\u2192|\u2190")
CITE_TOK_RX = re.compile(r"^(?P<pre>[(\[`'\"*]*)(?P<path>\S+?):(?P<spec>\d{1,9}(?:[-\u2013\u2014]\d{1,9})?(?:,\d{1,9}(?:[-\u2013\u2014]\d{1,9})?)*)(?::\d+)?(?:\([^)\s]*\))?[)\]`'\",;.*]*$")


ALSO_RX = re.compile(r"^\s*(?:[-*+]\s+)?\**\s*Also at\s*\**\s*:\**\s*(.*)$", re.I)


def also_sinks(text: str, file_path: str | None = None) -> list[tuple[str, int, int]]:
    """The sinks an `Also at:` line names — one missing check's other sink lines (base skill, Deduplication & Sink
    Location) — as (path, first line, last line): `path:30`, `path:30,32` and `path:30, 32`, `path:30:12` (a column),
    `path:L30` and `path#L30`, a bare `:32` reading in the path before it and a bare `32` only as the next item of a
    comma-separated list, `./` dropped, a bare file name that is the `File:` path's own read as that path, a path holding
    `(…)` or `[…]` segments kept. A range comes back as (path, first, last), first < last, which the line may not hold
    (item (40) flags it, and it holds its first line alone). `text` is the line after its label."""
    out_, last_, cont_ = [], None, False
    norm_ = lambda x_: re.sub(r"^(?:\./)+", "", x_.strip())
    s_ = re.sub(r"[`*​‌‍﻿]", "", text or "").replace("−", "-")
    raws_ = re.split(r"[\s;]+", s_)
    cite_rx = re.compile(r"^[(\[]*([^\s:#]*?)(?::L?|#L)(\d{1,9}(?:[-–]\d{1,9})?(?:,\d{1,9}(?:[-–]\d{1,9})?)*)(?::\d{1,9})?[)\],.]*$")
    num_rx = re.compile(r"^(\d{1,9})(?:[-–](\d{1,9}))?$")
    for i_, raw_ in enumerate(raws_):
        tok_ = raw_.strip(",").rstrip(".")  # a leading `.` is a path's (`./src`, `.gitlab-ci.yml`), a trailing one the sentence's
        if not tok_:
            cont_ = cont_ or raw_.endswith(",")
            continue
        if tok_.lower() in ("and", "&"):
            continue  # `30, 32 and 40`: the list goes on
        m_ = cite_rx.match(tok_)
        if m_:
            path_ = norm_(m_.group(1)) if m_.group(1) else last_
            if path_ and file_path and "/" not in path_ and file_path.endswith("/" + path_):
                path_ = file_path  # a bare file name that is the sink's file
            if not path_:
                cont_ = False
                continue
            last_ = path_
            for sp_ in m_.group(2).split(","):
                a_, _, b_ = sp_.replace("–", "-").partition("-")
                out_.append((path_, int(a_), int(b_ or a_)))
            cont_ = raw_.endswith(",")
            continue
        n_ = num_rx.match(tok_)
        nxt_ = next((r_ for r_ in raws_[i_ + 1:] if r_.strip(",")), "")
        nxt_t = nxt_.strip(",").rstrip(".")
        prev_ = raws_[i_ - 1].lower() if i_ else ""
        # a bare number is a line only as the next item of a list: after a comma (or `and`), and before a comma, a cite,
        # `and` or the line's end — `30, 3 of them` names one line
        if n_ and last_ and (cont_ or prev_ in ("and", "&")) and (raw_.endswith(",") or not nxt_ or nxt_t.lower() in ("and", "&", "\u2014", "\u2013", "-", "--")
                                                                   or cite_rx.match(nxt_t) or num_rx.match(nxt_t)):
            out_.append((last_, int(n_.group(1)), int(n_.group(2) or n_.group(1))))
            cont_ = raw_.endswith(",")
            continue
        cont_ = False
    return out_



# one missing check's group and a line that is its own finding: STEP 2 reads, in each worker file (the gate's `groups`
# field) and across them (`--overlaps`), every record whose `Also at:` line names a sink that another record holds as its
# own `File:` sink at one class and entry point — one defect counted twice, or a line that needs a fix of its own on a
# group's line (base skill, Deduplication & Sink Location). Two runs' workers put decoder-depth sinks on a schema
# group's `Also at:` line and stopped at STEP 3 on it; a third run merged such a finding into the group and read clean.
EP_IDENT = r"[A-Za-z_$][\w$]*"
REC_HEAD_RX = re.compile(r"^(?:#+ )?\**\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\]\**\s+\**(VULN-[A-Za-z0-9-]*\d)", re.I)
ANY_HEAD_RX = re.compile(r"^(?:#+ )?\**\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*|CONFIRMED|LIKELY)\]", re.I)


def entry_list(plan: str) -> list:
    """The scan-plan's `## Entry points` list, as item (4) reads it: (path, line, the name field's last identifier, the
    name field's words, a pattern finding those words whole — compiled once: lists of 700 entries outrun `re`'s cache)."""
    sec = plan.split("## Entry points", 1)[1].split("\n## ", 1)[0] if "## Entry points" in plan else ""
    out = []
    for l in sec.splitlines():
        f = l.split(" | ")
        m = re.match(r"^(.+):(\d+)", f[0].strip().lstrip("|").strip().strip("`")) if len(f) >= 3 and not l.startswith("#") else None
        if m:
            ids = re.findall(EP_IDENT, f[2])
            nm = " ".join(f[2].replace("`", "").split())
            out.append((m.group(1), int(m.group(2)), ids[-1] if ids else None, nm, re.compile(r"(?<![\w$])" + re.escape(nm) + r"(?![\w$])") if nm else None))
    return out


def entry_at(cell: str, entries: list):
    """The list entry a record's `Entry point:` names, as (path, line) — item (4)'s reading: a cited `file:line` as the
    entry at it or up to three lines below it in that file, else a name only one entry's last identifier is — and, where
    that name is several entries', the one of them whose whole name field the text holds (`QueueA Events`, whose last
    word `QueueB Events` shares). The text itself when it names none."""
    c = re.sub(r"\s+", " ", cell.replace("`", "")).strip()
    for m in re.finditer(r"([\w./-]+\.\w+):(\d+)", c):
        cited, ln = m.group(1).lstrip("./"), int(m.group(2))
        paths = {e[0] for e in entries if e[0] == cited or e[0].endswith("/" + cited)}
        if len(paths) != 1:
            continue
        near = [e for e in entries if e[0] in paths and e[1] <= ln + 3]
        if near:
            e = next((x for x in near if x[1] == ln), None) or max(near, key=lambda e: e[1])
            return (e[0], e[1])
    words = set(re.findall(EP_IDENT, re.sub(r"\S+:\d+(?:-\d+)?", " ", c)))
    named = {(e[0], e[1]) for e in entries if e[2] in words}
    if len(named) == 1:
        return next(iter(named))
    whole = {(e[0], e[1]) for e in entries if (e[0], e[1]) in named and e[4] is not None and e[4].search(c)}
    return next(iter(whole)) if len(whole) == 1 else c


def worker_records(text: str, stems: set, roots: tuple = ()) -> list:
    """Each finding record of a worker file, read as `record_also` reads one — from its severity heading to the next
    record heading, a `#` to `###` heading or the sentinel, outside fenced code — as a dict: `id`, `line` (its heading's
    line number), `sink` (its `File:` line's first `path:line`, first line, `./` and a target root dropped) or None,
    `entry` (its `Entry point:` text) or None, `cls` (the first base-skill reference its `Reference:` line names, the
    first name when it names none) or None, and `also` (the sinks its `Also at:` lines name, each by its first line)."""
    def norm(p_: str) -> str:
        p_ = re.sub(r"^(?:\./)+", "", rel(p_.strip()))
        return next((p_[len(r_) + 1:] for r_ in roots if r_ and p_.startswith(r_ + "/")), p_)
    lines_ = text.splitlines()
    heads_ = [i for i, l in enumerate(lines_) if ANY_HEAD_RX.match(l)]
    head_set = set(heads_)
    fenced_ = set()
    for a_, b_ in zip([0] + heads_, heads_ + [len(lines_)]):
        marks_ = [i for i in range(a_, b_) if FENCE_RX.match(lines_[i])]
        if len(marks_) % 2:
            marks_ = marks_[:-1]
        for x_, y_ in zip(marks_[::2], marks_[1::2]):
            fenced_.update(range(x_, y_ + 1))
    out, cur = [], None
    for i, l in enumerate(lines_):
        if i in head_set:
            h_ = REC_HEAD_RX.match(l)
            cur = {"id": h_.group(2), "line": i + 1, "sink": None, "file": None, "entry": None, "cls": None, "also": []} if h_ else None
            if cur:
                out.append(cur)
            continue
        if i in fenced_ or cur is None:
            continue
        if re.match(r"^#{1,3} |^<!-- LLM-SAST-COMPLETE", l):
            cur = None
            continue
        f_l = re.match(r"^\**Files?:\**\s*(.+)$", l)
        if f_l and cur["sink"] is None:
            # the path as `record_also` reads it, so `app/(auth)/page.tsx:20` keeps its route-group directory; the
            # first `path:line` anywhere on the line only when the line does not open with one
            s_ = (re.match(r"`?([^\s`|:,;]+):(\d+)", re.sub(r"\*", "", f_l.group(1)).strip())
                  or re.search(r"([^\s|:,;()]+):(\d+)", re.sub(r"[`*]", "", f_l.group(1))))
            if s_:
                cur["file"] = norm(s_.group(1))
                cur["sink"] = f"{cur['file']}:{s_.group(2)}"
        e_ = re.match(r"^\s*(?:[-*+]\s+)?\**Entry points?\**\s*:\**\s*(.+)$", l, re.I)
        if e_ and cur["entry"] is None:
            cur["entry"] = e_.group(1).strip()
        r_ = re.match(r"^\**Reference:\**\s*(.+)$", l)
        if r_ and cur["cls"] is None:
            names_ = re.findall(r"(?:^|[/\s,(])([a-z0-9_]+)\.md\b", re.sub(r"[`*]", "", r_.group(1)))
            named_ = [n_ for n_ in names_ if n_ in stems] or names_
            cur["cls"] = named_[0] if named_ else None
        a_ = ALSO_RX.match(l)
        if a_:
            cur["also"] += [f"{norm(p_)}:{n_}" for p_, n_, _ in also_sinks(a_.group(1), cur["file"])]
    return out


def entry_key(rec: dict, entries: list):
    """A record's entry point: the list entry it names, else its words; None when it names none (`unavailable`)."""
    e = rec.get("entry")
    if not e:
        return None
    k = entry_at(e, entries)
    if isinstance(k, tuple):
        return k
    w = " ".join(re.sub(r"[`*]", "", e).lower().split()).strip(" .")
    return None if w in ("", "unavailable", "n/a", "none", "unknown", "-", "—") else w


def overlap_files(cache: Path, plan: str) -> list:
    """The worker files `--overlaps` reads: the wave rosters' pairs' files, as the gate reads them — every
    `deep-<lens>-p<n>-results.md` of the cache when the plan holds no roster — so a stray file is no worker's."""
    pairs = [pr for _, body in re.findall(r"^wave roster (\d+):\s*(.*)$", plan, re.M) for pr in re.findall(r"[a-z-]+/p\d+", body)]
    if pairs:
        return [q for q in (cache / "deep-{}-{}-results.md".format(*pr.split("/", 1)) for pr in dict.fromkeys(pairs)) if q.is_file()]
    return sorted(q for q in cache.glob("deep-*-results.md") if re.match(r"^deep-(.+)-(p\d+)-results\.md$", q.name))


def own_sink_aliases(recs_by_file: dict, entries: list, cross: bool) -> list:
    """(file A, record A, file B, record B, sink): record B's own `File:` sink stands on record A's `Also at:` line at one
    class and entry point — within one file (`cross` False) or in two (`cross` True). A record naming no class or no
    entry point is read by neither side."""
    if not any(r_["also"] for recs_ in recs_by_file.values() for r_ in recs_):
        return []  # no group: nothing to read, and a 700-entry list is not resolved for nothing
    at_ = {}
    for f_, recs_ in recs_by_file.items():
        for r_ in recs_:
            k_ = entry_key(r_, entries)
            if r_["sink"] and r_["cls"] and k_ is not None:
                at_.setdefault((r_["cls"], k_, r_["sink"]), []).append((f_, r_))
    out = []
    for f_, recs_ in recs_by_file.items():
        for r_ in recs_:
            k_ = entry_key(r_, entries)
            if not r_["cls"] or k_ is None:
                continue
            for s_ in dict.fromkeys(r_["also"]):
                for fo_, o_ in at_.get((r_["cls"], k_, s_), []):
                    if o_ is not r_ and (fo_ != f_) == cross:
                        out.append((f_, r_, fo_, o_, s_))
    return out

def cited_locations(block: str) -> list[tuple[list[str], int, int, str, str]]:
    """Every `path:line`, `path:line-line`, `path:line,line` and `path:line:col` a block's `File:` and `Flow:` lines cite, as
    (the path read without and with the bracket or parenthesis its token opens with — `(auth)/page.tsx` is a name,
    `(apps/x.ts:12)` an aside — first line, the last line it reaches, where, the lines as cited). `where` is `sink` for the
    sink as item (37) reads it — the first `path:line` of the first `File:` line — `file` for another citation on a
    `File:` line, `flow` for a `Flow:` hop. The block is read as item (40) reads it: to its first `#`, `##` or `###`
    heading after its own, outside fenced code, a field line starting at the margin, so a section after the last block, a
    snippet quoting `File:` and indented code are not its citations. Tokens split on whitespace and arrows, so a name
    holding `$`, brackets or parentheses stays one path; a line number of ten digits or more is no line."""
    lines = unfenced(block).split("\n")
    body = lines[:1]
    for line in lines[1:]:
        if re.match(r"^#{1,3} ", line):
            break
        body.append(line)
    text = "\n".join(body)
    f_l = re.search(r"^\**Files?:\**\s*(.+)$", text, re.M)
    f_s = re.search(r"([^\s|:,;()]+):(\d+)", re.sub(r"[`*]", "", f_l.group(1))) if f_l else None
    norm = lambda x: re.sub(r"^(?:\./)+", "", rel(x.strip()))
    sink37 = (norm(f_s.group(1)), int(f_s.group(2))) if f_s else None
    # a record written absolute is met by its tail, and item (37)'s regex, which stops at a parenthesis, reads
    # `app/(auth)/page.tsx` as `/page.tsx`: the cited path that ends with that is the one it read
    same = lambda x, y: x == y or (y.startswith("/") and (y.endswith("/" + x) or x.endswith(y))) or (x.startswith("/") and x.endswith("/" + y))
    out, sink_taken = [], False
    for line in body[1:]:
        a_l = ALSO_RX.match(line)
        if a_l:  # an `Also at:` line's sinks are cited as `File:`'s are, read as items (24) and (26) read them
            for p_, n1_, n2_ in also_sinks(a_l.group(1), sink37[0] if sink37 else None):
                out.append(([p_], n1_, n2_, "file", f"{n1_}" if n1_ == n2_ else f"{n1_}-{n2_}"))
            continue
        m = re.match(r"^(?:[-*+]\s+)?\**(Files?|Flow)\**:\**\s*(.*)$", line)
        if not m:
            continue
        kind = "flow" if m.group(1) == "Flow" else "file"
        for tok in CITE_SPLIT_RX.split(m.group(2)):
            t = CITE_TOK_RX.match(tok)
            if not t:
                continue
            nums = [int(x) for x in re.findall(r"\d+", t.group("spec"))]
            pre = t.group("pre").lstrip("`'\"*")
            paths = [t.group("path")] + ([pre + t.group("path")] if pre else [])
            where = kind
            if kind == "file" and not sink_taken and sink37 and nums[0] == sink37[1] and any(same(norm(x), sink37[0]) for x in paths):
                where, sink_taken = "sink", True
            out.append((paths, nums[0], max(nums), where, t.group("spec").replace("\u2013", "-").replace("\u2014", "-")))
    return out


# a NEEDS CONTEXT judgement in a worker's prose: the base skill reports one under Unverifiable, and a worker writes it in
# its clearances, where no table row carries it
NC_RX = re.compile(r"(?i)\bneeds[\s-]context\b|\bunverifiable candidate\b|\[unverifiable\]|(?-i:\bUNVERIFIABLE\b)")
NC_REC_HEAD = re.compile(r"^(?:#+ )?\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\] VULN-", re.I)
# a worker's own NEEDS CONTEXT record, one candidate: its `[UNVERIFIABLE]` tag first (a severity tag may stand before
# it), or a `#` heading naming its id before the tag — a section heading `## Candidates [UNVERIFIABLE]` names none
NC_UNV_HEAD = re.compile(r"^\s*(?:#+\s*|[-*+]\s+|\d+[.)]\s+)?[*_]*(?:\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\]\s*)?\[UNVERIFIABLE\]", re.I)
NC_UNV_TAIL = re.compile(r"^#{1,6} .*\b[A-Z][A-Z0-9]*-[A-Z0-9-]*\d\b.*\[UNVERIFIABLE\]")
NC_ANS_RX = re.compile(r"^[-*+>\s]*(?:\d+[.)]\s*)?[*_`]*needs[\s-]+context[*_`]*\s*:[*_`]*\s*`?([a-z][a-z0-9-]*(?:/p\d+)?):(\d{1,9})`?[*_`]*"
                       r"\s*(?:—|–|--|-)\s*(.*\S)\s*$", re.I)
NC_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})([^`]*)$")  # a fence line: a one-line ```code``` span opens nothing
NC_END = re.compile(r"^#{1,6} |^\s*(?:-{3,}|\*{3,}|_{3,})\s*$|^\*{0,2}(?:Clearances?|Coverage|Pass log|Convergence|Hardening|Positive|Hits)\b[^*:]{0,60}\*{0,2}:?\*{0,2}\s*$", re.I)
NC_FIELD = re.compile(r"^\s*(?:[-*+]\s+)?\**(?:File|Location|Sink|Blocked|Missing|Judge|Verdict|Status|Reason|CWE|Class|Severity|"
                      r"Confidence|Description|Impact|Evidence|Flow|Entry|Source|Remediation|Fix|Recommendation|Reference|Worker|"
                      r"Note|Why|Context|Precondition|Attack|Exploit|Platform|Proof|Test|Adversarial|Base|Overlap|Variant|Ledger|"
                      r"Route|Reachability|Sanitization|Authorization|Business)[A-Za-z0-9 /&()\u2192-]{0,40}\**\s*:", re.I)  # a record's field line


def nc_pair(p: Path) -> str:
    """`deep-<lens>-p<n>-results.md` -> `<lens>/p<n>`; an unpartitioned `deep-<lens>-results.md` -> `<lens>`."""
    m = re.match(r"deep-(.+?)(?:-p(\d+))?-results\.md$", p.name)
    return (m.group(1) + (f"/p{m.group(2)}" if m.group(2) else "")) if m else p.name


def nc_lines(worker_files: list) -> list:
    """Every line of a worker file outside its finding records that names a NEEDS CONTEXT judgement — `(<lens>/p<n>,
    <line>, <text>)`, numbered as `grep -n` numbers it, the file split at its newlines alone. A record runs from its
    `[SEVERITY] VULN-` line to the next record, a `#` heading, a rule or a section label line; its row carries it. A
    worker's own `[UNVERIFIABLE]` record is one candidate, listed by its heading line alone: it runs over the field lines
    under its heading — `File:`, `- **Blocked by:**`, blank lines and fenced evidence — and ends at the first other line."""
    out = []
    for p in worker_files:
        try:
            raw = read_raw(p)
        except OSError:
            continue
        inside = unv = False
        fence = None  # the open fence's marker: only a bare fence of its character, as long or longer, closes it
        for n_, l in enumerate(raw.split("\n"), 1):
            head_ = False
            fm_ = NC_FENCE.match(l)
            if fence is None and fm_:
                fence = fm_.group(1)
            elif fence is not None:
                if fm_ and fm_.group(1)[0] == fence[0] and len(fm_.group(1)) >= len(fence) and not fm_.group(2).strip():
                    fence = None
            elif NC_REC_HEAD.match(l):
                inside, unv = True, False
            elif NC_UNV_HEAD.match(l) or NC_UNV_TAIL.match(l):
                inside, unv, head_ = False, True, True
            elif NC_END.match(l):
                inside = unv = False
            elif unv and l.strip() and not NC_FIELD.match(l):
                unv = False
            if head_ or (not inside and not unv and NC_RX.search(l)):
                out.append((nc_pair(p), n_, l.strip()))
    return out


def nc_section(report: str) -> str:
    """The report's Unverifiable section, its `## Unverifiable` heading to the next `##` heading."""
    m = re.search(r"^## Unverifiable\b.*$", report, re.M | re.I)
    return report[m.end():].split("\n## ", 1)[0] if m else ""


def nc_answers(section: str) -> dict:
    """`needs context: <lens>/p<n>:<line> — <answer>` lines of the Unverifiable section, by key."""
    out: dict = {}
    for l_ in section.splitlines():
        m_ = NC_ANS_RX.match(l_)
        if m_:
            out.setdefault((m_.group(1).lower(), int(m_.group(2))), []).append(m_.group(3).strip(" `*"))
    return out


def find_skills(explicit: str | None, shipped: str | None) -> Path | None:
    cands = []
    if explicit:
        cands.append(Path(explicit).expanduser())
    if shipped:
        cands.append(Path(shipped).expanduser().resolve().parent.parent)
    cands.append(Path(__file__).resolve().parent.parent)  # run from the skill's own directory: its parent is the skills root
    cands += [Path.home() / ".claude" / "skills", Path.home() / ".agents" / "skills"]
    for c in cands:
        if (c / "llm-sast-scanner" / "references").is_dir():
            return c
    return None


def frontmatter_version(skill_dir: Path) -> str | None:
    m = re.search(r'^\s*version:\s*"?([0-9][0-9.]*)"?', read(skill_dir / "SKILL.md"), re.M)
    return m.group(1) if m else None


def partition_checks(plan: str, cache: Path) -> tuple[bool, list[str], list[str]]:
    """STEP 1's partition checks, the one computation both `--checks` and recheck item (19) run: every partition's share of
    the `## Entry points` list at most 40%, and of the manifests' lines within 15% of one third. An entry belongs to the
    partition whose manifest holds its file — the list's `p<n>` column (a bare `<n>` reads the same) must agree with it.
    Returns (all pass, one share part per partition, one failure per defect)."""
    ep_sec = plan.split("## Entry points", 1)[1].split("\n## ", 1)[0] if "## Entry points" in plan else ""
    ep_lines = [l for l in ep_sec.splitlines() if ENTRY_LINE_RX.match(l)]
    man_text, man_lines = {}, {}
    for mp in sorted(cache.glob("partition-p*-manifest.txt")):
        pn = re.search(r"partition-(p\d+)-", mp.name).group(1)
        mt = read(mp)
        man_text[pn] = mt
        hl = re.search(r"^#?\s*lines:\s*(\d+)\s*$", mt, re.M)  # a `lines:` or `# lines:` total, else the sum of the rows
        man_lines[pn] = int(hl.group(1)) if hl else sum(int(a or b) for a, b in re.findall(r"^(\d+)\t|^[^|#\n]+\|\s*(\d+)\s*\|", mt, re.M))
    def holder(path: str) -> str | None:
        """The one manifest whose rows name this path (rows read `path: n`, `path | n | class` or `n<TAB>path`)."""
        rx = re.compile(r"(?:^|[\s|])" + re.escape(path) + r"(?=[\s|:]|$)", re.M)
        found = [pn for pn, mt in man_text.items() if rx.search(mt)]
        return found[0] if len(found) == 1 else None
    ep_per = Counter()
    ep_file = Counter()  # entries per (partition, file): one file's entries cannot be split across partitions
    unassigned, misplaced = [], []
    for l in ep_lines:
        loc = l.split(" | ", 1)[0].strip().lstrip("|").strip().strip("`")
        path = re.sub(r":\d+(?:-\d+)?$", "", loc)
        col_m = re.search(r"\|\s*p?(\d+)\s*\|?\s*$", l)
        col = f"p{col_m.group(1)}" if col_m else None
        home = holder(path)
        if col and home and col != home:
            misplaced.append(f"{loc} ({col}, file in {home})")
        part = home or col
        if not part:
            unassigned.append(loc)
            continue
        if not col:
            unassigned.append(loc)  # a line must name its partition: workers are assigned entries by that column
        ep_per[part] += 1
        ep_file[(part, path)] += 1
    tot_ep = sum(ep_per.values()) or 1
    tot_lines = sum(man_lines.values()) or 1
    file_rows = [(int(n_), f_.strip(), pn_) for pn_, mt_ in man_text.items() for f_, n_ in re.findall(r"^([^|#\n]+?)\s*\|\s*(\d+)\s*\|", mt_, re.M)]
    file_rows += [(int(n_), f_.strip(), pn_) for pn_, mt_ in man_text.items() for n_, f_ in re.findall(r"^(\d+)\t(.+)$", mt_, re.M)]
    big_file = max(file_rows, default=(0, None, None))  # the one file with the most lines, and the partition holding it
    parts, failures = [], []
    if unassigned:
        failures.append(f"{len(unassigned)} entry points name no partition ({', '.join(unassigned[:3])}{', …' if len(unassigned) > 3 else ''})")
    if misplaced:
        failures.append(f"{len(misplaced)} entry points name a partition other than their file's ({', '.join(misplaced[:3])}{', …' if len(misplaced) > 3 else ''})")
    for pn in sorted(set(ep_per) | set(man_lines)):
        eps = 100.0 * ep_per.get(pn, 0) / tot_ep
        ls = 100.0 * man_lines.get(pn, 0) / tot_lines
        if eps > 40.0:
            # a partition over the cap because one file alone is: no split or reassignment can bring it under, so the
            # failure is the skill's recorded outcome, not an unfinished cut
            big = max(((n_, f_) for (pp, f_), n_ in ep_file.items() if pp == pn), default=(0, None))
            one = f" (one file: {big[1]} holds {big[0]} of {sum(ep_per.values())} entry points)" if big[1] and 100.0 * big[0] / tot_ep > 40.0 else ""
            failures.append(f"{pn} holds {eps:.2f}% of entry points (cap 40%){one}")
        if not (100 / 3 * 0.85 <= ls <= 100 / 3 * 1.15):
            # one file above the cap by itself leaves no cut of whole files inside the band: the failure is the outcome
            # only the partition holding the file: the others can still be cut inside the band around it
            one_l = f" (one file: {big_file[1]} holds {big_file[0]} of {tot_lines} lines)" if big_file[1] and big_file[2] == pn and 100.0 * big_file[0] / tot_lines > 100 / 3 * 1.15 else ""
            failures.append(f"{pn} holds {ls:.2f}% of lines (outside 15% of one third){one_l}")
        parts.append(f"{pn} entry points {eps:.2f}% lines {ls:.2f}%")
    return (bool(parts) and not failures), parts, failures


COPY_FLOOR = 100  # a file with fewer eight-word phrases of composed prose than this is too short to tell a copy from a re-verification
COPY_FIELD = re.compile(r"^(?:CWE|Files?|Entry points?|References?|Worker record|Evidence|coverage|passes|convergence|unread ranges|new entry points|procedure)\s*:", re.I)
COPY_PRESCRIBED = re.compile(r"SAFE in p\d+ — no .*? in this partition|no in-repository production caller|ledger empty", re.I)


def composed_words(text: str) -> list[str]:
    """A worker file's composed prose, as its words: what a re-verifying worker writes afresh even at an unchanged commit,
    where the code it quotes, the paths it cites and the forms the template prescribes are the same. Left out: code fences,
    lines indented two spaces or a tab that are not list items (quoted code), the first line, headings, comments,
    label-only lines, the lines that open with `CWE:`, `File:`, `Entry point:`, `Reference:`, `Worker record:`,
    `Evidence:`, `coverage:`, `passes:`, `convergence:`, `unread ranges:`, `new entry points:` or `procedure:`, and the
    template's prescribed phrases."""
    out, fence = [], False
    for i, l in enumerate(text.splitlines()):
        s_ = l.strip()
        if s_.startswith("```") or s_.startswith("~~~"):
            fence = not fence
            continue
        if fence or not s_:
            continue
        if (l[:2] == "  " or l[:1] == "\t") and not re.match(r"^(?:[-*+]|\d+[.)])\s", s_):
            continue
        t = re.sub(r"^(?:[-*+>]\s+|\d+[.)]\s+)+", "", s_).replace("**", "").replace("__", "")
        if i == 0 or t.startswith("#") or t.startswith("<!--") or re.match(r"^[^:]{1,40}:\s*$", t) or COPY_FIELD.match(t):
            continue
        out.append(COPY_PRESCRIBED.sub(" ", t))
    return re.findall(r"\w+", " ".join(out).lower())


# item 37's entry-point reading: the words that name nothing in particular — every entry point is an operation, a handler,
# a route or an HTTP endpoint — and a cell holding only such words names its record's entry point only by its words
EP_GENERIC = set("""entry point points worker graphql gql query queries mutation mutations subscription resolver resolvers field
fields type types handler handlers http https route routes request requests input inputs src modules module common services
service utils util helpers helper data sources source datasource datasources index the and for with from into via used uses
none this that when calls call called method methods function functions class file files line lines through path api rest get
post put delete patch public private yaml yml json apollo server express endpoint endpoints operation operations root level
top any all its their other same new not""".split())


def ep_norm(s_: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[`*]", "", s_.lower())).strip()


def ep_words(s_: str) -> set:
    """The words of an entry point that name it: four letters or more, none of EP_GENERIC, a plural's `s` dropped."""
    out = set()
    for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", re.sub(r"[`*]", "", s_)):
        w = w.lower()
        if len(w) >= 4 and w not in EP_GENERIC:
            out.add(w[:-1] if len(w) > 4 and w.endswith("s") else w)
    return out


EP_META = {"vuln", "see", "record", "records", "impact", "flow", "flows", "reference", "description", "judge", "remediation",
           "evidence", "adversarial", "severity", "status", "finding", "findings", "cwe", "confirmed", "likely", "standing",
           "downgraded", "disputed", "unknown", "unavailable", "entry", "point", "points", "worker", "sink", "sinks"}  # the report's own words


def ep_meets(cell: str, ep: str, flow: str, id_lines: str, sink: tuple | None) -> bool:
    """A table row's entry point cell names its worker record's entry point. The writer names it as the scan-plan's
    `## Entry points` list does, the record in its own words, so the cell is met by what the worker wrote about the entry
    point — the record's `Entry point:` line first, then its `Flow:` line and the lines of its file that name its id (a
    record whose entry point is `the operations listed below`) — never by the rest of its block, whose id, labels and sink
    name every row's record. Paths are read by their file name, so a directory (`src`, `services`) names nothing. The
    cell meets the entry point when either holds the other whole; when a naming word of the cell — four letters or more,
    none of EP_GENERIC or the report's words — is in the `Entry point:` line, or its `file:line` is; when such a word or
    `file:line` that is not the sink's own is in the `Flow:` line or the id's lines (where the sink always stands); when a
    naming word of the `Entry point:` line is in the cell; or when the two share a name of twelve letters or more. A cell
    of generic words meets it only when the `Entry point:` line holds at least half of them; a cell with no word, never. An
    entry point that names several (`;`, `every`, two `file:line`s) is met by any cell that names something of its own."""
    idx = lambda s_: re.sub(r"(?:\b[a-z][a-z-]*/p\d+/)?VULN-[A-Za-z0-9-]*\d", " ", s_)  # an id, with its `<lens>/p<n>/`
    base = lambda s_: re.sub(r"(?:[\w.~-]+/)+([\w-][\w.-]*\.[A-Za-z]{1,5})\b", r"\1", re.sub(r"[`*]", "", s_))  # a file path by its name
    c_, e_ = ep_norm(idx(cell)), ep_norm(ep)
    if c_ and c_ == e_:
        return True  # the record's entry point copied as it stands — a route `/` has no word to name it by
    if not re.search(r"[a-z0-9]{3}", c_):
        return False
    if e_ and (c_ in e_ or e_ in c_):
        return True
    cb_, eb_, rest_ = base(idx(cell)), base(ep), base(idx(flow + "\n" + id_lines))
    s_file, s_line = ((Path(sink[0]).name.lower(), str(sink[1])) if sink else ("", ""))
    for f_, l_ in re.findall(r"([A-Za-z0-9_.-]+\.[A-Za-z]{1,5}):(\d+)", cb_):
        pat_ = r"(?:^|[\s`(])" + re.escape(f_) + r":" + l_ + r"(?!\d)"
        if re.search(pat_, eb_) or ((f_.lower(), l_) != (s_file, s_line) and re.search(pat_, rest_)):
            return True
    naming = ep_words(cb_) - EP_META
    # a record naming several entry points gives the cell nothing single to copy (item (4) reads it so): its cell need only
    # name something — a word or a `file:line` of its own, never the report's words alone
    several = ";" in eb_ or re.search(r"\b(?:every|all|each|any)\b", eb_, re.I) or len(re.findall(r"[\w-]+\.[A-Za-z]{1,5}:\d+", eb_)) >= 2
    if several and (naming or re.search(r"[\w-]+\.[A-Za-z]{1,5}:\d+", cb_)):
        return True
    if not naming:
        words_ = [w for w in re.findall(r"[a-z0-9_]+", c_) if len(w) >= 3 and w not in EP_META]
        ew_ = set(re.findall(r"[a-z0-9_]+", e_))
        return bool(words_) and 2 * sum(1 for w in words_ if w in ew_) >= len(words_)
    flat_e = re.sub(r"[^a-z0-9]", "", eb_.lower())
    if any(t in flat_e for t in naming):
        return True
    sink_w = ep_words(Path(sink[0]).name) if sink else set()
    flat_r = re.sub(r"[^a-z0-9]", "", rest_.lower())
    if any(t in flat_r for t in naming - sink_w):
        return True
    flat_c = re.sub(r"[^a-z0-9]", "", cb_.lower())
    if any(t in flat_c for t in ep_words(eb_) - EP_META):
        return True
    import difflib
    a_ = "".join(w for w in re.findall(r"[a-z0-9]+", cb_.lower()) if w not in EP_GENERIC)
    b_ = "".join(w for w in re.findall(r"[a-z0-9]+", eb_.lower()) if w not in EP_GENERIC)
    return bool(a_ and b_) and difflib.SequenceMatcher(None, a_, b_, autojunk=False).find_longest_match(0, len(a_), 0, len(b_)).size >= 12


def copied_share(text: str, cache: Path, name: str) -> tuple[int | None, str]:
    """The share, in whole percent rounded down, of a worker file's eight-word phrases of composed prose that the file of the
    same name under a `previous-run-*` directory also holds — in any order and across line breaks, so a moved section or a
    re-wrapped line is the same phrase — the highest over those directories, with that directory's name. None when the file
    holds fewer than COPY_FLOOR phrases; 0 and "" when no directory holds a file of that name."""
    w = composed_words(text)
    b = {tuple(w[i:i + 8]) for i in range(len(w) - 7)}
    if len(b) < COPY_FLOOR:
        return None, ""
    best, where = 0, ""
    for d in sorted(cache.glob("previous-run-*")):
        try:
            if not (d / name).is_file():
                continue
        except OSError:
            continue
        wa = composed_words(read(d / name))
        a = {tuple(wa[i:i + 8]) for i in range(len(wa) - 7)}
        pct = 100 * len(a & b) // len(b)
        if pct > best:
            best, where = pct, d.name
    return best, where


def gate_lines(target: Path, cache: Path, plan: str, skills: Path | None, only: str | None = None, with_copied: bool = True) -> tuple[bool, list[str]]:
    """The artifact gate, one `gate:` line per worker file exactly as the gate rule defines each field — the one computation
    STEP 2's gate writes and a worker may run on its own file before its sentinel. Returns (every line passes, lines)."""
    def fm(skill: str, key: str) -> str | None:
        m = re.search(r"^\s*" + key + r":\s*\"?([^\"\n]+?)\"?\s*$", read(skills / skill / "SKILL.md"), re.M) if skills else None
        return m.group(1).strip() if m else None
    want = {(fm(s, "name"), fm(s, "version")) for s in ("llm-sast-scanner-convergence-loop", "llm-sast-scanner")}
    stems = {q.stem for q in (skills / "llm-sast-scanner" / "references").glob("*.md")} if skills else set()
    plan_target = corrected_str(plan, "target:")  # as the run last stated it, like the base-sha beside it
    plan_sha = plan_base_sha(plan) or ""
    start = corrected(plan, "ledger rows at start:")
    ep_list_g = entry_list(plan)
    pairs = [pr for _, body in re.findall(r"^wave roster (\d+):\s*(.*)$", plan, re.M) for pr in re.findall(r"[a-z-]+/p\d+", body)]
    if not pairs:
        pairs = sorted(f"{m_.group(1)}/{m_.group(2)}" for m_ in (re.match(r"^deep-(.+)-(p\d+)-results\.md$", q.name) for q in cache.glob("deep-*-results.md")) if m_)
    out, all_ok = [], True
    for pair in pairs:
        if only and only not in ("all", pair):
            continue
        lens, part = pair.split("/", 1)
        f = cache / f"deep-{lens}-{part}-results.md"
        if not f.exists():
            continue  # a pair with no worker file has no gate line
        text = read(f)
        lines_ = text.splitlines()
        first = lines_[0].strip() if lines_ else ""
        fields = {}
        parsed = True
        for chunk in first.split(" | "):
            m = re.match(r"^([a-z-]+):\s*(.+)$", chunk.strip())
            if not m:
                parsed = False
                break
            fields[m.group(1)] = m.group(2).strip()
        proc = [tuple(x.strip().rsplit(" v", 1)) for x in fields.get("procedure", "").split(" / ")] if fields.get("procedure") else []
        header_ok = parsed and len(proc) == 2 and all(len(x) == 2 for x in proc) and set(proc) == want
        pinned_ok = parsed and fields.get("target") == plan_target and fields.get("base-sha") == plan_sha
        if start and start > 0:
            phrase_ok = re.search(r"new entry points:\s*\d+", text, re.I) is not None
        else:
            phrase_ok = re.search(r"ledger empty", text, re.I) is not None
        man = read(cache / f"partition-{part}-manifest.txt")
        mf = re.search(r"^#?\s*files:\s*(\d+)\s*$", man, re.M)
        ml = re.search(r"^#?\s*lines:\s*(\d+)\s*$", man, re.M)
        mf_n, ml_n = (int(mf.group(1)) if mf else None), (int(ml.group(1)) if ml else None)
        tail = [l for l in lines_ if l.strip()]
        sm = re.match(r"^<!-- LLM-SAST-COMPLETE lens=([a-z-]+) partition=(p\d+) files=([\d,]+)/([\d,]+) lines=([\d,]+)/([\d,]+) passes=(\d+)[^\n]*-->\s*$", tail[-1].strip()) if tail else None
        if sm and sm.group(1) == lens and sm.group(2) == part:
            fv, lv, pv = int(sm.group(3).replace(",", "")), int(sm.group(5).replace(",", "")), int(sm.group(7))
            mfv = mf_n if mf_n is not None else int(sm.group(4).replace(",", ""))
            mlv = ml_n if ml_n is not None else int(sm.group(6).replace(",", ""))
            sent = f"sentinel files {fv}/{mfv} lines {lv}/{mlv} passes {pv}"
            sent_ok = fv >= mfv and lv >= mlv and pv > 0 and int(sm.group(4).replace(",", "")) == mfv and int(sm.group(6).replace(",", "")) == mlv
        else:
            sent, sent_ok = "sentinel absent", False
        # one record per `File:` line (a plural `Files:` line listing several paths is one record, resolving when all do)
        roots = {r_ for r_ in (plan_target.rstrip("/"), str(target)) if r_}  # the run's target row, and where this runs
        def under(pth: str) -> str | None:
            """An absolute path under the target, as the path relative to it; None for one outside."""
            return next((pth[len(r_) + 1:] for r_ in roots if pth.startswith(r_ + "/")), None)
        def exists(pth: str) -> bool:
            rel_ = under(pth) if pth.startswith("/") else pth
            return rel_ is not None and (target / rel_).is_file()
        records_paths = []
        for m in re.finditer(r"^\**Files?:\**\s*(.+)$", text, re.M):
            toks = re.findall(r"`([^`]+)`", m.group(1)) or [m.group(1).split()[0]]
            records_paths.append([re.sub(r":\d+(?:-\d+)?$", "", tok.strip().strip("*").rstrip(",;.)").split()[0]) for tok in toks if tok.strip()])
        m_ = len(records_paths)
        k = sum(1 for ps in records_paths if ps and all(exists(pth) for pth in ps))
        a = sum(1 for ps in records_paths if any(pth.startswith("/") and under(pth) is not None for pth in ps))
        s = sum(1 for l in lines_ if re.match(r"^(?:#+ )?\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\] VULN-", l, re.I))
        # `r` counts RECORDS carrying a Reference line, never Reference lines: a Clearance Record section names reference files
        # too, and counting its lines once showed `references 22/3`. A record's block runs from the heading above its File:
        # line to the next heading.
        def names_stem(l: str) -> bool:
            return re.match(r"^\**Reference:\**", l) is not None and any(re.search(r"(?:^|[/`\s])" + re.escape(st) + r"\.md\b", l) for st in stems)
        # a record's block ends at the next record heading (one naming a VULN- id) or a section heading (`#` or `##`), never at
        # a sub-heading inside the record, such as `#### Evidence`
        heads_at = [i for i, l in enumerate(lines_) if re.match(r"^(?:#+\s|\[|\*\*\[).*VULN-", l) or re.match(r"^#{1,2}\s", l)]
        r = 0
        for i, l in enumerate(lines_):
            if not re.match(r"^\**Files?:\**\s*\S", l):
                continue
            blk_from = max([h for h in heads_at if h <= i], default=0)  # never `start`: that name holds `ledger rows at start`
            blk_to = min([h for h in heads_at if h > i], default=len(lines_))
            r += any(names_stem(x) for x in lines_[blk_from:blk_to])
        records_seen = s or sum(1 for l in lines_ if re.match(r"^(?:#+ )?\[[A-Za-z]+\] VULN-", l))
        # a record written behind a list marker, a blockquote `>` or indentation is still a record, one no count downstream
        # reads: the file's record count takes it, so its heading shows missing and the worker is re-run, never passed
        disguised = sum(1 for l in lines_ if re.match(r"^\s*(?:>\s*)*(?:[-*+]\s+)?(?:#+\s*)?\**\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*|CONFIRMED|LIKELY)\]\** VULN-", l, re.I)
                        and not re.match(r"^(?:#+ )?\[[A-Za-z]+\] VULN-", l))
        m_ = m_ + disguised if disguised else m_
        if m_ == 0 and records_seen > 0:
            # records and not one File: line — `0/0` would read as a pass to everything that reads the line, so the count is
            # the records' headings and the line shows the paths, headings and references those records lack
            m_ = records_seen
        paths_ok = k == m_
        # a `|` in an `Entry point:` line is counted, never a fail: the plan's entry-point list writes ` | ` between its fields, and a
        # worker naming an entry point as the list does carries them; the writer builds the table cell without them
        e = sum(1 for l in lines_ if re.match(r"^\**Entry point:\**", l.strip()) and "|" in l.split(":", 1)[1])
        c, c_from = copied_share(text, cache, f.name) if with_copied else (None, "")
        try:
            dg = hashlib.sha256(f.read_bytes()).hexdigest()[:12]  # the file as gated: any later write changes it
        except OSError:
            dg = "unreadable"
        # a line over the reader's limit outside a fenced code block: the writer reads only its start
        ll = len(long_text_lines(text))
        # the records whose `Also at:` line names a sink and those of them naming no other record's own `File:` sink in
        # this file at their class and entry point — such a line is one finding filed twice or a line of its own on a group
        recs_g = worker_records(text, stems, tuple(sorted(roots, key=len, reverse=True)))
        grp_ = [r_ for r_ in recs_g if r_["also"]]
        bad_g = {id(a_) for _, a_, _, _, _ in own_sink_aliases({f.name: recs_g}, ep_list_g, False)}
        gk, gg = sum(1 for r_ in grp_ if id(r_) not in bad_g), len(grp_)
        ok = header_ok and pinned_ok and phrase_ok and sent_ok and paths_ok and s >= m_ and r >= m_ and (c is None or c < COPY_CAP) and ll == 0 and gk == gg
        all_ok = all_ok and ok
        out.append(f"gate: {pair} — header {'ok' if header_ok else 'fail'} | pinned {'ok' if pinned_ok else 'fail'} | phrase {'ok' if phrase_ok else 'fail'} | {sent} | paths {k}/{m_} resolve | headings {s}/{m_} | absolute {a} | references {r}/{m_} | entry pipes {e} | copied " + ("n/a" if c is None else f"{c}%" + (f" from {c_from}" if c else "")) + f" | digest {dg} | long lines {ll} | groups {gk}/{gg}")
    return all_ok, out


BASE_LENSES = ["injection", "access-auth", "crypto-data", "server-side", "protocol-infra", "hardening-platform"]


def _flat(s: str) -> str:
    """Text as a subagent reads it: blockquote markers, backticks and bold dropped, whitespace collapsed."""
    s = re.sub(r"(?m)^\s*>\s?", "", s)
    s = s.replace("`", "").replace("**", "")
    # typography is not wording: curly quotes and dash variants read as their plain forms on both sides of a comparison
    s = s.translate({0x2018: "'", 0x2019: "'", 0x201C: '"', 0x201D: '"', 0x2013: "\u2014", 0x2212: "-"})
    s = re.sub(r"\s+--?\s+", " \u2014 ", s)
    return re.sub(r"\s+", " ", s).strip()


def _span_rx(span: str, skills: Path | None = None) -> re.Pattern:
    """A template span as a pattern: `<skills root>` stands for any path — the skills directory itself too, spaces and all —
    `<lens>` for the placeholder or a lens name."""
    rx = re.escape(_flat(span))
    root = r"\S+?" if not skills else "(?:" + "|".join(re.escape(_flat(str(q))) for q in dict.fromkeys((skills, skills.resolve()))) + r"|\S+?)"
    rx = rx.replace(re.escape("<skills root>"), root).replace(re.escape("<lens>"), r"(?:<lens>|[a-z][a-z-]*)")
    return re.compile(rx)


def template_spans(skills: Path) -> dict[str, str]:
    """The checked spans, taken from this skill's own SKILL.md so the check follows the text."""
    sk = read(skills / "llm-sast-scanner-full-scan-loop" / "SKILL.md")
    # the worker template is the blockquote; the contract-check paragraph above it quotes the same opening words, so the
    # spans are searched in the template's own lines only, joined as a subagent reads them
    flat_tpl = _flat("\n".join(l for l in sk.splitlines() if l.startswith(">")))
    spans = {}
    a = flat_tpl.find("for every ledger sink whose file is in your partition")
    b = flat_tpl.find("new entry points: <count>", a)
    if a >= 0 and b > a:
        spans["caller enumeration"] = flat_tpl[a:b + len("new entry points: <count>")]
    a = flat_tpl.find("You are the <lens> worker for partition p<n>")
    b = flat_tpl.find("If you stop early, omit the sentinel.", a)
    if a >= 0 and b > a:
        spans["worker template"] = flat_tpl[a:b + len("If you stop early, omit the sentinel.")]
    a = flat_tpl.find("Before the final line, check your own file")
    b = flat_tpl.find("before you write it.", a)
    if a >= 0 and b > a:
        spans["self-gate"] = flat_tpl[a:b + len("before you write it.")]
    a = sk.find("**Writer self-check.**")
    b = sk.find("\n\n", a)
    if a >= 0 and b > a:
        spans["writer self-check"] = sk[a:b]
    a = sk.find("**Same-commit carry.**")
    b = sk.find("\n\n", a)
    if a >= 0 and b > a:
        spans["same-commit carry"] = sk[a:b]
    return spans


def contract_lines(cache: Path, plan: str, skills: Path) -> tuple[bool, list[str]]:
    """STEP 1's contract check over every lens contract: the first-line form and the sentinel form with their placeholders
    intact, the caller enumeration and the self-gate copied from the template. Returns (all pass, lines)."""
    spans = template_spans(skills)
    # the lens set: the rosters' pairs when STEP 1 has written them (the definitive list), else the plan's lens rows, each item
    # read as its leading lens name so a note after a name is ignored
    def lens_row(name: str) -> list[str]:
        return [m.group(0) for x in (row(plan, name) or "").split(",") for m in [re.match(r"[a-z][a-z-]*", x.strip())] if m and m.group(0) != "none"]
    ros = [pr.split("/")[0] for _, body in re.findall(r"^wave roster (\d+):\s*(.*)$", plan, re.M) for pr in re.findall(r"[a-z-]+/p\d+", body)]
    if ros:
        lenses = list(dict.fromkeys(ros))
    else:
        base = lens_row("base lenses:") or BASE_LENSES
        lenses = base + [x for x in lens_row("added lenses:") if x not in base]
    # introduced by `Its first line is`, a few words of the orchestrator's own allowed before the form ("exactly", a colon)
    first_rx = re.compile(re.escape("Its first line is") + r"[^<]{0,80}?" + re.escape(_flat("procedure: <convergence-loop skill name> v<its version> / <base skill name> v<its version> | target: <pwd output> | base-sha: <git output>")))
    sent_rx = re.compile(r"The final line.{0,120}?<!-- LLM-SAST-COMPLETE lens=\S+ partition=p<n> files=<f>/<mf> lines=<l>/<ml> passes=<p> convergence=")
    out, good = [], 0
    for lens in lenses:
        c = cache / f"{lens}-agent-procedure.md"
        if not c.exists():
            out.append(f"contract {lens}: absent")
            continue
        flat = _flat(read(c))
        missing = [name for name, ok_ in [
            ("first-line form", first_rx.search(flat) is not None),
            ("sentinel form", sent_rx.search(flat) is not None),
            ("caller enumeration", "caller enumeration" in spans and _span_rx(spans["caller enumeration"], skills).search(flat) is not None),
            ("self-gate", "self-gate" in spans and _span_rx(spans["self-gate"], skills).search(flat) is not None),
            ("skills root filled", "<skills root>" not in flat),
        ] if not ok_]
        if missing:
            out.append(f"contract {lens}: missing {', '.join(missing)}")
        else:
            good += 1
    return good == len(lenses), [f"contracts checked: {good}/{len(lenses)}"] + out


def roster_lines(plan: str, k: int, cache: Path | None = None) -> tuple[bool, list[str]]:
    """Wave k's pairs from its `wave roster <k>:` line — the batch STEP 2 sends — the first attempts recorded so far, and,
    once every pair's file ends with its sentinel or the pair is recorded `worker not run:`, the wave's `complete` time."""
    ros = dict((int(a), re.findall(r"[a-z-]+/p\d+", b)) for a, b in re.findall(r"^wave roster (\d+):\s*(.*)$", plan, re.M))
    if k not in ros:
        return False, [f"wave {k}: no `wave roster {k}:` line"]
    pairs = ros[k]
    lines = [f"wave {k}: {len(pairs)} workers — start exactly these {len(pairs)} subagents and no other"] + pairs
    firsts = {}
    for pair, when, _ in re.findall(r"^([a-z-]+/p\d+): \S+ (\S+) paths \d+/\d+(.*)$", plan, re.M):
        firsts[pair] = min(firsts.get(pair, when), when)
    # each wave's start by its own number, whatever the line says between the count and `started` (an error form included)
    starts = {int(a): b for a, b in re.findall(r"^wave (\d+): .*?\| started (\d[\d:_-]+)", plan, re.M)}  # dated or time-only stamps
    if firsts and k in starts:
        lo = starts[k]
        later = sorted(w for n_, w in starts.items() if n_ > k)
        hi = later[0] if later else None
        in_wave = sorted(p_ for p_, w in firsts.items() if w >= lo and (hi is None or w < hi))
        extra = sorted(set(in_wave) - set(pairs))
        missing = sorted(set(pairs) - set(in_wave))
        if cache is not None:
            not_run = set(re.findall(r"^worker not run: ([a-z-]+/p\d+)", plan, re.M))
            done, newest = 0, None
            for pr in pairs:
                f_ = cache / f"deep-{pr.split('/')[0]}-{pr.split('/')[1]}-results.md"
                sealed = f_.exists() and "LLM-SAST-COMPLETE" in ([l for l in read(f_).splitlines() if l.strip()] or [""])[-1]
                if sealed:
                    newest = max(newest or 0, f_.stat().st_mtime)
                done += sealed or pr in not_run
            # the completion is read from the files, rounded up to the second, so no file is sealed after it
            lines.append(f"wave {k} files ended {done}/{len(pairs)}" + (f" — complete {time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime(int(newest) + (0 if newest == int(newest) else 1)))}" if done == len(pairs) and newest else ""))
        lines.append(f"recorded first attempts in wave {k}: {len(in_wave)}" + (f" | not on this roster: {', '.join(extra)}" if extra else "") + (f" | roster pairs not yet started: {', '.join(missing)}" if missing else ""))
        return not extra, lines
    return True, lines


def paths_lines(path: Path, target: Path, pair: str | None, skills: Path | None = None) -> tuple[bool, list[str]]:
    """A worker prompt file before it is sent: every filesystem path it names exists — absolute paths anywhere (after `=` or
    `:` too), bare file names resolved in the target and then its cache — and the worker's output path, which cannot exist
    yet, equals `<target>/.llm-sast-scanner-cache/deep-<lens>-p<n>-results.md` for the prompt's own pair."""
    text = read(path)
    if not text:
        return False, [f"paths {path.name}: prompt file absent or empty"]
    long_p = long_lines(text)
    # a home-relative path is a path: `~/`, `$HOME/` and `${HOME}/` read as the home directory they stand for
    text = re.sub(r"(?<![\w.~:/-])(?:~|\$HOME|\$\{HOME\})(?=/)", lambda _: str(Path.home()), text)
    cache = target / ".llm-sast-scanner-cache"
    # a root the run itself names — the target, the home directory, the skills directory — may hold spaces: each is read as
    # one token while paths are collected, so a path under it stays one path; a misspelling below the root still fails
    roots = sorted({str(r) for r in (target, target.resolve(), Path.home(), skills, skills.resolve() if skills else None)
                    if r is not None and " " in str(r)}, key=len, reverse=True)
    alias = {f"/__sast_root{i}__": r for i, r in enumerate(roots)}
    scan = text
    for a, r in alias.items():
        scan = scan.replace(r, a)
    def unalias(tok: str) -> str:
        for a, r in alias.items():
            if tok.startswith(a):
                return r + tok[len(a):]
        return tok
    trail = ".,;:)]}'\"`\u2019\u201d"
    found, missing, wrong_out = [], [], []
    expected_out = (cache / f"deep-{pair.split('/')[0]}-{pair.split('/')[1]}-results.md") if pair else None
    # a URL is not a path: `https://host/x` holds `//host/x`, so a double slash never opens one; `key:/path` does
    for m in re.finditer(r"(?<![\w.~/-])(/(?!/)[^\s`'\"<>|,;()\u2018\u2019\u201c\u201d\u2013\u2014\u2026]+)", scan):
        # a cited `:line`, `:line-line`, `:line:col` or `#anchor` names a place in the file, not another file; stars after an
        # extension are emphasis (`**…/scan-plan.md**`), not a glob
        tok_ = re.sub(r"(?::\d+(?:[-:]\d+)*|#[\w-]+)$", "", m.group(1).rstrip(trail)).rstrip(trail)
        tok_ = re.sub(r"(\.(?:md|txt|json|py|ya?ml))\*+$", r"\1", tok_)
        # a route (`POST /graphql`, `/api/items/:id`) is not a path: a filesystem path starts at a directory the root holds
        tok_ = unalias(tok_)
        if tok_.strip("/") and not Path("/" + tok_.strip("/").split("/")[0]).exists():
            continue
        found.append(tok_)
    # a glob inside a name too; a name never starts right after a glob star inside another name (`deep-*-results.md`),
    # while a name in italics (`*scan-plan.md*`) is still read
    for m in re.finditer(r"(?<![/\w.-])(?<![\w./-][*?])([\w.-][\w.*?-]*/)*[\w.-][\w.*?-]*\.(?:md|txt|json|py|ya?ml)\b", scan):
        tok = re.sub(r"(\.(?:md|txt|json|py|ya?ml))\*+$", r"\1", m.group(0).rstrip(trail))
        if not tok.startswith("/") and not any(f.endswith("/" + tok) for f in found):
            found.append(tok)
    seen, tested, ok_n = set(), 0, 0
    for tok in found:
        if tok in seen:
            continue
        seen.add(tok)
        if re.search(r"deep-[a-z-]+-p\d+-results\.md$", tok):
            full = Path(tok) if tok.startswith("/") else (target / tok if "/" in tok else cache / tok)
            tested += 1
            if expected_out is not None and full.resolve() != expected_out.resolve():
                wrong_out.append(tok)
            elif not full.parent.is_dir():
                wrong_out.append(tok)
            else:
                ok_n += 1
            continue
        if re.search(r"[*?\[]", tok):
            # a glob names a pattern, not a file (no worker file exists yet at a first dispatch): its directory must exist
            head = Path(re.split(r"[*?\[]", tok, maxsplit=1)[0] + "x").parent
            tested += 1
            if (head if tok.startswith("/") else target / head).is_dir():
                ok_n += 1
            else:
                missing.append(tok)
            continue
        cands = [Path(tok)] if tok.startswith("/") else [target / tok, cache / tok] + (
            ([r / tok for q in skills.iterdir() if q.is_dir() for r in (q, q / "references")] if "/" not in tok  # a bare skill or reference file name
             else [skills / tok] + [q / tok for q in skills.iterdir() if q.is_dir()]) if skills else [])  # or a path inside a skill
        tested += 1
        if any(c.exists() for c in cands):
            ok_n += 1
        else:
            missing.append(tok)
    # the first-line form and the sentinel form keep their placeholders by rule: they are not read for unfilled ones
    bare = re.sub(r"<!-- LLM-SAST-COMPLETE[^\n]*?-->", " ", text)
    bare = re.sub(r"procedure: <convergence-loop skill name>[^\n`]*<git output>", " ", bare)
    unfilled = sorted(set(re.findall(r"<(?:skills root|lens|target)>", bare)) | ({"p<n>"} if "p<n>" in bare else set()))
    if pair and expected_out is not None and not any(re.search(r"deep-[a-z-]+-p\d+-results\.md$", tok) for tok in found):
        wrong_out.append("(none named — the prompt must name its output file)")
    others, first_bad, form_missing, stale, misplaced = [], None, False, None, None
    if pair:
        lens_p, part_p = pair.split("/")
        home_ = (cache / "prompts" / f"{lens_p}-{part_p}.md").resolve()
        if str(path.resolve()).startswith(str(target.resolve()) + "/") and path.resolve() != home_:
            misplaced = str(home_)
        # a prompt names its own partition's manifest and its own lens's contract, never another pair's
        others = sorted(set(f"partition-{x}-manifest.txt" for x in re.findall(r"partition-(p\d+)-manifest\.txt", text) if x != part_p)
                        | set(f"{x}-agent-procedure.md" for x in re.findall(r"(?<![\w-])([a-z][a-z-]*)-agent-procedure\.md", text) if x != lens_p))
        # its first line names its own lens and partition, the line the worker checks before it follows the file
        first = _flat(next((l for l in text.splitlines() if l.strip()), ""))
        parts_named = re.findall(r"partition (p\d+)", first)
        if not (re.search(rf"(?<![\w-]){re.escape(lens_p)}(?![\w-])", first) and parts_named and set(parts_named) == {part_p}):
            first_bad = first[:120]
        # the first-line form survives the write with its placeholders (an unquoted heredoc runs its backticks)
        form_missing = re.search(re.escape("Its first line is") + r"[^<]{0,80}?" + re.escape(_flat("procedure: <convergence-loop skill name> v<its version> / <base skill name> v<its version> | target: <pwd output> | base-sha: <git output>")), _flat(text)) is None
    # the prompt is the WORKER DISPATCH text with its slots filled, the whole of it: a prompt whose template was dropped,
    # condensed or mangled passes every path test above, so the text itself is compared, sentence by sentence
    tpl_missing, one_char = None, 0
    lines_ = text.split("\n")
    one_char = sum(1 for l in lines_ if len(l.strip()) == 1)
    if pair and skills:
        tpl = template_spans(skills).get("worker template")
        if tpl:
            # dashes and arrows read alike (`1-5`, `1–5`; `->`, `→`), and the target as `pwd` prints it or resolved
            dnorm = lambda s: re.sub(r"[\u2013\u2014-]", "-", s).replace("\u2192", "->")
            flat_p = dnorm(_flat(text))
            logical = Path(os.environ.get("PWD", "")) if os.environ.get("PWD") else None
            tgt_forms = [q for q in (target, target.resolve(), logical) if q is not None and str(q) and q.resolve() == target.resolve()]
            tgts = "|".join(re.escape(dnorm(_flat(str(q)))) for q in dict.fromkeys(tgt_forms))
            roots = "|".join(re.escape(dnorm(_flat(str(q)))) for q in dict.fromkeys((skills, skills.resolve())))
            def slot_rx(s: str) -> str:
                rx = re.escape(dnorm(s))
                rx = rx.replace(re.escape("<skills root>"), f"(?:{roots}|\\S+?)").replace(re.escape("<target>"), f"(?:{tgts})")
                # a slot reads filled or, as the sentinel may keep it, as its placeholder — an unfilled one outside the
                # sentinel and first-line forms is caught by the placeholder scan above
                return rx.replace(re.escape("<lens>"), f"(?:{re.escape(lens_p)}|<lens>)").replace(re.escape("p<n>"), f"(?:{re.escape(part_p)}|p<n>)")
            sents = [s.strip() for s in re.split(r"(?<=[.;:])\s+(?=[A-Z`])", tpl) if s.strip()]
            for i_s, sent in enumerate(sents):
                if not re.search(slot_rx(sent), flat_p):
                    tpl_missing = sent[:90] + (" — a re-run reason goes on its own line after the prompt's first line" if i_s == 0 else "")
                    break
    # a prompt file older than this run's start is an earlier run's: a write that missed its path leaves it in place
    st_ = re.search(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", row(read(cache / "scan-plan.md"), "started:") or "")
    if st_:
        import datetime
        if path.stat().st_mtime < datetime.datetime.strptime(st_.group(0), "%Y-%m-%d_%H-%M-%S").timestamp():
            stale = st_.group(0)
    lines = [f"paths {ok_n}/{tested}"]
    if missing:
        lines.append("missing: " + ", ".join(missing))
    if others:
        lines.append("another pair named: " + ", ".join(others))
    if first_bad is not None:
        lines.append(f"first line does not name {pair}: {first_bad!r}")
    if form_missing:
        lines.append("first-line form missing — the prompt ends with it, placeholders intact")
    if stale:
        lines.append(f"prompt file older than this run's start ({stale}) — write it again")
    if misplaced:
        lines.append(f"prompt file not at {misplaced}, where the send line's fallback reads it")
    if one_char > 50:
        lines.append(f"text written one character per line ({one_char} such lines) — the prompt was built by joining a string's characters")
    if tpl_missing is not None:
        lines.append(f"worker template not in the prompt with its slots filled; first sentence missing: {tpl_missing!r}")
    if long_p:
        lines.append(f"line {long_p[0][0]} is {long_p[0][1]} bytes" + (f" ({len(long_p)} lines over {LINE_LIMIT})" if len(long_p) > 1 else "")
                     + f" — a file reader cuts a line over {LINE_LIMIT} bytes (UTF-8, an em dash three) and the worker reads only its start: write the prompt with the template's line breaks")
    if wrong_out:
        lines.append(f"output path not {expected_out if expected_out else 'under the cache'}: " + ", ".join(wrong_out))
    if unfilled:
        lines.append("unfilled placeholders: " + ", ".join(unfilled))
    ok = ok_n == tested and not unfilled and not wrong_out and tested > 0 and not others and first_bad is None and not form_missing and not stale and not misplaced and one_char <= 50 and tpl_missing is None and not long_p
    if ok:
        # the worker is started with this one line, never with the prompt re-typed: a re-typed prompt is a copy this test never read
        lens_, part_ = pair.split("/")
        # a typo in the one path heals without a re-run: the fallback names the file without the cache directory's spelling
        # read, then check, then follow: with the check after "follow it", four of five test workers followed a file naming another partition
        lines.append(f"send: You are the {lens_} worker for partition {part_}. Your prompt is {path.resolve()}. Read it in full before anything else; if that path cannot be read, read prompts/{lens_}-{part_}.md in the directory of {target} whose name begins .llm-sast instead. Before you follow it, check its first line: it must name the {lens_} worker and partition {part_}. If neither path can be read, or the first line names another lens or partition, stop: write nothing and reply \"prompt file not found\". Otherwise follow the file; it is your whole task.")
    return ok, lines


def copy_commit(copy_text: str) -> tuple[str | None, str]:
    """The commit a pre-write copy was last written at: its header's `last-scanned-sha:` row, above the ledger heading as
    item (36) reads it — or, for a copy holding ledger rows under no such row (a write that dropped the memory's header),
    the sha of its newest `run <sha> <date>:` line under Coverage / depth notes, the one the run that wrote it added: the
    latest date, and of lines sharing it the last — writers append, though one put its line first. Returns the sha and
    how it was read: "" (the row), "run line", or "unreadable" (rows, no row, no run line that parses)."""
    text_ = copy_text or ""
    head_ = text_.split("## Confirmed findings ledger", 1)[0]
    m_ = re.search(r"^[ \t]*last-scanned-sha:[ \t]*(\S+)", head_, re.M)
    if m_:
        return m_.group(1), ""
    sec_ = text_.split("## Confirmed findings ledger", 1)[1].split("\n## ", 1)[0] if "## Confirmed findings ledger" in text_ else ""
    if any(LEDGER_RX.match(l.strip()) for l in sec_.splitlines()):
        cov_ = text_.split("## Coverage / depth notes", 1)[1].split("\n## ", 1)[0] if "## Coverage / depth notes" in text_ else ""
        runs_ = [l.strip() for l in cov_.splitlines() if l.strip().startswith("run ")]
        dated_ = [(m_.group(2), i_, m_.group(1)) for i_, m_ in enumerate(re.match(r"run (\S+) (\d{4}-\d{2}-\d{2})[^:\s]*:", r_) for r_ in runs_) if m_]
        return (max(dated_)[2], "run line") if dated_ else (None, "unreadable")
    return None, ""


def header_sha(report_text: str) -> str | None:
    """A report's `Base SHA:` value as its header states it — the first such line before its first `## ` heading."""
    m = re.search(r"^[^\w\n]*Base SHA:[^\w\n]*([0-9A-Za-z]+)", report_text.split("\n## ", 1)[0], re.M)
    return m.group(1) if m else None


def same_commit(copy_sha: str | None, base_sha: str | None) -> bool:
    """An unchanged commit: the copy's commit is this run's base-sha — never `unknown`, whose entries are all stale."""
    return bool(copy_sha) and bool(base_sha) and copy_sha == base_sha and base_sha.lower() != "unknown"


def prompt_lines(path: Path, skills: Path, cache: Path | None = None) -> tuple[bool, list[str]]:
    """A writer's or a repair's prompt file: the Writer self-check paragraph verbatim, `<skills root>` filled — and, at an
    unchanged commit whose pre-write copy holds ledger rows to carry, the Same-commit carry paragraph verbatim."""
    spans = template_spans(skills)
    text = read(path)
    if not text:
        return False, [f"prompt {path.name}: absent or empty"]
    flat = _flat(text)
    missing = []
    if "writer self-check" not in spans or not _span_rx(spans["writer self-check"], skills).search(flat):
        # name the first sentence of the paragraph the prompt does not hold, so the file is corrected where it differs
        first_off = None
        for sent in re.split(r"(?<=[.;:])\s+(?=[A-Z`(*])", _flat(spans.get("writer self-check", ""))):
            if len(sent) > 20 and not _span_rx(sent, skills).search(flat):
                first_off = sent
                break
        where_ = ""
        if first_off:
            words_ = first_off.split()
            lo_, hi_ = 0, len(words_)  # the longest opening of that sentence the prompt holds, then the words after it
            while lo_ < hi_:
                mid_ = (lo_ + hi_ + 1) // 2
                if _span_rx(" ".join(words_[:mid_]), skills).search(flat):
                    lo_ = mid_
                else:
                    hi_ = mid_ - 1
            where_ = f" (it differs at '… {' '.join(words_[max(0, lo_ - 4):lo_])} >> {' '.join(words_[lo_:lo_ + 8])} …')"
        missing.append("the Writer self-check paragraph verbatim" + where_)
    else:
        # the paragraph sends the writer to this skill's STEP 3 by path: a path that does not open sends it nowhere
        want_v = frontmatter_version(skills / "llm-sast-scanner-full-scan-loop")
        rest = flat
        home_ = str(Path.home())
        spellings = []
        for r_ in dict.fromkeys((skills.absolute(), skills.resolve())):  # a root the run names, spaces and all, is read whole
            if (r_ / "llm-sast-scanner-full-scan-loop" / "SKILL.md").is_file():
                s_ = str(r_)
                spellings.append(s_)
                if s_.startswith(home_ + "/"):
                    spellings += [h_ + s_[len(home_):] for h_ in ("~", "$HOME", "${HOME}")]
        for s_ in dict.fromkeys(spellings):
            rest = re.sub(r"(?<![\w./~$:-])" + re.escape(_flat(s_) + "/llm-sast-scanner-full-scan-loop/SKILL.md"), " ", rest)
        # every other path to this skill's SKILL.md: from its `/`, `~` or `$HOME`, never the punctuation before it
        # every other absolute path to this skill's SKILL.md — from a `/`, `~` or `$HOME` that opens a token, never the punctuation
        # before it; a relative path or a URL names no file this check can open, and is left alone
        for r_ in dict.fromkeys((skills.absolute(), skills.resolve())):
            if (r_ / "llm-sast-scanner" / "SKILL.md").is_file():
                rest = re.sub(r"(?<![\w./~$-])" + re.escape(_flat(str(r_)) + "/llm-sast-scanner/SKILL.md"), " ", rest)
        for m_b in dict.fromkeys(re.findall(r"(?<![\w./~$:-])((?:~|\$\{HOME\}|\$HOME(?![A-Za-z0-9_])|/)[^\s()\[\]<>\"'`,;]*?/llm-sast-scanner/SKILL\.md)", rest)):
            if not Path(os.path.expanduser(re.sub(r"^(?:\$\{HOME\}|\$HOME)", "~", m_b))).is_file():
                missing.append(f"a base-skill path that opens — `{m_b}` does not")
        for m_sk in dict.fromkeys(re.findall(r"(?<![\w./~$:-])((?:~|\$\{HOME\}|\$HOME(?![A-Za-z0-9_])|/)[^\s()\[\]<>\"'`,;]*?/llm-sast-scanner-full-scan-loop/SKILL\.md)", rest)):
            p_sk = Path(os.path.expanduser(re.sub(r"^(?:\$\{HOME\}|\$HOME)", "~", m_sk)))
            if not p_sk.is_file():
                missing.append(f"a skill path that opens — `{m_sk}` does not; the Writer self-check paragraph's `<skills root>` is the directory that holds this skill's directory")
            elif want_v and frontmatter_version(p_sk.parent) != want_v:
                missing.append(f"this skill's version at `{m_sk}` — it holds v{frontmatter_version(p_sk.parent) or '?'}, the skill checked is v{want_v}")
    if cache is not None:
        plan_ = read(cache / "scan-plan.md")
        st = re.search(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", row(plan_, "started:") or "")
        copy_ = read(cache / f"project-memory.md.pre-write-{st.group(0)}") if st else ""
        copy_sha, _ = copy_commit(copy_)
        base_ = plan_base_sha(plan_)
        sec_ = copy_.split("## Confirmed findings ledger", 1)[1].split("\n## ", 1)[0] if "## Confirmed findings ledger" in copy_ else ""
        has_rows = any(LEDGER_RX.match(l.strip()) for l in sec_.splitlines())
        if same_commit(copy_sha, base_) and has_rows:
            if "same-commit carry" not in spans or not _span_rx(spans["same-commit carry"], skills).search(flat):
                missing.append("the Same-commit carry paragraph verbatim (unchanged commit, ledger rows to carry)")
    if "<skills root>" in flat:
        missing.append("<skills root> filled in")
    long_w = long_lines(text)
    if long_w:
        missing.append(f"lines a file reader keeps whole — line {long_w[0][0]} is {long_w[0][1]} bytes" + (f" ({len(long_w)} lines over {LINE_LIMIT})" if len(long_w) > 1 else "")
                       + f": a reader cuts a line over {LINE_LIMIT} bytes (UTF-8, an em dash three), so write the prompt with its paragraphs' line breaks")
    if cache is not None and skills is not None:
        plan_g = read(cache / "scan-plan.md")
        roster_g = {pr for body in re.findall(r"^wave roster \d+:\s*(.*)$", plan_g, re.M) for pr in re.findall(r"[a-z-]+/p\d+", body)}
        files_g = {q.name: (f"{m_.group(1)}/{m_.group(2)}" if m_ else None) for q in cache.glob("deep-*-results.md") for m_ in [re.match(r"^deep-(.+)-(p\d+)-results\.md$", q.name)]}
        strays_g = sorted(n_ for n_, pr in files_g.items() if pr is None or (roster_g and pr not in roster_g))
        if strays_g:
            missing.append("a cache holding only this run's worker files — move " + ", ".join(strays_g) + " (on no roster of this run) to .llm-sast-scanner-cache/previous-run-<started>/: the writer reads every `deep-*-results.md` in the cache as a worker's")
        pairs_g = sorted(pr for n_, pr in files_g.items() if pr is not None and (not roster_g or pr in roster_g))
        if pairs_g:
            head_rx = re.compile(r"^gate: ([a-z-]+/p\d+) — ")
            rec = {}
            for l in plan_g.splitlines():
                m_g = head_rx.match(l)
                if m_g:
                    rec[m_g.group(1)] = l.strip()
            _, now_g = gate_lines(cache.parent, cache, plan_g, skills, "all")
            now = {head_rx.match(l).group(1): l.strip() for l in now_g if head_rx.match(l)}
            counts_g = Counter(m_g.group(1) for m_g in (head_rx.match(l) for l in plan_g.splitlines()) if m_g)
            absent_g = [p_ for p_ in pairs_g if p_ not in rec]
            differ_g = [p_ for p_ in pairs_g if p_ in rec and p_ in now and gate_line_passes(rec[p_]) != gate_line_passes(gate_line_as(rec[p_], now[p_]))]
            nr_g = set(re.findall(r"^worker not run: ([a-z-]+/p\d+)", plan_g, re.M))
            stale_g = [(p_, gate_line_diff(rec[p_], now[p_])) for p_ in pairs_g if p_ in rec and p_ in now and p_ not in differ_g and p_ not in nr_g]
            stale_g = [(p_, d_) for p_, d_ in stale_g if d_]
            # a file changed after the writer's prompt was written is the writer's or a repair's write: its line is never
            # rewritten in place before a repair, which would leave item (29) nothing to name
            wp_g = (cache / "writer-prompt.md").stat().st_mtime if cache and (cache / "writer-prompt.md").is_file() and path.name != "writer-prompt.md" else None
            def _mg(p_: str) -> float:
                try:
                    return (cache / f"deep-{p_.split('/')[0]}-{p_.split('/')[1]}-results.md").stat().st_mtime
                except OSError:
                    return 0.0
            stale_g = [(p_, d_) for p_, d_ in stale_g if wp_g is None or _mg(p_) <= wp_g + 1]
            dup_g = sorted(p_ for p_, n_ in counts_g.items() if n_ > 1)
            all_gate = [l for l in plan_g.splitlines() if l.startswith("gate:")]
            extra_g = sorted(p_ for p_ in counts_g if p_ not in pairs_g)
            nf_g = sum(1 for l in all_gate if l.startswith("gate: no worker file for"))
            err_g = sum(1 for l in all_gate if not head_rx.match(l)) - nf_g
            not_run_g = set(re.findall(r"^worker not run: ([a-z-]+/p\d+)", plan_g, re.M))
            failing_g = [p_ for p_ in pairs_g if p_ in rec and p_ not in differ_g and gate_line_passes(rec[p_]) is False and p_ not in not_run_g]
            if absent_g:
                missing.append(f"a recorded gate line for {len(absent_g)} of {len(pairs_g)} worker files — " + (
                    "append the output of `python3 <this skill's directory>/recheck.py --gate all` to .llm-sast-scanner-cache/scan-plan.md" if len(absent_g) == len(pairs_g) and not counts_g
                    else "append to .llm-sast-scanner-cache/scan-plan.md the line `--gate <lens>/p<n>` prints for: " + ", ".join(absent_g)))
            if differ_g:
                missing.append("a recorded gate line reading the verdict the file reads now — rewrite in place in .llm-sast-scanner-cache/scan-plan.md, with the line `--gate <lens>/p<n>` prints, the line of: " + ", ".join(differ_g))
            if stale_g:
                missing.append("a recorded gate line reading every field the file reads now — the file changed after it was gated, after its sentinel: rewrite in place in .llm-sast-scanner-cache/scan-plan.md, with the line `--gate <lens>/p<n>` prints, the line of: "
                               + "; ".join(f"{p_} ({', '.join(d_)})" for p_, d_ in stale_g))
            if dup_g:
                missing.append("one `gate:` line per worker file — the writer stops on a count that differs; in .llm-sast-scanner-cache/scan-plan.md keep only the last line of: " + ", ".join(dup_g))
            if len(all_gate) != len(pairs_g) and (extra_g or err_g or nf_g):
                missing.append(f"as many `gate:` lines as worker files ({len(all_gate)} lines, {len(pairs_g)} files) — the writer stops on a count that differs; remove from .llm-sast-scanner-cache/scan-plan.md "
                               + "; ".join(x for x in (("the lines of pairs with no worker file: " + ", ".join(extra_g)) if extra_g else "",
                                                       f"{nf_g} `gate: no worker file for` line(s) — a pair with no worker file has no gate line" if nf_g else "",
                                                       f"{err_g} `gate: error` line(s), after running the gate again with `--skills <skills root>`" if err_g else "") if x))
            if failing_g:
                missing.append("a passed gate for " + ", ".join(failing_g) + " — STEP 3 does not start while a worker file fails its gate and its pair is not recorded `worker not run:`")
            # STEP 2's last reading of the worker files against each other, from the version that added it: its
            # `overlaps:` line, copied as printed, counts what `--overlaps` counts in the files now
            v_o = re.search(r"v(\d+)\.(\d+)\.(\d+)", corrected_str(plan_g, "wrapper:") or "")
            late_o = wp_g is not None and any(_mg(p_) > wp_g + 1 for p_ in pairs_g)  # a repair's prompt over files changed since the writer's: item (29)'s
            if v_o and tuple(int(x_) for x_ in v_o.groups()) >= (2, 26, 12) and not late_o:
                stems_o = {q.stem for q in (skills / "llm-sast-scanner" / "references").glob("*.md")}
                roots_o = tuple(sorted({r_ for r_ in ((corrected_str(plan_g, "target:") or "").rstrip("/"), str(cache.parent)) if r_}, key=len, reverse=True))
                recs_o = {q.name: worker_records(read(q), stems_o, roots_o) for q in overlap_files(cache, plan_g)}
                n_o = len(own_sink_aliases(recs_o, entry_list(plan_g), True))
                got_o = re.findall(r"^overlaps: (\d+)\b", plan_g, re.M)
                if len(got_o) > 1:
                    missing.append(f"a single `overlaps:` line — the plan holds {len(got_o)}: keep one, rewritten in place with the last line `--overlaps` prints now")
                elif not got_o:
                    missing.append(f"STEP 2's `--overlaps` reading — run `python3 <this skill's directory>/recheck.py --overlaps` from the target, judge each pair it lists as STEP 2 says, then copy its last line as printed, on a line of its own, into .llm-sast-scanner-cache/scan-plan.md (it counts {n_o} now)")
                elif int(got_o[-1]) != n_o:
                    missing.append(f"an `overlaps:` line reading the worker files now — the plan's last reads {got_o[-1]}, `--overlaps` counts {n_o}: run it again and rewrite that line in place")
    if cache is not None:
        st2 = re.search(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", row(read(cache / "scan-plan.md"), "started:") or "")
        if st2:
            import datetime
            if path.stat().st_mtime < datetime.datetime.strptime(st2.group(0), "%Y-%m-%d_%H-%M-%S").timestamp():
                missing.append(f"a file written by this run (it is older than started: {st2.group(0)})")
    out_ = [f"prompt {path.name}: " + ("ok" if not missing else "missing " + "; ".join(missing))]
    if not missing:
        # the writer or repair is started with this one line, as the workers are, never with its prompt re-typed
        tgt_ = cache.parent if cache is not None else path.resolve().parent.parent
        out_.append(f"send: Your prompt is {path.resolve()}. Read it in full before anything else; if that path cannot be read, read {path.name} in the directory of {tgt_} whose name begins .llm-sast instead. If neither path can be read, stop: write nothing and reply \"prompt file not found\". Otherwise follow the file; it is your whole task.")
    return not missing, out_


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default=".", help="target directory (default: cwd)")
    ap.add_argument("--report", help="report file name (default: the scan plan's last `report:` row)")
    ap.add_argument("--previous", help="newest earlier report (default: last file of `earlier-reports:`)")
    ap.add_argument("--skills", help="skills directory holding the three skills")
    ap.add_argument("--shipped", help="path of the skill's own recheck.py (default: <skills>/llm-sast-scanner-full-scan-loop/recheck.py)")
    ap.add_argument("--gate", nargs="?", const="all", help="STEP 2: print the `gate:` line of every worker file (or of one `<lens>/p<n>`) as the gate rule computes it, and exit (0 all pass, 1 any fails)")
    ap.add_argument("--contracts", action="store_true", help="STEP 1: print the `contracts checked: <k>/<n>` line over every lens contract, and exit (0 all pass, 1 any fails)")
    ap.add_argument("--roster", type=int, metavar="K", help="STEP 2: print wave K's pairs from its roster line — the batch to send — and the first attempts recorded in it")
    ap.add_argument("--prompt", metavar="FILE", help="STEP 3: check a writer's or a repair's prompt file for the Writer self-check paragraph, print `ok` and the `send:` line it is started with, and exit (0 ok, 1 not)")
    ap.add_argument("--paths", nargs="+", metavar=("FILE", "PAIR"), help="STEP 2: test every path a worker prompt file names (the output path against `<lens>/p<n>`), print `paths <k>/<m>` and, when all pass, the `send:` line the worker is started with, and exit (0 all exist, 1 not)")
    ap.add_argument("--record", action="store_true", help="STEP 3, the session only: append this set to the scan plan — the recorded set; a run without it reads and records nothing")
    ap.add_argument("--checks", action="store_true", help="STEP 1: print the `checks:` line the scan plan must carry, from its entry list and the partition manifests, and exit (0 pass, 1 failed)")
    ap.add_argument("--overlaps", action="store_true", help="STEP 2: print one `overlap:` line for each sink a record's `Also at:` line names that another worker file's record holds as its own `File:` sink at one class and entry point, then `overlaps: <n>` and the grouping workers, and exit (0 none, 1 any — a list to read, not a failure — 2 no worker files or no skills directory)")
    ap.add_argument("--duplicates", action="store_true", help="STEP 3: print every pair of table rows item (48) asks the writer to judge — kind, worker records, VULN ids, worker severities, classes, sinks, whether each key is a ledger row of the pre-write copy, entry points and the answer written — and exit")
    ap.add_argument("--needs-context", action="store_true", help="STEP 3: print every worker-file line outside a finding record that names a NEEDS CONTEXT judgement — `<lens>/p<n>:<line>`, its text, and the report's `needs context:` answer if it has one — the lines item (49) asks the writer to answer, and exit 0 (2 with no worker files)")
    ap.add_argument("--ledger-start", action="store_true", help="STEP 1: print the `ledger rows at start:` row, counted in the pre-write copy the plan's `started:` row names, and exit (0 counted; 2 no copy, a plan past STEP 1, or a copy whose ledger rows differ in number from the memory's)")
    args = ap.parse_args()
    other_mode = next((f"--{n}" for n in ("contracts", "prompt", "paths", "roster", "gate", "ledger-start", "checks", "duplicates", "needs-context", "overlaps")
                       if getattr(args, n.replace("-", "_"), None) is not None and getattr(args, n.replace("-", "_"), None) is not False), None)  # `--roster 0` is a mode too
    if args.record and other_mode:
        sys.stderr.write(f"recorded: nothing — --record records a plain recheck set, and this run is {other_mode}\n")
    RECORD["on"] = bool(args.record) and not other_mode
    RECORD["plan"] = Path(args.target).resolve() / ".llm-sast-scanner-cache" / "scan-plan.md"
    if args.contracts or args.prompt:
        tgt = Path(args.target).resolve()
        skills_c = find_skills(args.skills, args.shipped)
        if not skills_c:
            print(f"{'contracts' if args.contracts else 'prompt'}: error — skills directory not found (pass --skills <dir>); nothing checked")
            return 2
        if args.contracts:
            ok_c, lines_c = contract_lines(tgt / ".llm-sast-scanner-cache", read(tgt / ".llm-sast-scanner-cache" / "scan-plan.md"), skills_c)
        else:
            pp = Path(args.prompt)
            ok_c, lines_c = prompt_lines(pp if pp.is_absolute() else tgt / pp, skills_c, tgt / ".llm-sast-scanner-cache")
        print("\n".join(lines_c))
        return 0 if ok_c else 1
    if args.needs_context:
        # the writer's worklist for item (49): every NEEDS CONTEXT line of the worker files, with its answer so far
        tgt = Path(args.target).resolve()
        wf_ = sorted((tgt / ".llm-sast-scanner-cache").glob("deep-*-results.md"))
        if not wf_:
            print("needs-context: error — no worker files (`.llm-sast-scanner-cache/deep-*-results.md`) under the target; nothing listed")
            return 2
        rn_ = args.report or (re.findall(r"^report:\s*(sast_report-\S+\.md)", read(tgt / ".llm-sast-scanner-cache" / "scan-plan.md"), re.M) or [None])[-1]
        try:
            rp_ = tgt / rn_ if rn_ else None
            ok_r = bool(rp_ and rp_.is_file() and os.access(rp_, os.R_OK))
        except (OSError, ValueError):
            ok_r = False
        ans_ = nc_answers(nc_section(read(rp_))) if ok_r else {}
        nl_ = nc_lines(wf_)
        for pair_, n_, l_ in nl_:
            got_ = ans_.get((pair_.lower(), n_), [])
            mk_ = NC_RX.search(l_)
            at_ = mk_.start() if mk_ else 0  # an `[UNVERIFIABLE]` heading may hold no marker words
            show_ = l_[:300] + (" …" if len(l_) > 300 else "") if at_ < 200 else f"{l_[:120]} … {l_[at_ - 120:at_ + 160]}{' …' if len(l_) > at_ + 160 else ''}"
            print(f"needs context line: {pair_}:{n_} — {show_} | answer: "
                  + (got_[0][:80] if len(got_) == 1 else ("none" if not got_ else f"{len(got_)} lines")))
        note_ = "" if ok_r else ((f" | report {rn_[:80]} absent or unreadable" if rn_ else " | no `report:` row in the plan") + ": every answer reads none")
        print(f"needs context lines: {len(nl_)} to answer{note_}")
        return 0
    if args.paths:
        tgt = Path(args.target).resolve()
        if len(args.paths) != 2 or not re.fullmatch(r"[a-z][a-z-]*/p\d+", args.paths[1]):  # the pair names the output file tested
            print(f"paths: error — call it as `--paths FILE <lens>/p<n>` (got {' '.join(args.paths[1:])!r}); nothing checked")
            return 2
        pf = Path(args.paths[0])
        ok_p, lines_p = paths_lines(pf if pf.is_absolute() else tgt / pf, tgt, args.paths[1] if len(args.paths) > 1 else None, find_skills(args.skills, args.shipped))
        print("\n".join(lines_p))
        return 0 if ok_p else 1
    if args.roster is not None:
        tgt = Path(args.target).resolve()
        ok_r, lines_r = roster_lines(read(tgt / ".llm-sast-scanner-cache" / "scan-plan.md"), args.roster, tgt / ".llm-sast-scanner-cache")
        print("\n".join(lines_r))
        return 0 if ok_r else 1
    if args.gate:
        tgt = Path(args.target).resolve()
        skills_g = find_skills(args.skills, args.shipped)
        if not skills_g:
            # without the frontmatters and the reference files every header and every reference would read as a fail
            print("gate: error — skills directory not found (pass --skills <dir>); no gate line computed")
            return 2
        ok_g, lines_g = gate_lines(tgt, tgt / ".llm-sast-scanner-cache", read(tgt / ".llm-sast-scanner-cache" / "scan-plan.md"), skills_g, args.gate)
        print("\n".join(lines_g) if lines_g else f"gate: no worker file for {args.gate}")
        # the lines `long lines <n>` counts, named on stderr so the line recorded from stdout stays the gate line: a
        # character count (`wc -L`) misses the lines of 1,982 to 2,000 characters an em dash takes over the limit
        for l_g in lines_g:
            m_g = re.match(r"^gate: ([a-z-]+)/(p\d+) — .* \| long lines (\d+)(?: \| groups (\d+)/(\d+))?$", l_g)
            if m_g and int(m_g.group(3)) > 0:
                f_g = tgt / ".llm-sast-scanner-cache" / f"deep-{m_g.group(1)}-{m_g.group(2)}-results.md"
                ll_g = long_text_lines(read(f_g))
                print(f"long lines in {f_g.name}: " + ", ".join(f"line {n_} ({b_} bytes)" for n_, b_ in ll_g[:12])
                      + (f" … and {len(ll_g) - 12} more" if len(ll_g) > 12 else ""), file=sys.stderr)
            if m_g and m_g.group(4) is not None and int(m_g.group(4)) < int(m_g.group(5)):
                # the `Also at:` sinks `groups` counts, named on stderr as the long lines are
                f_g = tgt / ".llm-sast-scanner-cache" / f"deep-{m_g.group(1)}-{m_g.group(2)}-results.md"
                plan_g = read(tgt / ".llm-sast-scanner-cache" / "scan-plan.md")
                roots_g = tuple(sorted({r_ for r_ in ((corrected_str(plan_g, "target:") or "").rstrip("/"), str(tgt)) if r_}, key=len, reverse=True))
                stems_g = {q.stem for q in (skills_g / "llm-sast-scanner" / "references").glob("*.md")}
                recs_ = worker_records(read(f_g), stems_g, roots_g)
                al_ = own_sink_aliases({f_g.name: recs_}, entry_list(plan_g), False)
                by_a_: dict = {}
                for _, a_, _, o_, s_ in al_:
                    by_a_.setdefault((a_["id"], a_["line"]), []).append(f"{o_['id']}'s own sink {s_}")
                tail_g = (" — one class and entry point: the line is its own finding (a fix of its own: keep its record, take the line"
                          " off the group's `Also at:` line) or that group's (one missing check closes it: no record of its own)")
                # each grouping record once, its sinks after it, cut at a sink so the line stays under the reader's limit
                head_g, parts_g, shown_, total_ = f"groups in {f_g.name}: ", [], 0, sum(len(v_) for v_ in by_a_.values())
                fits_ = lambda ps_: len((head_g + "; ".join(ps_) + f" … and {total_} more" + tail_g).encode("utf-8")) <= LINE_LIMIT - 20
                for (aid_, aln_), own_ in by_a_.items():
                    lead_, took_ = f"{aid_} (line {aln_}) names on its `Also at:` line ", []
                    for x_ in own_:
                        if not fits_(parts_g + [lead_ + ", ".join(took_ + [x_])]):
                            break
                        took_.append(x_)
                    if took_:
                        parts_g.append(lead_ + ", ".join(took_))
                        shown_ += len(took_)
                    if len(took_) < len(own_):
                        break
                print(head_g + "; ".join(parts_g) + (f" … and {total_ - shown_} more" if total_ > shown_ else "") + tail_g, file=sys.stderr)
        return 0 if ok_g and lines_g else 1
    if args.overlaps:
        # STEP 2's last reading: a record whose `Also at:` line names another worker's record's own `File:` sink at one
        # class and entry point — the gate's `groups` field reads one file; this reads the files against each other
        tgt = Path(args.target).resolve()
        cache_o = tgt / ".llm-sast-scanner-cache"
        plan_o = read(cache_o / "scan-plan.md")
        wf_o = overlap_files(cache_o, plan_o)
        skills_o = find_skills(args.skills, args.shipped)
        if not wf_o or not skills_o:
            print("overlaps: error — " + ("no worker files (`.llm-sast-scanner-cache/deep-*-results.md`) under the target" if not wf_o else "skills directory not found (pass --skills <dir>)") + "; nothing listed")
            return 2
        roots_o = tuple(sorted({r_ for r_ in ((corrected_str(plan_o, "target:") or "").rstrip("/"), str(tgt)) if r_}, key=len, reverse=True))
        stems_o = {q.stem for q in (skills_o / "llm-sast-scanner" / "references").glob("*.md")}
        pair_o = lambda q_: re.sub(r"^deep-(.+)-(p\d+)-results\.md$", r"\1/\2", q_)
        recs_o = {q.name: worker_records(read(q), stems_o, roots_o) for q in wf_o}
        al_o = own_sink_aliases(recs_o, entry_list(plan_o), True)
        for fa_, a_, fb_, b_, s_ in al_o:
            print(f"overlap: {pair_o(fa_)}/{a_['id']} ({a_['sink']}) names {pair_o(fb_)}/{b_['id']}'s own sink {s_} on its `Also at:` line, at one class ({a_['cls']}) and entry point")
        grp_o = sorted({pair_o(fa_) for fa_, _, _, _, _ in al_o})
        print(f"overlaps: {len(al_o)}" + (f" | grouping workers {len(grp_o)} — {', '.join(grp_o)}" if al_o else ""))
        return 1 if al_o else 0
    if args.ledger_start:
        # the row STEP 1 copies: counted, never composed — one session counted the previous run's copy and wrote its 363
        # over a ledger of 448
        cache_l = Path(args.target).resolve() / ".llm-sast-scanner-cache"
        plan_l = read(cache_l / "scan-plan.md")
        row_l = row(plan_l, "started:")
        st_l = re.search(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", row_l or "")
        st_l = st_l.group(0) if st_l else ((row_l or "").split() or [None])[0]  # the copy item (16) reads: the stamp, else the row's first word
        cp_l = cache_l / f"project-memory.md.pre-write-{st_l}" if st_l else None
        # a plan holding a `workers dispatched:` line is past STEP 1 — this run's at STEP 3, or the previous run's still in
        # place, whose copy is that run's ledger: counting it is the miscount this command exists to prevent
        if re.search(r"^workers dispatched:", plan_l, re.M):
            print("ledger-start: error — the plan holds a `workers dispatched:` line, so it is past STEP 1: this run's plan takes the count recheck item (16) names, appended to the row as ` → corrected <n> at <date +%Y-%m-%d_%H-%M-%S>`; the previous run's plan, still in place, is copied to `previous-run-<started>/` — write this run's scan-plan.md with its `started:` row, copy project-memory.md to `project-memory.md.pre-write-<started>`, then run this again")
            return 2
        if not cp_l or not cp_l.exists():  # as item (16) reads it: a copy that exists but cannot be read counts 0
            print("ledger-start: error — no `project-memory.md.pre-write-<started>` for the plan's `started:` row: write the plan's `started:` row, copy project-memory.md to that name (an empty file when it is absent), then run this again")
            return 2
        def ledger_n(text_: str) -> int:
            sec_ = text_.split("## Confirmed findings ledger", 1)
            return sum(1 for l_ in (sec_[1].split("\n## ", 1)[0] if len(sec_) > 1 else "").splitlines() if LEDGER_RX.match(l_.strip()))
        n_l = ledger_n(read(cp_l))
        # nothing before the dispatch adds a ledger row to project-memory.md (a first run's template holds none), so at
        # STEP 1 the copy holds the memory's ledger: one that does not is an earlier run's, its plan still in place, or was
        # made before a write it does not hold
        if ledger_n(read(cache_l / "project-memory.md")) != n_l:
            print("ledger-start: error — the copy the plan's `started:` row names holds a different number of ledger rows from project-memory.md now: the plan is an earlier run's, still in place, or the memory was written after the copy — write this run's scan-plan.md with its `started:` row, copy project-memory.md to `project-memory.md.pre-write-<started>`, then run this again")
            return 2
        print(f"ledger rows at start: {n_l}")
        return 0
    if args.checks:
        tgt = Path(args.target).resolve()
        ok_c, parts_c, fails_c = partition_checks(read(tgt / ".llm-sast-scanner-cache" / "scan-plan.md"), tgt / ".llm-sast-scanner-cache")
        if not parts_c:
            print("checks: failed — no entry list or partition manifests to check")
            return 1
        print(f"checks: pass — {'; '.join(parts_c)}" if ok_c else f"checks: failed — {'; '.join(fails_c)} | {'; '.join(parts_c)}")
        # a line share outside the band with no file above it by itself is left to the split and the moves, which only the
        # session can run (the checker never reads units): say how, so it is not dispatched on untried; the plan carries the
        # `checks:` line alone, and once no split and no move remains the line stands as printed
        line_f = [f_ for f_ in fails_c if "of lines (outside 15% of one third)" in f_]
        open_l = [f_.split(" holds ")[0] for f_ in line_f if "(one file: " not in f_]
        # one file above 100% - 2 x (one third - 15%) of the lines by itself leaves the other two no room inside the band
        crowded = any(100.0 * int(m_.group(1)) / max(int(m_.group(2)), 1) > 100 - 2 * (100 / 3 * 0.85)
                      for f_ in line_f for m_ in [re.search(r"\(one file: .+ holds (\d+) of (\d+) lines\)", f_)] if m_)
        if open_l and not crowded:
            print(f"remedy: not final — {', '.join(open_l)} outside the line band with no `(one file: …)` on its failure: split the "
                  "largest unit by lines one level deeper while it is not a single file, then move units one at a time — the "
                  "partition with the most lines that has a movable unit gives the partition with the fewest the smallest "
                  "movable unit whose move puts both inside the band, else its smallest movable unit, a unit being movable "
                  "when it has more than zero lines, is smaller than the difference between the two partitions' lines and "
                  "puts the receiving partition above neither 40% cap (source lines, entry points) — each moved unit's entry "
                  "points with it (their list lines' partition column rewritten); rewrite the manifests and the unit lines, "
                  "run --checks again, and copy only its `checks:` line into the plan; once no split and no move remains, "
                  "the line stands as printed")
        return 0 if ok_c else 1

    target = Path(args.target).resolve()
    global TARGET_PREFIX
    TARGET_PREFIX = str(target) + "/"
    cache = target / ".llm-sast-scanner-cache"
    plan = read(cache / "scan-plan.md")
    skills = find_skills(args.skills, args.shipped)
    if not skills:
        # without the frontmatters and the reference files, items (0), (9) and (17) would read as mismatches of artifacts that
        # are right, and a writer correcting by them would rewrite a correct header and correct classes
        raise RuntimeError(f"skills directory not found — run again with {'--record ' if RECORD['on'] else ''}--skills <skills root>; no item was computed")
    shipped = Path(args.shipped).expanduser() if args.shipped else (skills / "llm-sast-scanner-full-scan-loop" / "recheck.py" if skills else None)

    # 0. script identity
    self_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    ship_sha = hashlib.sha256(shipped.read_bytes()).hexdigest() if shipped and shipped.exists() else None
    same = ship_sha == self_sha
    emit("script sha256", f"{self_sha[:12]} = shipped {ship_sha[:12] if ship_sha else 'absent'} | {'match' if same else 'MISMATCH'}", None, same)

    # artifacts
    report_name = args.report or (re.findall(r"^report:\s*(sast_report-\S+\.md)", plan, re.M) or [None])[-1]
    report_path = target / report_name if report_name else None
    report = read(report_path) if report_path else ""
    if not report:
        emit("report", f"absent ({report_name})", None, False)
    body_text = report.split("\n## Appendix", 1)[0]
    appendix = report[len(body_text):]
    blocks = [b for b in re.split(r"\n(?=(?:#+ )?\[(?i:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\] VULN-)", body_text) if RECORD_RX.match(b)]
    lines_memo: dict[str, int | None] = {}

    def target_lines(p_: str) -> int | None:
        """The line count of a file of the target, its newline characters and a last line without one; None for a path
        that names no file under the target — a name the run cannot see is not judged here."""
        q_ = rel(p_)
        if q_ not in lines_memo:
            n_ = None
            norm_ = os.path.normpath(q_) if q_ else ""
            if norm_ and not os.path.isabs(norm_) and norm_ != ".." and not norm_.startswith(".." + os.sep):
                f_ = target / norm_
                try:
                    if f_.is_file():
                        data_ = f_.read_bytes()
                        n_ = data_.count(b"\n") + (1 if data_ and not data_.endswith(b"\n") else 0)
                except OSError:
                    n_ = None
            lines_memo[q_] = n_
        return lines_memo[q_]

    def citations_of(block: str) -> tuple[int, list[tuple[str, int, str]]]:
        """A block's citations that name a file of the target: how many, and those past its end — (as cited, the file's
        lines, `sink` when the `File:` sink's first line is past it, `range` when only the sink's range ends past it, else
        `hop`)."""
        seen_, bad_ = 0, []
        for paths_, a_, b_, where_, spec_ in cited_locations(block):
            for p_ in paths_:
                n_ = target_lines(p_)
                if n_ is not None:
                    seen_ += 1
                    if max(a_, b_) > n_:
                        kind_ = ("sink" if a_ > n_ else "range") if where_ == "sink" else "hop"
                        bad_.append((f"{rel(p_)}:{spec_}", n_, kind_))
                    break
        return seen_, bad_
    dispatched_row = re.search(r"^workers dispatched:.*$", plan, re.M)
    block_id = {RECORD_RX.match(b).group(2).upper(): b for b in blocks}

    table_rows = []
    malformed = 0
    DISPOSITIONS = {"body", "merged", "withdrawn", "unverifiable", "promoted", "carried", "refuted"}
    for line in read(cache / "disposition-table.md").splitlines():
        s = line.strip()
        if "|" not in s or re.match(r"^\|?\s*(worker record|-{2,}|:?-+:?)\s*\|", s, re.I):
            continue
        cells = [strip_cell(c) for c in s.strip("|").split(" | ")]
        is_id = re.match(r"^[a-z-]+[/-]p\d+[/-]", cells[0], re.I) is not None
        if len(cells) == 7 and cells[4].lower() in DISPOSITIONS:
            table_rows.append(cells)
        elif is_id or (len(cells) >= 5 and any(c.lower() in DISPOSITIONS for c in cells)):
            malformed += 1
    body_rows = [c for c in table_rows if c[4].lower() == "body"]
    merged_rows = [c for c in table_rows if c[4].lower() == "merged"]
    carried_rows = [c for c in table_rows if c[4].lower() == "carried"]
    refuted_rows = [c for c in table_rows if c[4].lower() == "refuted"]  # a ledger key Step 6 withdrew on a worker's `ledger refuted:` line
    body_by_id = {c[6].upper(): c for c in body_rows}
    carried_by_id = {c[6].upper(): c for c in carried_rows}

    worker_files = sorted(p for p in cache.glob("deep-*-results.md"))
    worker_text = {p: read(p) for p in worker_files}
    file_records = sum(1 for t in worker_text.values() for l in t.splitlines() if ANY_RECORD_RX.match(l))
    malformed_headings = file_records - sum(1 for t in worker_text.values() for l in t.splitlines() if RECORD_RX.match(l))

    memory = read(cache / "project-memory.md")
    ledger_sec = memory.split("## Confirmed findings ledger", 1)[1].split("\n## ", 1)[0] if "## Confirmed findings ledger" in memory else ""
    ledger = [m for m in (LEDGER_RX.match(l.strip()) for l in ledger_sec.splitlines()) if m]
    ledger_keys = Counter(key_of(m.group(1), m.group(2)) for m in ledger)
    archive_sec = read(cache / "project-memory-archive.md")
    archived = sum(1 for l in archive_sec.splitlines() if LEDGER_RX.match(l.strip()))
    started_row = row(plan, "started:")
    _st = re.search(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", started_row or "")
    started = _st.group(0) if _st else ((started_row or "").split() or [None])[0]  # the stamp; a decoration after it is ignored
    copy_path = cache / f"project-memory.md.pre-write-{started}" if started else None
    copy_text = read(copy_path) if copy_path else ""
    copy_sec = copy_text.split("## Confirmed findings ledger", 1)[1].split("\n## ", 1)[0] if "## Confirmed findings ledger" in copy_text else ""
    copy_rows = [m for m in (LEDGER_RX.match(l.strip()) for l in copy_sec.splitlines()) if m]
    copy_keys = {key_of(m.group(1), m.group(2)) for m in copy_rows}
    stems = {p.stem for p in (skills / "llm-sast-scanner" / "references").glob("*.md")} if skills else set()
    copy_sinks_nonstem = {canon(m.group(2)) for m in copy_rows if m.group(1) not in stems}
    # STEP X's class correction, read back from the ledger: a non-stem copy row whose sink now holds exactly one stem-class
    # row is that row's key — its rekey is neither a key gone nor an open key of its own
    stem_at_sink: dict[str, set] = {}
    for m in ledger:
        if m.group(1) in stems:
            stem_at_sink.setdefault(canon(m.group(2)), set()).add(m.group(1))

    # where two stems share the sink, the row a class was rekeyed onto says so in its trail (`… was <old class>`)
    stem_trail: dict[tuple, str] = {}
    for m in ledger:
        if m.group(1) in stems:
            for old_ in re.findall(r"\bwas ([a-z][a-z0-9_]*)", m.group(3).split(" | ")[0]):
                stem_trail.setdefault((canon(m.group(2)), old_), m.group(1))

    # a row the archive holds — a refuted key's, moved this run — still says which stem its title class became; the
    # ledger's rows come first
    arch_rows = [m for m in (LEDGER_RX.match(l.strip()) for l in archive_sec.splitlines()) if m]
    refuted_sinks = {canon(rel(c[2])) for c in refuted_rows}
    # only at a sink of this run's `refuted` rows: no older archive row changes how a key reads
    arch_moved = [m for m in arch_rows if canon(m.group(2)) in refuted_sinks and m.group(3).split(" | ")[-1].strip(" |") == "superseded"]
    for m in arch_moved:
        if m.group(1) in stems:
            if canon(m.group(2)) not in stem_at_sink:
                stem_at_sink.setdefault(("archive", canon(m.group(2))), set()).add(m.group(1))
            for old_ in re.findall(r"\bwas ([a-z][a-z0-9_]*)", m.group(3).split(" | ")[0]):
                stem_trail.setdefault((canon(m.group(2)), old_), m.group(1))

    def corrected_key(cls: str, sink: str) -> str:
        if cls in stems or not stems:
            return key_of(cls, sink)
        # a row's ` was <class>` trail names the stem the class became — read first, since a row archived this run leaves
        # its sink's other stem the one owner the ledger shows
        via = stem_trail.get((canon(rel(sink)), cls))
        if via:
            return key_of(via, sink)
        owners = stem_at_sink.get(canon(rel(sink))) or stem_at_sink.get(("archive", canon(rel(sink))), set())
        if len(owners) == 1:
            return key_of(next(iter(owners)), sink)
        return key_of(cls, sink)

    # new keys (item 12), needed by item 6's row equation as well
    def is_new(key: str) -> bool:
        if key in copy_keys:
            return False
        sink = key.split("|", 1)[1]
        return sink not in copy_sinks_nonstem
    new_keys = sum(1 for k in ledger_keys if is_new(k))

    co_m = re.search(r"^close-out: table rows (\d+) \| file records (\d+) \| body rows (\d+) \| promoted (\d+) (?:\| carried (\d+) )?\| body blocks (\d+) \| linked blocks (\d+) \| invalid cells (\d+)", appendix, re.M)
    closeout = [int(co_m.group(i)) for i in (1, 2, 3, 4, 6, 7, 8)] if co_m else None  # n f b p k j c
    co_carried = int(co_m.group(5)) if co_m and co_m.group(5) is not None else 0
    carried_blocks = [b for b in blocks if re.search(r"^Carried: confirmed ", b, re.M)]

    # 1. body blocks / linked blocks / verdict cells verbatim
    linked = [bid for bid in block_id if bid in body_by_id or bid in carried_by_id]
    verdict_mismatch, verdict_pairs = 0, []
    for bid in linked:
        cell = (body_by_id.get(bid) or carried_by_id[bid])[5]
        if not cell or cell.lower() in ("n/a", "not run", "—", "-"):
            continue
        adv = adversarial(block_id[bid]) or ""
        if not adv.startswith(cell):
            verdict_mismatch += 1
            verdict_pairs.append(f"{bid} (cell `{cell[:40]}`, block `{adv[:40]}{'…' if len(adv) > 40 else ''}`)")
    rep = f"{closeout[4]}/{closeout[5]}" if closeout else "absent"
    blk_ids = Counter(RECORD_RX.match(b).group(2).upper() for b in blocks)
    blk_shown = {}
    for b in blocks:
        blk_shown.setdefault(RECORD_RX.match(b).group(2).upper(), RECORD_RX.match(b).group(2))  # as the report writes it
    dup_blk = [(i, n_) for i, n_ in blk_ids.items() if n_ > 1]
    sev_of = lambda i: [RECORD_RX.match(b).group(1) for b in blocks if RECORD_RX.match(b).group(2).upper() == i]  # as written
    promoted_ids = {c[6].upper() for c in table_rows if c[4].lower() == "promoted"}  # promoted rows render blocks too
    unlinked = [i for i in blk_ids if i not in body_by_id and i not in carried_by_id and i not in promoted_ids]
    ok = bool(closeout) and closeout[4] == len(blocks) and closeout[5] == len(linked) and verdict_mismatch == 0 and not dup_blk
    dup_txt = ["`" + blk_shown[i] + "` heads " + str(n_) + " blocks (" + ", ".join(sev_of(i)) + ")" for i, n_ in dup_blk]
    def rec_sev(i: str) -> str | None:
        """The severity the worker record behind body row `i` states in its heading."""
        r_ = body_by_id.get(i)
        m_r = re.match(r"^([a-z][a-z-]*)/(p\d+)/(\S+)$", re.sub(r"[`*]", "", r_[0]).strip()) if r_ else None
        txt_ = next((v for k_, v in worker_text.items() if m_r and Path(k_).name == f"deep-{m_r.group(1)}-{m_r.group(2)}-results.md"), "")
        h_ = re.search(r"(?m)^(?:#+ )?\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\] " + re.escape(m_r.group(3)) + r"(?![\w-])", txt_, re.I) if m_r else None
        return h_.group(1) if h_ else None
    dup_txt = [d_ + (f" — its worker record states `{rec_sev(i)}`" if rec_sev(i) else "") for d_, (i, _) in zip(dup_txt, dup_blk)]
    fix_b = [f"each body row renders one block: {', '.join(dup_txt[:4])}{' …' if len(dup_blk) > 4 else ''} — keep the one headed with the severity its worker record states, or the one Step 6 set where the row's verdict is DOWNGRADED, delete the other, then re-count the histogram and the close-out" if dup_blk else "",
             f"no `body` or `carried` row holds {', '.join('`' + blk_shown[i] + '`' for i in unlinked[:4])}{' …' if len(unlinked) > 4 else ''} — the block is rendered from a row, so its row is written or the block removed" if unlinked else "",
             f"the row's verdict cell holds Step 6's one verdict and its block's `Adversarial:` line opens with it word for word — the cell is written from Step 6's result, never re-adjudicated to match: {', '.join(verdict_pairs[:6])}{' …' if len(verdict_pairs) > 6 else ''}" if verdict_pairs else "",
             f"the close-out's `body blocks` and `linked blocks` read {len(blocks)} and {len(linked)}" if not (bool(closeout) and closeout[4] == len(blocks) and closeout[5] == len(linked)) and not dup_blk and not unlinked else ""]
    emit("body blocks", f"{len(blocks)} | linked blocks {len(linked)} | verdict cells not verbatim {verdict_mismatch}" + (f" | ids on more than one block {len(dup_blk)}" if dup_blk else ""), rep, ok, "; ".join(x for x in fix_b if x) or None)

    # 2. invalid cells
    dd_lines = [adversarial(b) for b in blocks if (adversarial(b) or "").startswith(("DOWNGRADED", "DISPUTED"))]
    void_lines = [adversarial(b) for b in blocks if (adversarial(b) or "").startswith("STANDING — previous downgrade voided")]
    invalid = sum(1 for a in dd_lines if not VERDICT_RX.search(a)) + sum(1 for a in void_lines if not VOIDED_RX.search(a))
    emit("invalid cells", f"{invalid} (of {len(dd_lines)} downgrade/dispute lines and {len(void_lines)} voided lines)", str(closeout[6]) if closeout else "absent", bool(closeout) and closeout[6] == invalid == 0)

    # 3. first-line tags
    tagged = sum(1 for b in blocks if re.search(r"\[(CONFIRMED|LIKELY)\]\s*$", b.splitlines()[0]))
    emit("first-line tags", f"{tagged}/{len(blocks)}", None, tagged == len(blocks))

    # 4. merges with a different entry point
    # an entry point is the scan-plan's `## Entry points` entry it names: workers cite one resolver at its decorator line and
    # at its method line (`R.ts:373 Mutation createX`, `R.ts:376 Mutation createX`) or by name alone (`createX`)
    ep_list_sec = plan.split("## Entry points", 1)[1].split("\n## ", 1)[0] if "## Entry points" in plan else ""
    IDENT = r"[A-Za-z_$][\w$]*"
    ep_entries = []  # (path, line, operation name — the name field's last identifier)
    for l in ep_list_sec.splitlines():
        f = l.split(" | ")
        m = re.match(r"^(.+):(\d+)", f[0].strip().lstrip("|").strip().strip("`")) if len(f) >= 3 and not l.startswith("#") else None
        if m:
            ids = re.findall(IDENT, f[2])
            ep_entries.append((m.group(1), int(m.group(2)), ids[-1] if ids else None))
    def ep_id(cell: str):
        c = re.sub(r"\s+", " ", cell.replace("`", "")).strip()
        for m in re.finditer(r"([\w./-]+\.\w+):(\d+)", c):
            cited, ln = m.group(1).lstrip("./"), int(m.group(2))
            paths = {e[0] for e in ep_entries if e[0] == cited or e[0].endswith("/" + cited)}
            if len(paths) != 1:
                continue  # a basename two list files share names neither
            near = [e for e in ep_entries if e[0] in paths and e[1] <= ln + 3]  # a decorator sits up to three lines above
            if near:
                # the entry on the cited line itself first: `manage.py:344` among entries at :344, :345 and :346 is :344
                e = next((x for x in near if x[1] == ln), None) or max(near, key=lambda e: e[1])
                return (e[0], e[1])
        words = set(re.findall(IDENT, re.sub(r"\S+:\d+(?:-\d+)?", " ", c)))
        named = {(e[0], e[1]) for e in ep_entries if e[2] in words}
        return next(iter(named)) if len(named) == 1 else c
    def ep_single(text: str):
        """The one list entry a worker record's `Entry point:` names, None when it names none or several — a record that
        lists seven entry points gives the cell nothing single to copy."""
        c = re.sub(r"\s+", " ", text.replace("`", "")).strip()
        found = set()
        for m in re.finditer(r"([\w./-]+\.\w+):(\d+)", c):
            cited, ln = m.group(1).lstrip("./"), int(m.group(2))
            paths = {e[0] for e in ep_entries if e[0] == cited or e[0].endswith("/" + cited)}
            near = [e for e in ep_entries if e[0] in paths and e[1] <= ln + 3] if len(paths) == 1 else []
            if near:
                e = next((x for x in near if x[1] == ln), None) or max(near, key=lambda e: e[1])
                found.add((e[0], e[1]))
        if not found:
            words = set(re.findall(IDENT, re.sub(r"\S+:\d+(?:-\d+)?", " ", c)))
            found = {(e[0], e[1]) for e in ep_entries if e[2] in words}
        return next(iter(found)) if len(found) == 1 else None
    def record_entry(row_id: str) -> str | None:
        """The `Entry point:` line of the worker record a table row id names (`<lens>/p<n>/<VULN id>`), None when unfound."""
        m_id = re.match(r"^([a-z][a-z-]*)/(p\d+)/(\S+)$", row_id.strip())
        if not m_id:
            return None
        txt = next((v for k_, v in worker_text.items() if Path(k_).name == f"deep-{m_id.group(1)}-{m_id.group(2)}-results.md"), "")
        inside = False
        for l in txt.splitlines():
            if re.match(r"^(?:#+ )?\**\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\]", l, re.I):
                inside = re.search(r"(?<![\w-])" + re.escape(m_id.group(3)) + r"(?![\w-])", l) is not None
            elif inside and re.match(r"^#{1,6} ", l):
                inside = False  # a heading that is no record's ends the record
            elif inside:
                # as workers write it: a list marker, bold around the label or the colon, any letter case
                e = re.match(r"^\s*(?:[-*+]\s+)?\**Entry points?\**\s*:\**\s*(.+)$", l, re.I)
                if e:
                    return e.group(1).strip()
        return None
    def record_parts(row_id: str):
        """The worker record a table row id names — its own heading, the id right after the severity tag — read to the next
        `#` or `##` heading as item (37) reads it: None when its file holds none, else (its `Flow:` line, the file's other
        lines naming its id, its `File:` sink as (path, line) or None, its `Entry point:` line or None) — what item (37)'s
        `ep_meets` reads an entry point cell against."""
        m_id = re.match(r"^([a-z][a-z-]*)/(p\d+)/(\S+)$", row_id.strip())
        if not m_id:
            return None
        txt = next((v for k_, v in worker_text.items() if Path(k_).name == f"deep-{m_id.group(1)}-{m_id.group(2)}-results.md"), "")
        id_rx = re.compile(r"(?<![\w-])" + re.escape(m_id.group(3)) + r"(?![\w-])")
        own_rx = re.compile(r"^(?:#+ )?\**\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\]\**\s+\**" + re.escape(m_id.group(3)) + r"(?![\w-])", re.I)
        found, inside, flow, sink, entry, others = False, False, "", None, None, []
        for l in txt.splitlines():
            if re.match(r"^(?:#+ )?\**\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*|CONFIRMED|LIKELY)\]", l, re.I):
                inside = own_rx.match(l) is not None
                found = found or inside
                continue  # a heading is no line naming the id, as item (37) reads them
            if inside and re.match(r"^#{1,2} |^<!-- LLM-SAST-COMPLETE", l):
                inside = False
            if inside:
                f_ = re.match(r"^\s*(?:[-*+]\s+)?\**Flow\**:\**\s*(.+)$", l, re.I)
                if f_ and not flow:
                    flow = f_.group(1)
                f_l = re.match(r"^\**Files?:\**\s*(.+)$", l)
                s_ = re.search(r"([^\s|:,;()]+):(\d+)", re.sub(r"[`*]", "", f_l.group(1))) if f_l else None
                if s_ and sink is None:
                    sink = (s_.group(1), int(s_.group(2)))
                e_ = re.match(r"^\s*(?:[-*+]\s+)?\**Entry points?\**\s*:\**\s*(.+)$", l, re.I)
                if e_ and entry is None:
                    entry = e_.group(1).strip()
            elif id_rx.search(l):
                others.append(l)
        return (flow, "\n".join(others), sink, entry) if found else None

    record_also_memo: dict = {}

    def record_also(row_id: str) -> list:
        """The sinks the `Also at:` line of the worker record a table row id names lists — one missing check's other sink
        lines (base skill, Deduplication & Sink Location) — as `path:line` strings, read by `also_sinks`, a range by its
        first line. A promoted row's id reads as its record's. Empty when the record or the line is absent."""
        rid_ = re.sub(r"^promoted/", "", re.sub(r"[`*]", "", row_id).strip())
        if rid_ in record_also_memo:
            return record_also_memo[rid_]
        m_id = re.match(r"^([a-z][a-z-]*)/(p\d+)/(\S+)$", rid_)
        if not m_id:
            record_also_memo[rid_] = []
            return []
        txt = next((v for k_, v in worker_text.items() if Path(k_).name == f"deep-{m_id.group(1)}-{m_id.group(2)}-results.md"), "")
        own_rx = re.compile(r"^(?:#+ )?\**\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\]\**\s+\**" + re.escape(m_id.group(3)) + r"(?![\w-])", re.I)
        inside, out_, file_ = False, [], None
        # read outside fenced code, and ended by a section heading (`#`–`###`), never by a `#### Evidence` sub-heading
        # inside the record or a `# comment` in its Evidence: either once cut a record off before its `Also at:` lines.
        # Fences are paired within each record, from its heading to the next record heading, and one still open there
        # is none — as `long_text_lines` reads them — so a fence one record leaves open hides no `Also at:` line
        lines_ = txt.splitlines()
        heads_ = [i_ for i_, l in enumerate(lines_) if re.match(r"^(?:#+ )?\**\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*|CONFIRMED|LIKELY)\]", l, re.I)]
        fenced_ = set()
        for a_, b_ in zip([0] + heads_, heads_ + [len(lines_)]):
            marks_ = [i_ for i_ in range(a_, b_) if FENCE_RX.match(lines_[i_])]
            if len(marks_) % 2:
                marks_ = marks_[:-1]
            for x_, y_ in zip(marks_[::2], marks_[1::2]):
                fenced_.update(range(x_, y_ + 1))
        head_set_ = set(heads_)
        for i_, l in enumerate(lines_):
            if i_ in head_set_:
                inside = own_rx.match(l) is not None
                continue
            if i_ in fenced_:
                continue
            if inside and re.match(r"^#{1,3} |^<!-- LLM-SAST-COMPLETE", l):
                inside = False
            if not inside:
                continue
            f_l = re.match(r"^\**Files?:\**\s*`?([^\s`|:,;]+):\d", l)
            if f_l and file_ is None:
                file_ = re.sub(r"^(?:\./)+", "", f_l.group(1))
            a_ = ALSO_RX.match(l)
            if a_:
                out_ += [f"{p_}:{n_}" for p_, n_, _ in also_sinks(a_.group(1), file_)]
        record_also_memo[rid_] = out_
        return out_

    def block_holders(c_, skip_=None) -> list:
        """A body or promoted row's group as its block holds it — item (40)'s reading: its record's `Also at:` sinks and
        those of each record of its class merged into its block — so a group whose lead record was merged into another
        block is read where its line went; as (sink, the row whose record's line names it). `skip_`: a merged row whose
        own line is not read — the row being judged, so a record naming its own sink is no group's."""
        out_ = [(s_, c_) for s_ in record_also(c_[0])]
        for m_r in table_rows:
            if m_r is not skip_ and m_r[4].lower() == "merged" and (c_[6] or "") and m_r[6].upper() == c_[6].upper() and m_r[3] == c_[3]:
                out_ += [(s_, m_r) for s_ in record_also(m_r[0])]
        return out_

    def block_group(c_, skip_=None) -> list:
        return [s_ for s_, _ in block_holders(c_, skip_)]

    def block_also_lines(block_: str) -> list:
        """The `Also at:` lines of a report block, read as item (40) reads a block: to its next `#`, `##` or `###`
        heading, outside fenced code."""
        lines_ = unfenced(block_ or "").split("\n")
        out_ = []
        for l in lines_[1:]:
            if re.match(r"^#{1,3} ", l):
                break
            a_ = ALSO_RX.match(l)
            if a_:
                out_.append(a_.group(1))
        return out_

    def block_also(block_: str) -> list:
        """The sinks a report block's own `Also at:` line names, as `record_also` reads a record's."""
        f_ = file_of(block_ or "")
        fp_ = f_.rsplit(":", 1)[0] if f_ else None
        return [f"{p_}:{n_}" for l_ in block_also_lines(block_) for p_, n_, _ in also_sinks(l_, fp_)]

    def block_also_bad(block_: str) -> list:
        """What is wrong with a block's `Also at:` lines: one naming no sink it can read, a range, a path no file of the
        target holds."""
        f_ = file_of(block_ or "")
        fp_ = f_.rsplit(":", 1)[0] if f_ else None
        bad_ = []
        for l_ in block_also_lines(block_):
            s_ = also_sinks(l_, fp_)
            if not s_:
                bad_.append(f"`Also at: {l_.strip()[:40]}` names no `<path>:<line>` it can read")
            bad_ += [f"`{p_}:{a_}-{b_}` is a range — one line each" for p_, a_, b_ in s_ if b_ != a_]
            bad_ += [f"`{p_}` is no file of the target" for p_ in dict.fromkeys(p_ for p_, _, _ in s_) if target_lines(p_) is None]
        return bad_
    # the keys a row's record holds on its `Also at:` line, at its class: re-found by that record, never keys of their own
    also_rows = lambda disp_: {corrected_key(c[3], s_) for c in table_rows if c[4].lower() in disp_
                               for s_ in (block_also(block_id.get(c[6].upper(), "")) if c[4].lower() == "carried" else record_also(c[0]))}

    # duplicates (48): one finding reported by two workers. Nothing is merged by rule — a rule that guessed an entry point
    # once merged two routes — so the recheck lists the pairs, the writer judges each from its two records and answers it
    # on a `duplicate candidate:` line, and a merge stands only as that answer and item (4) allow
    ep_full = []
    for l in ep_list_sec.splitlines():
        f = l.split(" | ")
        m = re.match(r"^(.+):(\d+)", f[0].strip().lstrip("|").strip().strip("`")) if len(f) >= 3 and not l.startswith("#") else None
        if m:
            ep_full.append((m.group(1), int(m.group(2)), f[2].strip()))
    HTTP_RX = re.compile(r"(?i)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[^\s()`,;]*)")
    def route_path(p_):
        """A path ends at the sentence around it: a trailing `.`, `:`, `!` or quote is prose, never the route's. A `?` is
        left as written — a route's own optional marker (`/:id?`, `/abc?`) looks the same as a question's — as are `*`,
        `]` and `>` (`/files/*`, `/[id]`, `/<int:id>`) and an ellipsis (`/api/...`), whatever follows it."""
        if not re.search(r"\.\.[.:!?'\"]*$", p_):
            p_ = p_.rstrip(".:!'\"")
        return p_.rstrip("/") or "/"
    routes_of = lambda t_: {f"{m_.group(1).upper()} {route_path(m_.group(2))}" for m_ in HTTP_RX.finditer(t_ or "")}
    route_entries: dict = {}
    for e_ in ep_full:
        for r_ in routes_of(e_[2]):
            route_entries.setdefault(r_, set()).add((e_[0], e_[1]))
    # a route one list entry holds names that entry; `GET /:id`, which many routers hold, names none
    unique_routes = lambda t_: {r_ for r_ in routes_of(t_) if len(route_entries.get(r_, ())) == 1}
    PATH_CITE = re.compile(r"([\w./()\[\]@+-]+\.\w+):(\d+)")
    memo48: dict = {}

    def ep_strict(cell: str):
        """The list entry a cell names by `file:line`: a path naming one list file, a line within three of exactly one
        registration there, and a positive name match — every `METHOD /path` the cell names that registration's own, or,
        naming none, the registration's operation name in the cell. None when anything is unsure."""
        if ("strict", cell) in memo48:
            return memo48[("strict", cell)]
        c_ = re.sub(r"\s+", " ", (cell or "").replace("`", "")).strip()
        found_ = set()
        for m_ in PATH_CITE.finditer(c_):
            ln_ = int(m_.group(2))
            paths_ = set()
            # a path may hold `(admin)` or `[id]` segments; a `(` or `[` before it is the prose's own
            for cited_ in dict.fromkeys((m_.group(1).lstrip("./"), m_.group(1).lstrip("([").lstrip("./"))):
                paths_ = {e_[0] for e_ in ep_full if e_[0] == cited_ or e_[0].endswith("/" + cited_)}
                if paths_:
                    break
            if len(paths_) != 1:
                continue
            near_ = [e_ for e_ in ep_full if e_[0] in paths_ and abs(e_[1] - ln_) <= 3]
            if len(near_) == 1:
                found_.add(near_[0])
        res_ = None
        if len(found_) == 1:
            e_ = next(iter(found_))
            own_, named_ = routes_of(e_[2]), routes_of(c_)
            if named_:
                ok_ = bool(own_) and named_ <= own_
            else:
                last_ = (re.findall(IDENT, e_[2]) or [None])[-1]
                ok_ = bool(last_) and last_ in set(re.findall(IDENT, re.sub(r"\S+:\d+(?:-\d+)?", " ", c_)))
            res_ = (e_[0], e_[1]) if ok_ else None
        memo48[("strict", cell)] = res_
        return res_

    def ep_loose(cell: str):
        if ("loose", cell) not in memo48:
            memo48[("loose", cell)] = ep_single(cell or "")
        return memo48[("loose", cell)]
    unavail = lambda cell: re.sub(r"[`*_\s.]", "", cell or "").lower() in ("unavailable", "", "—", "-", "n/a", "none")
    cell_norm = lambda cell: " ".join(re.sub(r"[`*]", "", cell or "").lower().split())
    sink_of = lambda c_: canon(rel(c_[2]))
    file_line = lambda c_: (re.sub(r":\d+(?:-\d+)?$", "", sink_of(c_)), int((re.search(r":(\d+)(?:-\d+)?$", sink_of(c_)) or [0, 0])[1]))
    copy_keys48 = {corrected_key(m.group(1), m.group(2)) for m in copy_rows}
    SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0.5, "INFORMATIONAL": 0.5}
    wr_id = lambda c_: re.sub(r"[`*]", "", c_[0]).strip().upper()

    def record_sev(row_id: str):
        """The severity the worker record a row id names states in its heading — the one Step 6 saw."""
        m_r = re.match(r"^([a-z][a-z-]*)/(p\d+)/(\S+)$", re.sub(r"[`*]", "", row_id).strip())
        txt_ = next((v for k_, v in worker_text.items() if m_r and Path(k_).name == f"deep-{m_r.group(1)}-{m_r.group(2)}-results.md"), "")
        h_ = re.search(r"(?m)^(?:#+ )?\**\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\]\** " + re.escape(m_r.group(3)) + r"(?![\w-])", txt_, re.I) if m_r else None
        return h_.group(1).upper() if h_ else None
    sev_rank = lambda c_: SEV_RANK.get(record_sev(c_[0]) or "", 0)

    def ep_of(c_):
        """A row's entry point as its worker record states it — the cell only when no record is found: a merged row's
        cell, which no item reads, never makes two findings one."""
        if ("ep", c_[0]) not in memo48:
            memo48[("ep", c_[0])] = record_entry(re.sub(r"[`*]", "", c_[0]).strip()) or c_[1]
        return memo48[("ep", c_[0])]

    def ep_same(c_):
        """As `ep_of`, for two rows of one class and sink: a record that states no `Entry point:` line leaves the writer
        to fill its cell from the list, and that cell stands only when the record's own lines name it — every route the
        cell names in its `Flow:` line or its file's lines naming its id, or the cell met there as item (37)'s `ep_meets`
        reads a cell — else it is `unavailable`, so a pick the record does not bear out never keeps a pair from the
        writer's judgement. The memo holds (reading, whether the record's silence set it)."""
        if ("same", c_[0]) not in memo48:
            rid_ = re.sub(r"[`*]", "", c_[0]).strip()
            parts_ = None if record_entry(rid_) else record_parts(rid_)
            if parts_ is None:
                memo48[("same", c_[0])] = (ep_of(c_), False)
            elif parts_[3]:
                memo48[("same", c_[0])] = (parts_[3], False)  # an entry point under a sub-heading `record_entry` stops at
            else:
                own_ = parts_[0] + "\n" + parts_[1]
                routes_ = routes_of(c_[1])
                named_ = not unavail(c_[1]) and ((bool(routes_) and routes_ <= routes_of(own_)) or ep_meets(c_[1], "", parts_[0], parts_[1], parts_[2]))
                memo48[("same", c_[0])] = (c_[1], False) if named_ else ("unavailable", not unavail(c_[1]))
        return memo48[("same", c_[0])][0]

    def no_line_(c_) -> bool:
        """The row's worker record is found and states no `Entry point:` line anywhere in it."""
        rid_ = re.sub(r"[`*]", "", c_[0]).strip()
        parts_ = None if record_entry(rid_) else record_parts(rid_)
        return parts_ is not None and not parts_[3]

    # a configuration or infrastructure file: container and build recipes, CI, deployment manifests, server and
    # environment config (a template of one too), a site's `index.html` shell — one statement at a line, reached through no
    # route of its own, so two records of one class at one of its lines are one statement; no other page (a filename cannot
    # tell a static page from a template rendered once per route), no page under a template, view, layout, partial or
    # include directory, and no code file whatever its name
    CONFIG_SINK = re.compile(r"(?i:(?:^|[/\\])(?:(?:[^/\\]+\.)?(?:dockerfile|containerfile)(?:\.[\w.-]+|[-_][\w-]+)?"
                             r"|(?:gnu)?makefile(?:\.(?:am|in))?|[^/\\]+\.mk|jenkinsfile(?:\.[\w.-]+|-[\w-]+)?|procfile|caddyfile"
                             r"|\.htaccess|(?:[^/\\]+)?\.env(?:\.[\w.-]+)?"
                             r"|[^/\\]+\.(?:ya?ml|toml|ini|cfg|conf|tf|tfvars|hcl|bicep|properties)(?:\.(?:template|tpl|tmpl|j2))?"
                             r"|index\.html?))$")
    RENDER_DIR = re.compile(r"(?i)(?:^|[/\\])(?:[^/\\]*[-_.])?(?:templates?|views?|layouts?|partials?|includes?|jinja2)[/\\]")
    CODE_FILE = re.compile(r"(?i)\.(?:py|pyi|js|mjs|cjs|jsx|ts|mts|cts|tsx|go|rb|rs|java|kts?|cs|php|swift|scala|c|cc|cpp|h|hpp"
                           r"|mm?|sh|bash|ps1|pl|lua|dart|vue|svelte|groovy|gvy|ex|exs|erl|clj|cljs|hs|r|jl|fs|fsx|vb|sql)$")
    config_sink = lambda f_: bool(CONFIG_SINK.search(f_)) and not CODE_FILE.search(f_) and not re.search(r"[\s,;]|:\d", f_) \
        and not (re.search(r"(?i)\.html?$", f_) and RENDER_DIR.search(f_))

    def dup_pair(a_, b_):
        """How two record rows relate: `entry` (one class and sink, both cells naming one list entry by `file:line` and
        name — one finding by the identity rule), `same` (one class and sink, entry points not told apart), `near`
        (another class or sink line within five lines of one file, one entry point — or another class at one line of a
        configuration file, entry points not told apart), or None."""
        same_key = a_[3] == b_[3] and sink_of(a_) == sink_of(b_)
        pa_, pb_ = (ep_same(a_), ep_same(b_)) if same_key else (ep_of(a_), ep_of(b_))
        ra_, rb_ = routes_of(pa_), routes_of(pb_)
        if ra_ and rb_ and not (ra_ & rb_):
            return None  # two cells naming other routes: two entry points
        ea_, eb_ = ep_strict(pa_), ep_strict(pb_)
        ua_, ub_ = unique_routes(pa_), unique_routes(pb_)

        def apart_(ea_, la_, ua_, eb_, lb_, ub_):
            """The list resolves the two entry points — each to its strict entry, else its loose one, else the entries its
            unique routes name — to entries with none in common."""
            xs_ = lambda e_, l_, u_: {e_} if e_ else {l_} if l_ else {x_ for r_ in u_ for x_ in route_entries.get(r_, ())}
            xa_, xb_ = xs_(ea_, la_, ua_), xs_(eb_, lb_, ub_)
            return bool(xa_ and xb_ and not (xa_ & xb_))
        both_un = unavail(pa_) and unavail(pb_)
        text_eq = cell_norm(pa_) == cell_norm(pb_)
        if same_key:
            if ea_ and ea_ == eb_:
                return "entry"
            if ea_ and eb_:
                return None  # two list entries: two findings
            la_, lb_ = ep_loose(pa_), ep_loose(pb_)
            if la_ and lb_ and la_ != lb_ and not (ua_ and ua_ == ub_):
                return None
            # an `unavailable` entry point cannot be told apart from any other: with one class and sink the pair is judged
            one_ = unavail(pa_) or unavail(pb_) or text_eq or bool(la_ and la_ == lb_) or bool(ea_ and ea_ == lb_) or bool(eb_ and eb_ == la_) or bool(ua_ and ua_ == ub_)
            if not one_ and config_sink(file_line(a_)[0]):
                # a configuration line is one statement, its entry point a deployment surface in prose: two records of one
                # class there are judged unless the list resolves their entry points to entries with none in common (strict,
                # loose, or the entries a cell's routes name) — two cells naming routes, none of them shared, were ruled two
                # findings above
                one_ = not apart_(ea_, la_, ua_, eb_, lb_, ub_)
            return "same" if one_ else None
        (fa_, na_), (fb_, nb_) = file_line(a_), file_line(b_)
        if fa_ == fb_ and abs(na_ - nb_) <= 5 and (both_un or text_eq or bool(ea_ and ea_ == eb_) or bool(ua_ and ua_ == ub_)):
            return "near"
        # two classes at one line of a configuration file are mostly one defect under two names, sometimes two checks: the
        # pair is judged unless the list resolves the entry points apart, each read as for one class there — from the
        # record's own `Entry point:` line, a record that states none `unavailable`
        if fa_ == fb_ and na_ == nb_ and na_ > 0 and config_sink(fa_):
            sa_, sb_ = ep_same(a_), ep_same(b_)
            if not apart_(ep_strict(sa_), ep_loose(sa_), unique_routes(sa_), ep_strict(sb_), ep_loose(sb_), unique_routes(sb_)):
                return "near"
        return None

    def also_line(block_: str, c_) -> bool:
        """The block names row `c_` on an `Also: <class> — <worker record> at <sink>` line: its worker record and class as
        whole tokens, its sink's file and line."""
        wr_, cl_ = wr_id(c_), c_[3].lower()
        f_, n_ = file_line(c_)
        for l_ in re.findall(r"(?m)^\**Also:\**\s*(.+)$", block_ or ""):
            t_ = re.sub(r"[`*]", "", l_)
            if re.search(r"(?<![\w/-])" + re.escape(wr_) + r"(?![\w-])", t_, re.I) and re.search(r"(?<![\w-])" + re.escape(cl_) + r"(?![\w-])", t_, re.I) \
                    and re.search(re.escape(f_.rsplit("/", 1)[-1]) + r":" + str(n_) + r"(?!\d)", t_):
                return True
        return False
    ans48: dict = {}
    for l_ in appendix.splitlines():
        m_ = re.match(r"^[-*+\s]*\**duplicate candidate:\**\s*`?([^`\s/]+/p\d+/[^`\s]+)`?\s*/\s*`?([^`\s]+)`?\s*(?:[—–]|--|-)\s*(.+)$", l_.strip(), re.I)
        if m_:
            ans48.setdefault(frozenset({m_.group(1).upper(), m_.group(2).upper()}), []).append(m_.group(3).strip(" `*"))

    def answered_into(c_, t_) -> bool:
        """The pair's one answer line reads `merged into <t_'s VULN id>`."""
        got_ = ans48.get(frozenset({wr_id(c_), wr_id(t_)}), [])
        return len(got_) == 1 and re.match(r"(?i)merged into\s+`?" + re.escape(t_[6].strip()) + r"(?![\w-])", got_[0]) is not None

    def xmerge_why(c_, t_):
        """Why row `c_`, merged across keys into body row `t_`, is no valid duplicate merge, or None when it is."""
        why_ = []
        if not also_line(block_id.get(t_[6].upper(), ""), c_):
            why_.append(f"the kept block `{t_[6]}` holds no `Also: {c_[3]} — {c_[0]} at {c_[2]}` line")
        if corrected_key(c_[3], c_[2]) in copy_keys48:
            why_.append(f"its key `{c_[3]}|{sink_of(c_)}` is a ledger row of the pre-write copy — it stays a `body` row and the pair is `linked`")
        if sev_rank(c_) > sev_rank(t_):
            why_.append(f"its worker record is {record_sev(c_[0])} and the kept one {record_sev(t_[0])} — the lower severity is the one merged")
        return "; ".join(why_) or None
    ep_list_go = entry_list(plan)
    def group_overlap(c_, t_) -> bool:
        """Row `c_` and body row `t_` are one missing check's two records: one class, one entry point (the list entry each
        cell names, or the same words), and one's sink on the other's record's `Also at:` line — the kept row's read as its
        block holds it, with the records of its class merged into it."""
        if not t_ or c_[3] != t_[3]:
            return False
        ek_ = lambda x_: ep_id(x_[1]) or " ".join(re.sub(r"[`*]", "", x_[1] or "").lower().split())
        if ek_(c_) != ek_(t_):
            return False
        es_c_, es_t_ = ep_strict(ep_of(c_)), ep_strict(ep_of(t_))
        if es_c_ and es_t_ and es_c_ != es_t_:
            return False
        er_c_, er_t_ = entry_at(ep_of(c_) or "", ep_list_go), entry_at(ep_of(t_) or "", ep_list_go)
        if isinstance(er_c_, tuple) and isinstance(er_t_, tuple) and er_c_ != er_t_:
            return False  # two list entries, as STEP 2's `--overlaps` and the gate's `groups` read the records
        sc_, st_ = canon(rel(c_[2])), canon(rel(t_[2]))
        # the merged side read with the records of its own key merged into the same block: a group line its sibling holds
        sib_ = [c_] + [m_ for m_ in table_rows if m_ is not c_ and m_[4].lower() == "merged" and m_[6].upper() == c_[6].upper()
                       and m_[3] == c_[3] and canon(rel(m_[2])) == sc_ and ek_(m_) == ek_(c_)]
        return sc_ in {canon(rel(x_)) for x_ in block_group(t_, c_)} or st_ in {canon(rel(x_)) for r_ in sib_ for x_ in record_also(r_[0])}
    def group_merge(x_, y_) -> bool:
        """A `merged` row `x_` that is a group overlap of the `body` row `y_` it points at: merged into the block that holds
        the group's line, whatever the two worker severities — that block reads at the highest severity among its lines."""
        if not (x_[4].lower() == "merged" and y_[4].lower() == "body" and x_[6].upper() == y_[6].upper() and group_overlap(x_, y_)):
            return False
        sx_ = canon(rel(x_[2]))
        if sx_ == canon(rel(y_[2])):
            return False  # one key: a same-key duplicate, which the Duplicates rule's order merges
        at_x_ = {id(m_) for m_ in table_rows if m_[4].lower() == "merged" and canon(rel(m_[2])) == sx_}
        return sx_ in {canon(rel(s_)) for s_, h_ in block_holders(y_) if id(h_) not in at_x_}
    bad_merge, merge_fix = 0, []
    for c in merged_rows:
        t = body_by_id.get(c[6].upper())
        kind4 = None
        if t and (ep_id(t[1]), canon(rel(t[2])), t[3]) == (ep_id(c[1]), canon(rel(c[2])), c[3]):
            # the cells agree; the records must too: two list entries are two findings, a cell rewritten to match or not
            es_c, es_t = ep_strict(ep_of(c)), ep_strict(ep_of(t))
            if es_c and es_t and es_c != es_t:
                bad_merge += 1
                merge_fix.append(f"`{c[0]}`'s record names the entry `{es_c[0]}:{es_c[1]}` and the kept `{t[0]}`'s `{es_t[0]}:{es_t[1]}` — two list entries are two findings: undo `{c[0]}` into its own body block and table row, its cell its record's entry point")
            continue
        if t and (ep_id(t[1]), canon(rel(t[2])), t[3]) != (ep_id(c[1]), canon(rel(c[2])), c[3]):
            # a duplicate the writer judged: its `duplicate candidate:` line reads `merged into` the kept row, and a merge
            # across keys also keeps both classes visible, merges the lower severity and never a ledger key of the copy
            kind4 = dup_pair(c, t)
            if kind4 in ("entry", "same") and answered_into(c, t) and sev_rank(c) <= sev_rank(t):
                continue
            if kind4 == "near" and answered_into(c, t) and not xmerge_why(c, t):
                continue
            # a group overlap: two records of one missing check at one class and entry point, one's sink on the other's
            # `Also at:` line — item (48) asks for this merge, and a block cannot leave its record's `Also at:` line
            if group_merge(c, t):
                continue  # merged into the block that holds the group's line, the one way a group overlap is merged
            if group_overlap(c, t):
                # the other way round: the group's line would leave the report, or stand only as a Flow hop
                bad_merge += 1
                merge_fix.append(f"`{c[0]}` and `{t[0]}` are a group overlap merged the wrong way round — turn the merge round: `{t[0]}`, whose sink stands on the group's `Also at:` line, is the one merged, into the block that holds that line, which reads at the highest severity among its lines")
                continue
        if not t or (ep_id(t[1]), canon(rel(t[2])), t[3]) != (ep_id(c[1]), canon(rel(c[2])), c[3]):  # one sink, whichever line form each row cites
            bad_merge += 1
            if t and kind4 and answered_into(c, t):
                # judged a duplicate, recorded so, and short of what the merge needs
                why4 = xmerge_why(c, t) if kind4 == "near" else (f"its worker record is {record_sev(c[0])} and the kept one {record_sev(t[0])} — the lower severity is the one merged" if sev_rank(c) > sev_rank(t) else None)
                merge_fix.append(f"`{c[0]}` is merged into `{c[6]}` as a duplicate, but {why4}")
                continue
            dup_note4 = " — then judge the pair from `python3 .llm-sast-scanner-cache/recheck.py --duplicates`, never writing a line for a merge nobody judged" if t and kind4 else ""
            own_blk = block_id.get(c[6].upper()) if not t else None
            wr_line = re.search(r"^\**Worker record:\**\s*`?([^`\s]+)", own_blk or "", re.M)
            if own_blk and wr_line and wr_line.group(1).upper() == c[0].upper():
                # the block this row points at is the row's own: the record is a body record, not a merge
                merge_fix.append(f"`{c[0]}` points at `{c[6]}`, its own body block, which no `body` row carries — its disposition is `body`")
                continue
            rec_ep = record_entry(c[0])
            rec_one = ep_single(rec_ep) if rec_ep else None
            if rec_one and rec_one != ep_id(c[1]):
                # the cell, not the merge, is what differs: the row copies its worker record
                merge_fix.append(f"the entry-point cell of `{c[0]}` differs from its worker record's `Entry point:` ({rec_ep[:80]}) — copy the record's entry point into the cell, then read the merge again")
                continue
            own = next((b[6] for b in body_rows if (ep_id(b[1]), canon(rel(b[2])), b[3]) == (ep_id(c[1]), canon(rel(c[2])), c[3])), None)
            merge_fix.append((f"point `{c[0]}` at `{own}`, the body row with its own entry point, sink and class" if own else f"undo `{c[0]}` into its own body block and table row") + dup_note4)
    emit("merges with a different entry point", f"{bad_merge} (of {len(merged_rows)} merged rows; table rows {len(table_rows)} | malformed rows {malformed})", None, bad_merge == 0 and malformed == 0,
         "; ".join([x for x in ("; ".join(merge_fix[:6]) + (" …" if len(merge_fix) > 6 else "") + (", then re-count the histogram, the close-out and the ledger from what is written" if any(m.startswith("undo") for m in merge_fix) else ""),
                              "rewrite each malformed row as seven cells whose fifth is a disposition word" if malformed else "") if x]))

    # 48. duplicates — every pair of `body`/`merged` rows that may be one finding has one `duplicate candidate:` line
    # judging it, `merged into <the kept block's VULN id>`, `distinct: <what differs>` or `linked`, and the table bears
    # the answer out; a pair the table already answers — one key, one row merged into the other, or both rows merged into
    # one body row — needs none, and a line on it that agrees is no stray
    rec_rows = [c for c in table_rows if c[4].lower() in ("body", "merged")]
    by_file48: dict = {}
    for c in rec_rows:
        by_file48.setdefault(file_line(c)[0], []).append(c)
    cand48, skip48 = {}, {}
    for rows_ in by_file48.values():
        for i_ in range(len(rows_)):
            for j_ in range(i_ + 1, len(rows_)):
                a_, b_ = rows_[i_], rows_[j_]
                kind_ = dup_pair(a_, b_)
                if not kind_:
                    continue
                pair_ = frozenset({wr_id(a_), wr_id(b_)})
                into_ = any(x_[4].lower() == "merged" and y_[4].lower() == "body" and x_[6].upper() == y_[6].upper() and ep_id(x_[1]) == ep_id(y_[1]) for x_, y_ in ((a_, b_), (b_, a_)))
                both_into = a_[4].lower() == b_[4].lower() == "merged" and a_[6].upper() == b_[6].upper()
                if both_into or (into_ and a_[3] == b_[3] and sink_of(a_) == sink_of(b_)):
                    skip48[pair_] = (kind_, a_, b_)
                else:
                    cand48[pair_] = (kind_, a_, b_)
    if getattr(args, "duplicates", False):
        # the writer's worklist: every pair to judge, with what it needs to tell `merged into` from `linked`
        if not table_rows:
            print("duplicates: error — no disposition table rows yet: write `.llm-sast-scanner-cache/disposition-table.md` first; nothing listed")
            return 2
        for pair_, (kind_, a_, b_) in sorted(cand48.items(), key=lambda x_: (x_[1][0], sorted(x_[0]))):
            side_ = lambda c_: (f"{c_[0]} ({c_[6] if c_[4].lower() == 'body' else 'merged into ' + c_[6]}, {record_sev(c_[0]) or '?'}, {c_[3]} at {sink_of(c_)}, "
                                f"{'ledger key of the copy' if corrected_key(c_[3], c_[2]) in copy_keys48 else 'no ledger key'}; entry point: {(ep_same(c_) if kind_ != 'near' else ep_of(c_))[:90]}"
                                f"{' — its record states none and does not name its cell' if kind_ != 'near' and ep_same(c_) and memo48[('same', c_[0])][1] else ''}"
                                f"{' — its record states none: this is its cell' if kind_ == 'near' and not unavail(c_[1]) and no_line_(c_) else ''})")
            got_ = ans48.get(pair_, [])
            print(f"duplicate pair {kind_}: {side_(a_)} <> {side_(b_)} | answer: {got_[0][:60] if len(got_) == 1 else ('none' if not got_ else f'{len(got_)} lines')}")
        print(f"duplicate pairs: {len(cand48)} to answer | {len(skip48)} the table answers")
        # recheck item (51)'s reading made early: a `merged` row whose worker record outranks its kept `body` row's —
        # the higher record is the one kept, before the body, the histogram and the counts are taken
        R51 = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "INFORMATIONAL": 1}
        n51d = 0
        for c_ in merged_rows:
            t_ = body_by_id.get(c_[6].upper())
            sc_, st_ = record_sev(c_[0]), (record_sev(t_[0]) if t_ else None)
            if t_ and sc_ and st_ and R51.get(sc_, 0) > R51.get(st_, 0) and not group_merge(c_, t_):
                n51d += 1
                print(f"merge severity: {c_[0]} ({sc_}) is merged into {t_[6]} ({t_[0]}, {st_}) — keep {c_[0]} as the `body` row and merge {t_[0]} into it")
        if n51d:
            print(f"merge severity: {n51d} merged records outrank their kept record")
        # item (48)'s `Also at` reading made early: a `body` record whose sink stands on another `body` record's `Also at:`
        # line at one class and entry point is that group's — the writer merges it before the body is rendered
        ekd_ = lambda x_: ep_id(x_[1]) or " ".join(re.sub(r"[`*]", "", x_[1] or "").lower().split())
        bodyd_ = [x_ for x_ in table_rows if x_[4].lower() == "body"]
        atd_: dict = {}
        for x_ in bodyd_:
            atd_.setdefault((x_[3], ekd_(x_), canon(rel(x_[2]))), []).append(x_)
        ngo_ = 0
        vd_ = re.search(r"v(\d+)\.(\d+)\.(\d+)", corrected_str(plan, "wrapper:") or "")
        step2d_ = bool(vd_) and tuple(int(z_) for z_ in vd_.groups()) >= (2, 26, 12)  # STEP 2 read the files against each other
        for x_ in bodyd_:
            seen_ = set()
            for s0_, h_ in block_holders(x_):
                s_ = canon(rel(s0_))
                if s_ in seen_:
                    continue
                seen_.add(s_)
                for o_ in atd_.get((x_[3], ekd_(x_), s_), []):
                    if o_ is not x_:
                        ngo_ += 1
                        print(f"group overlap: {o_[0]} ({o_[3]} at {s_}) stands on {h_[0]}'s `Also at:` line (block {x_[6]}) at one class and entry point — merge it into that block, which reads at the highest severity among its lines"
                              + ("; a fix of its own STEP 2 left on the line is named on its own `Also:` line" if step2d_ else ""))
        if ngo_:
            print(f"group overlap: {ngo_} records stand on another record's `Also at:` line")
        return 0
    bad48, n_m, n_d, n_l, unans_l = [], 0, 0, 0, []
    clause48: dict = {}  # each `distinct` clause, normalised, with the class pairs and ids of the pairs it answers
    kinds48 = Counter(k_ for k_, _, _ in cand48.values())

    def merged_to(x_, k_):
        return (x_[4].lower() == "body" and x_[6].upper() == k_) or (x_[4].lower() == "merged" and x_[6].upper() == k_)
    # a merged row is read as the body block its `body record` cell names, a body row as itself
    kept_ = lambda x_: x_ if x_[4].lower() != "merged" else next(
        (y_ for y_ in table_rows if y_[4].lower() == "body" and y_[6].upper() == x_[6].upper()), x_)
    for pair_, (kind_, a_, b_) in sorted(cand48.items(), key=lambda x_: sorted(x_[0])):
        got_ = ans48.get(pair_, [])
        ids_ = f"{a_[0]} / {b_[0]}"
        if len(got_) != 1:
            unans_l.append(f"`{ids_}` ({kind_}: {a_[6]} {a_[3]} at {sink_of(a_)}; {b_[6]} {b_[3]} at {sink_of(b_)})" + (f" — {len(got_)} lines" if got_ else ""))
            continue
        ans_ = got_[0]
        into_ = re.match(r"(?i)merged into\s+`?(vuln-[\w-]*\d)", ans_)
        if into_:
            n_m += 1
            k_ = into_.group(1).upper()
            if not (merged_to(a_, k_) and merged_to(b_, k_) and "merged" in {a_[4].lower(), b_[4].lower()}):
                bad48.append(f"`{ids_}` reads `merged into {k_}`, but the table does not merge the pair into `{k_}` — each row `{k_}`'s body row or a `merged` row pointing at it")
            elif any(x_[4].lower() == "merged" and y_[4].lower() == "body" and sev_rank(x_) > sev_rank(y_) and not group_merge(x_, y_) for x_, y_ in ((a_, b_), (b_, a_))):
                bad48.append(f"`{ids_}` merges the higher worker severity into the lower — the lower is the one merged")
        elif re.match(r"(?i)distinct\b", ans_):
            n_d += 1
            if any(x_[4].lower() == "merged" and y_[4].lower() == "body" and x_[6].upper() == y_[6].upper() for x_, y_ in ((a_, b_), (b_, a_))):
                bad48.append(f"`{ids_}` reads `distinct`, but one row is merged into the other")
            elif (kept_(a_) is not a_ or kept_(b_) is not b_) and kept_(a_) is not kept_(b_) and kept_(a_)[4].lower() == kept_(b_)[4].lower() == "body" \
                    and any(re.match(r"(?i)linked\b", x_) for x_ in ans48.get(frozenset({wr_id(kept_(a_)), wr_id(kept_(b_))}), [])):
                bad48.append(f"`{ids_}` reads `distinct`, but its rows are held by the kept blocks `{kept_(a_)[6]}` / `{kept_(b_)[6]}`, "
                             f"whose own pair reads `linked` — the pair reads `linked` too")
            elif not re.match(r"(?i)distinct:\s*\S", ans_):
                bad48.append(f"`{ids_}` reads `distinct` with no clause saying what differs")
            cl_ = re.match(r"(?i)distinct:\s*(.*\S)", ans_)
            if cl_:
                clause48.setdefault(" ".join(re.sub(r"[^\w\s]", " ", cl_.group(1).lower()).split()), []).append(
                    (tuple(sorted((a_[3].lower(), b_[3].lower()))), ids_, cl_.group(1)))
        elif re.match(r"(?i)linked\b", ans_):
            n_l += 1
            # a row merged into the block linked to the other — three records of one defect over two keys — is read as the
            # block that holds it: the link is the two kept blocks'
            ka_, kb_ = kept_(a_), kept_(b_)
            if (ka_ is not a_ or kb_ is not b_) and ka_ is not kb_ and ka_[4].lower() == kb_[4].lower() == "body":
                # the kept blocks, when they are a listed pair, are answered `linked` themselves: the link is theirs
                kp_ = frozenset({wr_id(ka_), wr_id(kb_)})
                if kp_ in cand48 and not any(re.match(r"(?i)linked\b", x_) for x_ in ans48.get(kp_, [])):
                    bad48.append(f"`{ids_}` reads `linked` through the kept blocks `{ka_[6]}` / `{kb_[6]}`, but their own pair "
                                 f"`{ka_[0]} / {kb_[0]}` is not answered `linked` — one link, read alike on every pair it joins")
                    continue
                ids_ = f"{ids_} (read as the kept blocks `{ka_[6]}` / `{kb_[6]}`, records `{ka_[0]}` / `{kb_[0]}`)"
                a_, b_ = ka_, kb_
            # linked: the record that would be merged away — the lower severity, either on a tie — holds a ledger key
            away_ = [x_ for x_, y_ in ((a_, b_), (b_, a_)) if sev_rank(x_) <= sev_rank(y_)]
            why_l = ([] if a_[4].lower() == b_[4].lower() == "body" else ["both rows stay `body`"]) \
                + ([] if (a_[3], sink_of(a_)) != (b_[3], sink_of(b_)) else ["one key needs no ledger guard — the pair is `merged into` or `distinct`"]) \
                + ([] if all(corrected_key(x_[3], x_[2]) in copy_keys48 for x_ in away_) else ["the record merged away would hold no ledger key of the copy — the pair is `merged into` or `distinct`"]) \
                + ([] if also_line(block_id.get(a_[6].upper(), ""), b_) and also_line(block_id.get(b_[6].upper(), ""), a_) else [f"each block names the other on an `Also:` line"])
            if why_l:
                bad48.append(f"`{ids_}` reads `linked`, but " + "; ".join(why_l))
        else:
            bad48.append(f"`{ids_}` reads `{ans_[:40]}` — `merged into <VULN id>`, `distinct: <what differs>` or `linked`")
    # a line on a pair the table answers agrees with it or is wrong; a line on no pair is a stray
    for pair_, (kind_, a_, b_) in skip48.items():
        for ans_ in ans48.get(pair_, []):
            into_ = re.match(r"(?i)merged into\s+`?(vuln-[\w-]*\d)", ans_)
            if not (into_ and merged_to(a_, into_.group(1).upper()) and merged_to(b_, into_.group(1).upper())):
                bad48.append(f"`{a_[0]} / {b_[0]}` reads `{ans_[:40]}`, but the table merges the pair into `{a_[6] if a_[4].lower() == 'body' else b_[6] if b_[4].lower() == 'body' else a_[6]}`")
            elif any(x_[4].lower() == "merged" and y_[4].lower() == "body" and sev_rank(x_) > sev_rank(y_) and not group_merge(x_, y_) for x_, y_ in ((a_, b_), (b_, a_))):
                bad48.append(f"`{a_[0]} / {b_[0]}` merges the higher worker severity into the lower — the lower is the one merged")
    stray48 = sorted(" / ".join(sorted(k_)) for k_ in ans48 if k_ not in cand48 and k_ not in skip48)
    # a clause that names what differs in its own pair fits no pair of other classes: one clause answering three or more
    # pairs of two or more class pairs, across two or more groups of records its pairs join, judged none of them (an
    # analogous pair's clause repeats over one class pair; one clause may name every difference in one group of records
    # that pair with each other)
    def groups48(v_):
        root_: dict = {}
        def find_(x_):
            while root_.setdefault(x_, x_) != x_:
                x_ = root_[x_]
            return x_
        for _, ids_, _ in v_:
            a_, b_ = (s_.strip() for s_ in ids_.split(" / ", 1))
            root_[find_(a_)] = find_(b_)
        return len({find_(x_) for x_ in list(root_)})
    rep48 = sorted(((c_, v_) for c_, v_ in clause48.items()
                    if len(v_) >= 3 and len({k_ for k_, _, _ in v_}) >= 2 and groups48(v_) >= 2), key=lambda x_: -len(x_[1]))
    if rep48:
        c_, v_ = rep48[0]
        bad48.append(f"{sum(len(w_) for _, w_ in rep48)} pair(s) answered by {len(rep48)} `distinct` clause(s) repeated across class pairs — "
                     f"`distinct: {v_[0][2].replace('`', '')[:100]}` answers {len(v_)} pairs of {len({k_ for k_, _, _ in v_})} class pairs over {groups48(v_)} groups of records, so it names what differs in none of "
                     "them: judge each such pair from its two records — `merged into` the kept block's VULN id when both name the same absent "
                     "check on the same data path from one entry point, else `distinct: <the two entry points, checks, parameters or guards "
                     "its own records name>`: " + ", ".join(f"`{i_}`" for _, i_, _ in v_[:6]) + (f" … and {len(v_) - 6} more" if len(v_) > 6 else ""))
    if unans_l:
        bad48.append(f"{len(unans_l)} pair(s) have no one `duplicate candidate:` line — judge each from its two records: one finding only when both name the same absent check on the same data path from one entry point, the lower severity then `merged into` the other's VULN id (the kept block's last line `Also: <class> — <worker record> at <sink>` when class or sink differ), never merging away a ledger key of the pre-write copy (then `linked`, both blocks naming each other on `Also:` lines), else `distinct: <what differs>`; `python3 .llm-sast-scanner-cache/recheck.py --duplicates` lists every pair with its ledger keys: "
                     + ", ".join(unans_l[:10]) + (f" … and {len(unans_l) - 10} more" if len(unans_l) > 10 else ""))
    if stray48:
        bad48.append(f"`duplicate candidate:` lines at {', '.join('`' + x_ + '`' for x_ in stray48[:3])} — no pair: a line is written only for a pair `--duplicates` lists")
    # a line both on one finding's `Also at:` line and another finding's own `File:` sink, at one class and entry point,
    # is one defect counted twice: the line is the group's (the record merged into it) or its own (off the `Also at:` line)
    fins48 = [c for c in table_rows if c[4].lower() in ("body", "promoted")]
    ep_k48 = lambda c_: ep_id(c_[1]) or " ".join(re.sub(r"[`*]", "", c_[1] or "").lower().split())
    at_sink48: dict = {}
    for c in fins48:
        at_sink48.setdefault((c[3], ep_k48(c), canon(rel(c[2]))), []).append(c)
    also_twice48 = []
    for c in fins48:
        seen48_ = set()
        for s0_, h_ in block_holders(c):
            s_ = canon(rel(s0_))
            if s_ in seen48_:
                continue
            seen48_.add(s_)
            also_twice48 += [(h_, o_, s_) for o_ in at_sink48.get((c[3], ep_k48(c), s_), []) if o_ is not c]
    v48_ = re.search(r"v(\d+)\.(\d+)\.(\d+)", corrected_str(plan, "wrapper:") or "")
    step2_48 = bool(v48_) and tuple(int(x_) for x_ in v48_.groups()) >= (2, 26, 12)  # STEP 2 read the files against each other
    for k_, (c, o_, s_) in enumerate(also_twice48[:4]):
        bad48.append(f"`{o_[0]}`'s sink `{s_}` stands on `{c[0]}`'s `Also at:` line at one class and entry point — one defect counted twice: "
                     "merge the record into the block that holds the group's line, which reads at the highest severity among its lines (item (4) reads such a merge as one finding's: a block cannot leave its record's `Also at:` line)"
                     + (" — a fix of its own STEP 2 left on the line is named on that record's own `Also:` line" if k_ == 0 and step2_48 else ""))
    if len(also_twice48) > 4:
        bad48.append(f"… and {len(also_twice48) - 4} more sinks on an `Also at:` line that are another finding's own")
    n_lines = sum(len(v_) for v_ in ans48.values())
    stated48 = ints(r"^[-*\s]*\**duplicate candidates:\**\s*(\d+)", appendix)
    if not ((stated48[0] == n_lines) if stated48 else not n_lines and not cand48):
        bad48.append(f"the appendix line reads `duplicate candidates: {n_lines}`, the `duplicate candidate:` lines written")
    emit("duplicates", f"pairs {len(cand48)} (entry {kinds48['entry']} | same {kinds48['same']} | near {kinds48['near']}) | answered merged {n_m} | distinct {n_d} | linked {n_l} | unanswered {len(unans_l)} | lines at no pair {len(stray48)} | pairs the table answers {len(skip48)} | repeated clauses {len(rep48)}" + (f" | Also at lines that are another finding's sink {len(also_twice48)}" if also_twice48 else ""),
         str(stated48[0]) if stated48 else "absent", not bad48, "; ".join(bad48[:6]) + (" …" if len(bad48) > 6 else "") if bad48 else None)

    # 5. config clearances rewritten
    rec_head = re.compile(r"^(?:#+ )?\[(CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\] VULN-", re.I)
    def disposition_lines(text: str):
        # the lines outside finding records: a record runs from its `[SEVERITY] VULN-` heading to the next record or `#` heading
        inside, fence = False, False
        for n_, l in enumerate(text.splitlines(), 1):
            if re.match(r"^\s*(?:```|~~~)", l):
                fence = not fence  # a `---` or a heading inside a fenced block is the block's text, never a record's end
            elif fence:
                pass
            elif rec_head.match(l):
                inside = True
            elif re.match(r"^#{1,6} ", l) or re.match(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$", l) or re.match(
                    r"^\*\*(?:Clearance|Coverage|Pass log|Convergence|Hardening|Positive|Hits)\b[^*]*\*\*:?\s*$", l, re.I):
                inside = False
            if not inside:
                yield n_, l
    # a phrase inside an absence claim — its clause opens `no`, `none of`, `neither` or `nor` and lists what the partition
    # lacks (`SAFE in p3 — no IaC resource-attribute … or vendor non-production endpoint surface in this partition`) — names
    # a class found absent, not a configuration a clearance rests on: a writer told to rewrite one had no sink to rewrite
    def cfg_absent(l_):
        for m_ in CONFIG_PHRASES.finditer(l_):
            st_ = max([l_.rfind(c_, 0, m_.start()) for c_ in ("—", "–", ";", ":", ". ", "(")] + [-1])
            if not re.match(r"(?i)^\s*(?:[*_`]+\s*)?(?:no|none of|neither|nor)\b", l_[st_ + 1:m_.start()]):
                return False
        return True
    cfg_all = [(name, n_, l) for name, t in worker_text.items() for n_, l in disposition_lines(t) if CONFIG_PHRASES.search(l) and CLEARANCE_MARK.search(l) and not FILE_LINE_RX.search(l) and not any(refute_lines(l))]
    cfg_hits = [(name, n_) for name, n_, l in cfg_all if not cfg_absent(l)]
    phrase_lines, cfg_abs = len(cfg_hits), len(cfg_all) - len(cfg_hits)
    rep_cfg = ints(r"^config clearances rewritten:\s*(\d+)", appendix)
    # a report written before the absence claims were set apart counted them too, and reads either count
    emit("config clearances rewritten", str(phrase_lines) + (f" (absence claims {cfg_abs})" if cfg_abs else ""), str(rep_cfg[0]) if rep_cfg else "absent",
         bool(rep_cfg) and rep_cfg[0] in (phrase_lines, phrase_lines + cfg_abs),
         (f"each of the {phrase_lines} worker disposition line(s) that rest on configuration with no file:line guard — {', '.join(f'{pathlib_name(nm)}:{ln}' for nm, ln in cfg_hits[:6])}{' …' if len(cfg_hits) > 6 else ''} — is rewritten as a body record and listed in the report's appendix as `<lens>/p<n>: <its text> → <body VULN id>`; the report's appendix line then reads `config clearances rewritten: {phrase_lines}`" if phrase_lines else "no worker disposition line rests on configuration: the report's appendix line reads `config clearances rewritten: 0`")
         + (f" — the {cfg_abs} line(s) whose phrase stands inside an absence claim (`no … non-production endpoint surface`) name a class found absent and are not counted" if cfg_abs else ""))

    # 6. ledger rows after / archived / duplicate-key rows / ledger present
    dup_rows = sum(v - 1 for v in ledger_keys.values() if v > 1)
    body_keys = {key_of(c[3], c[2]) for c in body_rows}
    present_keys = sum(1 for k in body_keys if k in ledger_keys)
    ledger_sinks = {canon(m.group(2)) for m in ledger}
    body_sinks = {f for f in (file_of(b) for b in blocks) if f}
    present_sinks = sum(1 for s in body_sinks if s in ledger_sinks)
    rep_led = ints(r"^ledger rows before (\d+) \| after (\d+) \| archived (\d+)", appendix)
    rep_merged = ints(r"^ledger rows before \d+ \| after \d+ \| archived \d+ \| duplicate-key rows merged (\d+)", appendix)
    rep_merged = rep_merged[0] if rep_merged else None
    rep_line = ints(r"^ledger: (\d+) distinct class\|file:line keys among body rows \| (\d+) of them present", appendix)
    # the statement's own numbers: `before` is the copy's row count, `merged` the copy's duplicate-key rows (all of them,
    # since none may remain), and rows can only fall by archiving or merging and rise by new keys
    copy_dups = sum(v - 1 for v in Counter(key_of(m.group(1), m.group(2)) for m in copy_rows).values() if v > 1)
    # a non-stem copy row whose sink a stem row also holds lands on that row when STEP X corrects its class: a merge too
    stem_sinks = {canon(m.group(2)) for m in copy_rows if m.group(1) in stems}
    rekey_collisions = sum(1 for m in copy_rows if m.group(1) not in stems and canon(m.group(2)) in stem_sinks) if stems else 0
    before_ok = bool(rep_led) and rep_led[0] == len(copy_rows)
    merged_ok = rep_merged is not None and copy_dups <= rep_merged <= copy_dups + rekey_collisions
    # `archived` in the statement is the archive file's all-time count, so the rows that left THIS run are the copy keys
    # with no row now (archived this run; at an unchanged commit only a `refuted` key's may leave — items 24 and 47 hold that)
    gone_keys = sum(1 for k in {corrected_key(m.group(1), m.group(2)) for m in copy_rows} if k not in ledger_keys)
    equation_ok = bool(rep_led) and rep_merged is not None and rep_led[1] == rep_led[0] - rep_merged - gone_keys + new_keys
    rk_stated = ints(r"rekeyed to stem (\d+)", appendix)  # the hint's statement keeps the field as the report states it
    ok = (bool(rep_led) and rep_led[1] == len(ledger) and rep_led[2] == archived and dup_rows == 0 and bool(rep_line) and rep_line[0] == len(body_keys)
          and rep_line[1] == present_keys == len(body_keys) and before_ok and merged_ok and equation_ok)
    emit("ledger rows after", f"{len(ledger)} | archived {archived} | duplicate-key rows {dup_rows} | body keys {len(body_keys)} present {present_keys} | body File: sinks {len(body_sinks)} present {present_sinks} | before {rep_led[0] if rep_led else 'absent'} (copy rows {len(copy_rows)}) | merged {rep_merged if rep_merged is not None else 'absent'} (copy duplicates {copy_dups}{f' + rekey collisions {rekey_collisions}' if rekey_collisions else ''}) | after = before - merged - keys gone {gone_keys} + new keys {new_keys}: {'holds' if equation_ok else 'FAILS'}",
         f"after {rep_led[1]} archived {rep_led[2]}" if rep_led else "absent" + (f"; ledger: {rep_line[0]}/{rep_line[1]}" if rep_line else "; ledger: absent"), ok,
         "; ".join(x for x in (
             f"merge the {dup_rows} duplicate-key ledger row(s) into one row per class and sink file:line, its brief the distinct briefs joined with `; ` — a duplicate this write made is merged, not counted: `duplicate-key rows merged` counts the pre-write copy's duplicates only ({copy_dups})" if dup_rows else "",
             f"write a ledger row for each of the {len(body_keys) - present_keys} body key(s) with none" if present_keys < len(body_keys) else "",
             f"the statement then reads `ledger rows before {len(copy_rows)} | after {len(ledger) - dup_rows + (len(body_keys) - present_keys)} | archived {archived} | duplicate-key rows merged {copy_dups} | rekeyed to stem {rk_stated[0] if rk_stated else '<r>'}`{f' — `merged` up to {copy_dups + rekey_collisions}, counting each of the {rekey_collisions} rekey collision(s) this write merged' if rekey_collisions else ''}{'' if rk_stated else ' — `<r>` as item (18) counts it'} — and the `ledger:` line `{len(body_keys)} distinct class|file:line keys among body rows | {len(body_keys)} of them present`" if not (bool(rep_led) and rep_led[1] == len(ledger) and bool(rep_line) and rep_line[0] == len(body_keys) and equation_ok and before_ok and merged_ok) else "",
         ) if x) or None)

    # 7. earlier reports
    er = row(plan, "earlier-reports:") or ""
    earlier_listed = re.findall(r"(sast_report-\S+\.md)\s+(\d+)", er)  # (name, bytes) pairs of the `earlier-reports:` row
    listed = earlier_listed
    present = sum(1 for n, s in listed if (target / n).exists() and (target / n).stat().st_size == int(s))
    rep_er = ints(r"^earlier reports:\s*(\d+) recorded \| (\d+) present at recorded size", appendix)
    emit("earlier reports", f"{present}/{len(listed)}", f"{rep_er[0]}/{rep_er[1]}" if rep_er else "absent", bool(rep_er) and rep_er[0] == len(listed) and rep_er[1] == present == len(listed))

    # 8. close-out equations
    totals = ints(r"^worker records: (\d+) \| body: (\d+) \| merged: (\d+) \| withdrawn: (\d+) \| unverifiable: (\d+) \| promoted: (\d+)", appendix)
    eq = []
    if closeout:
        n, f, b, p, k, j, c = closeout
        eq.append(("table rows", n == len(table_rows)))
        eq.append(("file records", f == file_records))
        eq.append(("body rows", b == len(body_rows)))
        eq.append(("carried rows", co_carried == len(carried_rows)))
        eq.append(("k=b+p+carried", k == b + p + co_carried))
        eq.append(("j=b+carried", j == b + co_carried))
        eq.append(("c=0", c == 0))
    if totals:
        n2, b2, m2, w2, u2, p2 = totals
        eq.append(("b+m+w+u=n", b2 + m2 + w2 + u2 == n2))
        eq.append(("merged rows", m2 == len(merged_rows)))
    tot_carried = ints(r"^worker records: .*\| carried: (\d+)", appendix)
    if carried_rows or tot_carried:
        eq.append(("totals carried", bool(tot_carried) and tot_carried[0] == len(carried_rows)))
    tot_refuted = ints(r"^worker records: .*\| refuted: (\d+)", appendix)
    if refuted_rows or tot_refuted:
        eq.append(("totals refuted", bool(tot_refuted) and tot_refuted[0] == len(refuted_rows)))
    failed = [name for name, ok_ in eq if not ok_]
    # 31. worker record ids — computed here, where the close-out hint needs it: the table's ids against the worker files'
    # records, both directions, one row each; a table whose ids the files do not hold joins nothing to its evidence
    rec_ids, rec_seen = {}, Counter()
    for pth_, txt_ in worker_text.items():
        m_f = re.match(r"^deep-(.+)-(p\d+)-results\.md$", Path(pth_).name)
        for l in txt_.splitlines() if m_f else []:
            h = ANY_RECORD_RX.match(l)
            if h:
                key_ = f"{m_f.group(1)}/{m_f.group(2)}/{h.group(2)}"
                rec_seen[key_.upper()] += 1
                rec_ids.setdefault(key_.upper(), key_)
    rec_dups = [rec_ids[k_] for k_, n_ in rec_seen.items() if n_ > 1]  # two records of one worker file under one id: that many rows
    own_rows = [c for c in table_rows if c[4].lower() not in ("promoted", "carried", "refuted")]
    cell_id = lambda c: re.sub(r"[`*]", "", c[0]).strip()
    shown = {}
    for c in own_rows:
        shown.setdefault(cell_id(c).upper(), cell_id(c))
    row_ids = Counter(cell_id(c).upper() for c in own_rows)
    unknown = [shown[i] for i in row_ids if i not in rec_ids]
    unrowed = [rec_ids[i] for i in rec_ids if row_ids.get(i, 0) < rec_seen[i]]
    multi = [(shown[i], n_) for i, n_ in row_ids.items() if n_ > rec_seen.get(i, 1)]  # an id no record holds is one row at most
    ids_ok = not unknown and not unrowed and not multi
    promoted_n = sum(1 for c in table_rows if c[4].lower() == "promoted")
    kinds = Counter(c[4].lower() for c in table_rows)
    fix_c = None
    if not (bool(eq) and not failed):
        fix_c = (f"the close-out line reads `close-out: table rows {len(table_rows)} | file records {file_records} | body rows {len(body_rows)} | promoted {promoted_n} | carried {len(carried_rows)} | body blocks {len(blocks)} | linked blocks {len(linked)} | invalid cells {invalid}` and the totals line "
                 f"`worker records: {len(own_rows)} | body: {kinds['body']} | merged: {kinds['merged']} | withdrawn: {kinds['withdrawn']} | unverifiable: {kinds['unverifiable']} | promoted: {promoted_n} | carried: {len(carried_rows)}{f' | refuted: {len(refuted_rows)}' if refuted_rows else ''}` as the table and the body stand now — after this set's other fixes, each number re-counted from them"
                 + (", the table first holding one row per worker record under its own id (`worker record ids` below)" if not ids_ok else ""))
    emit("close-out equations", ("pass" if eq and not failed else f"fail: {', '.join(failed) or 'lines absent'}") + f" (table {len(table_rows)}, file records {file_records}, record headings without a severity {malformed_headings}, body rows {len(body_rows)}, merged {len(merged_rows)}, carried {len(carried_rows)})", None, bool(eq) and not failed, fix_c)
    fix_i = []
    if unknown:
        pre = unknown[0].rsplit("/", 1)[0].upper() + "/"
        heads_free = [r_ for r_ in unrowed if r_.upper().startswith(pre)]
        fix_i.append(f"{len(unknown)} row id(s) name no worker record — a row's id is `<lens>/p<n>/` and the VULN id its record's own heading states: `{unknown[0]}` is none of them"
                     + (f"; the headings of that file with no row read {', '.join('`' + r_.rsplit('/', 1)[1] + '`' for r_ in heads_free[:4])}{' …' if len(heads_free) > 4 else ''}" if heads_free else ""))
    if unrowed and not unknown:
        fix_i.append(f"{len(unrowed)} worker record(s) have no row: {', '.join('`' + r_ + '`' for r_ in unrowed[:4])}{' …' if len(unrowed) > 4 else ''}")
    if multi:
        fix_i.append(f"{', '.join(f'`{i}` is on {n_} rows' for i, n_ in multi[:3])}{' …' if len(multi) > 3 else ''}: one row per worker record — the record's own finding stays its `body` row, and a finding at another of its entry points is a `promoted` row, worker record cell `promoted/<lens>/p<n>`")
    if fix_i and (unknown or unrowed or multi):
        fix_i.append("the table is rebuilt from the worker files, one row per record under that id, each body block's `Worker record:` line naming its row's id, and every count re-derived from it")
    emit("worker record ids", f"{len(set(row_ids) & set(rec_ids))}/{len(rec_ids)} records have a row under their own id | ids naming no record {len(unknown)} | records with no row {len(unrowed)} | ids on more rows than records {len(multi)}" + (f" | ids two records share {len(rec_dups)} ({', '.join(rec_dups[:3])})" if rec_dups else ""),
         None, ids_ok, "; ".join(fix_i) or None)

    # 32. withdrawn lines — a withdrawn row is Step 6's WITHDRAWN or a failed citation, said once in the appendix, never a
    # duplicate (which is `merged`); an unverifiable row's UNV entry stands in the Unverifiable section
    wd_ids = {cell_id(c).upper(): cell_id(c) for c in table_rows if c[4].lower() == "withdrawn"}
    wd_lines = [(re.sub(r"[`*]", "", n_).rstrip(":;,."), why) for n_, why in re.findall(
        r"(?im)^\s*`?(?:>\s*)*(?:[-*+]|\d+[.)])?\s*\**withdrawn\**:?\**\s*\**`?([a-z][a-z-]*/p\d+/[^`*\s—–]+)`?\**\s*(?:—|–|--|-)?\s*(.*)$", appendix)]
    wd_named = {n_.upper() for n_, _ in wd_lines}
    wd_rows_n = Counter(cell_id(c).upper() for c in table_rows if c[4].lower() == "withdrawn")
    wd_twice = sorted({x_ for x_, _ in wd_lines if [y_.upper() for y_, _ in wd_lines].count(x_.upper()) > wd_rows_n.get(x_.upper(), 1)})
    dup_word = re.compile(r"(?i)\bduplicates?\s+(?:of|to)\b|\bsame finding as\b")  # a merge given as a withdrawal
    wd_dup = [n_ for n_, why in wd_lines if dup_word.search(why)]
    wd_bad_reason = [n_ for n_, why in wd_lines if n_ not in wd_dup and not re.search(r"(?i)\bstep[\s-]*6\b|\bcitation", why)]
    wd_missing = [v_ for k_, v_ in wd_ids.items() if k_ not in wd_named]
    wd_extra = [n_ for n_ in wd_named if n_ not in wd_ids]
    unv_nums = {int(n_) for n_ in re.findall(r"UNV-(\d+)", report)}
    unv_rows = [c for c in table_rows if c[4].lower() == "unverifiable"]
    unv_missing = [cell_id(c) for c in unv_rows if not (re.search(r"UNV-(\d+)", c[6]) and int(re.search(r"UNV-(\d+)", c[6]).group(1)) in unv_nums)]
    emit("withdrawn lines", f"{len(wd_ids) - len(wd_missing)}/{len(wd_ids)} withdrawn rows have their line | lines naming no withdrawn row {len(wd_extra)} | reasons neither Step 6 nor citation {len(wd_bad_reason)} | reasons naming a duplicate {len(wd_dup)} | records with two lines {len(wd_twice)} | unverifiable rows without their UNV entry {len(unv_missing)}",
         None, not wd_missing and not wd_extra and not wd_bad_reason and not wd_dup and not wd_twice and not unv_missing,
         "; ".join(x for x in (
             (f"each withdrawn row has one appendix line `withdrawn: <worker record> — <Step 6 | citation>: <one line>` — none for {', '.join('`' + v_ + '`' for v_ in wd_missing[:4])}{' …' if len(wd_missing) > 4 else ''}") if wd_missing else "",
             (f"a record that repeats a finding is not withdrawn: {', '.join('`' + v_ + '`' for v_ in wd_dup[:4])}{' …' if len(wd_dup) > 4 else ''} — with the entry point, sink and class of a `body` row it is `merged` into that row; at an entry point of its own it is a `body` row") if wd_dup else "",
             (f"a withdrawn line states Step 6's WITHDRAWN or the failed citation: {', '.join('`' + v_ + '`' for v_ in wd_bad_reason[:4])}{' …' if len(wd_bad_reason) > 4 else ''}") if wd_bad_reason else "",
             (f"a `withdrawn:` line names a row that is not withdrawn: {', '.join('`' + v_ + '`' for v_ in wd_extra[:4])}") if wd_extra else "",
             (f"a withdrawn record has one line: {', '.join('`' + v_ + '`' for v_ in wd_twice[:4])}") if wd_twice else "",
             (f"an unverifiable row's `UNV-<nnn>` entry stands in the Unverifiable section: none for {', '.join('`' + v_ + '`' for v_ in unv_missing[:4])}{' …' if len(unv_missing) > 4 else ''}") if unv_missing else "",
         ) if x) or None)

    # 33. promoted rows — a promoted row is a STEP X or buried-sink promotion, or another entry point of a multi-route
    # record; one at the entry point, sink and class a withdrawn or unverifiable record names as its own is that record's
    # finding under another row. A record naming several entry points is read by none of them.
    def rec_site(pth_: Path, vid: str):
        """A worker record's own entry point (when it names one), its `File:` line's sinks [(file, line)] and its
        `Reference:` line's classes — the stems first, every name when none is a stem — read inside the record only."""
        txt_ = worker_text.get(pth_, "")
        for b_ in re.split(r"\n(?=(?:#+ )?\[(?i:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*|CONFIRMED|LIKELY)\] VULN-)", txt_):
            h_ = ANY_RECORD_RX.match(b_)
            if not h_ or h_.group(2).upper() != vid.upper():
                continue
            b_ = re.split(r"\n(?=#{1,2} |<!-- LLM-SAST-COMPLETE)", b_, maxsplit=1)[0]  # a record ends at a section heading
            f_l = re.search(r"^\**Files?:\**\s*(.+)$", b_, re.M)
            sinks_ = [(rel(a_).lstrip("./"), int(n_)) for a_, n_ in re.findall(r"`?([^\s`|:,;]+):(\d+)", f_l.group(1))] if f_l else []
            r_l = re.search(r"^\**Reference:\**\s*(.+)$", b_, re.M)
            names_ = re.findall(r"(?:^|[/`\s,])([a-z0-9_]+)\.md\b", r_l.group(1)) if r_l else []
            cls_ = [n_ for n_ in names_ if n_ in stems] or names_
            e_m = re.search(r"^\**Entry point:\**\s*(.+)$", b_, re.M)
            if sinks_ and cls_:
                return (ep_single(e_m.group(1)) if e_m else None), sinks_, cls_
        return None
    same_file = lambda a_, b_: a_ == b_ or a_.endswith("/" + b_) or b_.endswith("/" + a_)
    promoted_rows = [c for c in table_rows if c[4].lower() == "promoted"]
    pr_sites = []
    for c in promoted_rows:
        m_s = re.search(r"([^\s`|:,;]+):(\d+)", re.sub(r"[`*]", "", c[2]))
        if m_s:
            pr_sites.append((ep_id(c[1]), rel(m_s.group(1)).lstrip("./"), int(m_s.group(2)), c[3], c[6]))
    shadowed = []
    for c in table_rows:
        if c[4].lower() not in ("withdrawn", "unverifiable"):
            continue
        m_id = re.match(r"^([a-z][a-z-]*)/(p\d+)/(\S+)$", cell_id(c), re.I)
        pth_ = cache / f"deep-{m_id.group(1).lower()}-{m_id.group(2).lower()}-results.md" if m_id else None
        site = rec_site(pth_, m_id.group(3)) if m_id and pth_ in worker_text and rec_seen.get(cell_id(c).upper(), 1) == 1 else None
        if site and site[0]:
            hit = next((pr for pr in pr_sites if pr[0] == site[0] and pr[3] in site[2] and any(same_file(pr[1], f_) and abs(pr[2] - n_) <= 3 for f_, n_ in site[1])), None)
            if hit:
                shadowed.append((cell_id(c), hit[4], f"{site[1][0][0]}:{site[1][0][1]}", site[2][0]))
    # a promoted row stands at an entry point no body row at its sink and class stands at: one whose entry point cell
    # names a body row's `## Entry points` entry, at the same sink line and class, counts that row's finding twice. The
    # list is the authority: a direct call of a triggered function is no entry of its own unless the list holds its
    # handler's `direct-invocation branch` (base skill, finding identity), so a cell naming the function's
    # direct call reads as its trigger's entry when it names one — a name two list entries share reads as the cell
    # itself, a miss and never a flag; two cells that name none (`unavailable`) are not read
    body33 = {}
    for c in table_rows:
        m_b = re.search(r"([^\s`|:,;]+):(\d+)", re.sub(r"[`*]", "", c[2])) if c[4].lower() == "body" and not unavail(c[1]) else None
        if m_b:
            body33.setdefault((ep_id(c[1]), rel(m_b.group(1)).lstrip("./"), int(m_b.group(2)), c[3].strip("` ").lower()), c[6])
    pr33 = []
    for c in promoted_rows:
        m_s = re.search(r"([^\s`|:,;]+):(\d+)", re.sub(r"[`*]", "", c[2])) if not unavail(c[1]) else None
        if m_s:
            pr33.append(((ep_id(c[1]), rel(m_s.group(1)).lstrip("./"), int(m_s.group(2)), c[3].strip("` ").lower()), c[6]))
    twin33 = [(p_, body33[k_]) for k_, p_ in pr33 if k_ in body33 and body33[k_].upper() != p_.upper()]
    # a promoted cell names its entry as the list does: one citing only files of the target that do not hold the list
    # entry it is read as — found by its name alone — names a direct call or another unlisted part of a listed function;
    # both sides compared target-relative, a leading `./` or dot dropped from each, and a cited host:port or URL no file
    offlist33 = []
    for c in promoted_rows:
        if unavail(c[1]):
            continue
        e_ = ep_id(c[1])
        cited_ = [rel(m_.group(1)).lstrip("./") for m_ in re.finditer(r"([\w./-]+\.\w+):(\d+)", re.sub(r"\s+", " ", c[1].replace("`", "")))]
        cited_ = [f_ for f_ in cited_ if f_ and (target / f_).is_file()]
        if isinstance(e_, tuple) and cited_:
            ef_ = e_[0].lstrip("./")
            if not any(ef_ == f_ or ef_.endswith("/" + f_) for f_ in cited_):
                offlist33.append((c[6], cited_[0], f"{e_[0]}:{e_[1]}"))
    off_ids33 = {o_[0].upper() for o_ in offlist33}
    # two promoted rows at one entry, sink and class are one finding twice as well: the first in table order stands, a
    # row whose cell names its entry as the list does before one citing a line no list entry holds
    first33, ptwin33 = {}, []
    for k_, p_ in sorted(pr33, key=lambda t_: t_[1].upper() in off_ids33):
        if k_ in body33:
            continue  # read against the body row above
        if k_ in first33 and first33[k_].upper() != p_.upper():
            ptwin33.append((p_, first33[k_]))
        first33.setdefault(k_, p_)
    emit("promoted rows", f"{len(promoted_rows)} | at a withdrawn or unverifiable record's own entry point, sink and class {len(shadowed)}"
         + (f" | at a body row's entry point, sink and class {len(twin33)}" if twin33 else "")
         + (f" | at another promoted row's entry point, sink and class {len(ptwin33)}" if ptwin33 else "")
         + (f" | citing a line no list entry holds {len(offlist33)}" if offlist33 else ""), None, not shadowed and not twin33 and not ptwin33 and not offlist33,
         "; ".join(x_ for x_ in (
             (f"{', '.join(f'`{b_}` stands at `{a_}`' + chr(39) + f's own entry point, sink `{s_}` and class `{k_}`' for a_, b_, s_, k_ in shadowed[:3])}{' …' if len(shadowed) > 3 else ''} — a worker record's own finding is its own row: that row is `body` with the finding's VULN id and the promoted row goes; a promoted row is a STEP X or buried-sink promotion, or another entry point of a multi-route record") if shadowed else "",
             (f"{', '.join(f'promoted `{p_}` stands at body `{b_}`' + chr(39) + 's entry point, sink and class' for p_, b_ in twin33[:3])}{' …' if len(twin33) > 3 else ''} — one finding counted twice: an entry point cell is read as the `## Entry points` entry it names, and a direct call of a triggered function is no entry of its own (a `direct-invocation branch` the list holds is one) — the promoted row goes, with its block, its caller named in the body block's `Description:`; a body row whose worker record names the promoted row's entry beside another takes that other one in its cell") if twin33 else "",
             (f"{', '.join(f'promoted `{p_}` stands at promoted `{b_}`' + chr(39) + 's entry point, sink and class' for p_, b_ in ptwin33[:3])}{' …' if len(ptwin33) > 3 else ''} — one finding counted twice: the first stands and the other goes, with its block") if ptwin33 else "",
             (f"{', '.join(f'promoted `{p_}` cites `{f_}`, a file that does not hold its `## Entry points` entry `{e_}`' for p_, f_, e_ in offlist33[:3])}{' …' if len(offlist33) > 3 else ''} — a promoted row's cell names its entry as the list does: write it as that entry, its `<file:line>` and name, or as the `direct-invocation branch` the list holds; a direct call of a triggered function is no entry of its own (its caller named in the `Description:` of the trigger's finding), so its finding is the trigger's row") if offlist33 else "",
         ) if x_) or None)

    # 34. withdrawn cells — a withdrawn or unverifiable row's sink and class cells are its record's own `File:` and
    # `Reference:`, so what was withdrawn stays readable; a row whose cells were replaced says nothing of its finding
    cell_off = []
    for c in table_rows:
        if c[4].lower() not in ("withdrawn", "unverifiable"):
            continue
        m_id = re.match(r"^([a-z][a-z-]*)/(p\d+)/(\S+)$", cell_id(c), re.I)
        pth_ = cache / f"deep-{m_id.group(1).lower()}-{m_id.group(2).lower()}-results.md" if m_id else None
        site = rec_site(pth_, m_id.group(3)) if m_id and pth_ in worker_text and rec_seen.get(cell_id(c).upper(), 1) == 1 else None
        m_c = re.search(r"([^\s`|:,;]+):(\d+)", re.sub(r"[`*]", "", c[2]))
        if site:
            sink_ok = bool(m_c) and any(same_file(rel(m_c.group(1)).lstrip("./"), f_) and abs(int(m_c.group(2)) - n_) <= 3 for f_, n_ in site[1])
            stem_named = any(k_ in stems for k_ in site[2])
            cls_ok = (c[3] in site[2]) or not stem_named or (c[4].lower() == "unverifiable" and c[3].lower() == "unclassified" and not stem_named)
            if not (sink_ok and cls_ok):
                shown_ = c[2] if len(c[2]) <= 60 else c[2][:57] + "…"
                cell_off.append((cell_id(c), f"{site[1][0][0]}:{site[1][0][1]}", site[2][0], shown_, c[3]))
    emit("withdrawn cells", f"{len([c for c in table_rows if c[4].lower() in ('withdrawn', 'unverifiable')]) - len(cell_off)} of the withdrawn and unverifiable rows keep their record's sink and class | rows that do not {len(cell_off)}", None, not cell_off,
         (f"a withdrawn or unverifiable row keeps its worker record's own sink and class: {', '.join(f'`{a_}` reads `{d_}` / `{e_}` where its record states `{b_}` / `{k_}`' for a_, b_, k_, d_, e_ in cell_off[:3])}{' …' if len(cell_off) > 3 else ''}") if cell_off else None)

    # 37. record cells — a body or merged row's sink and class cells are its worker record's own: the first sink of its
    # `File:` line, the same `path:line` read by first line, and a stem its `Reference:` names; a body row's block keeps
    # them too. A merge read from cells the writer rewrote proves nothing: one write rewrote 213 rows onto one sink and class,
    # merged them into one body row, and every other item read the table it had made consistent with itself. The
    # entry-point cell is read too, by ep_meets: records name their entry point in forms the plan's list does not, so the
    # cell is met by what names it, never by equality — one writer put `worker entry point` in all 328 of its rows.
    def rc_path(p_: str) -> str:
        return re.sub(r"^(?:\./)+", "", rel(p_.strip()))  # target-relative, `./` dropped — never a leading dot of the name
    def rc_same(cell_p: str, rec_p: str) -> bool:
        # a record written absolute from another checkout is met by its target-relative tail; a bare file name is not a path
        return cell_p == rec_p or (rec_p.startswith("/") and rec_p.endswith("/" + cell_p)) or (cell_p.startswith("/") and cell_p.endswith("/" + rec_p))
    def rc_read(b_: str):
        """(first sink (path, line) of the `File:` line, or None; the `Reference:` line's stems — every name when none is a
        stem; the names as written) — backticks and bold aside."""
        f_l = re.search(r"^\**Files?:\**\s*(.+)$", b_, re.M)
        f_s = re.search(r"([^\s|:,;()]+):(\d+)", re.sub(r"[`*]", "", f_l.group(1))) if f_l else None
        r_l = re.search(r"^\**Reference:\**\s*(.+)$", b_, re.M)
        names_ = re.findall(r"(?:^|[/\s,(])([a-z0-9_]+)\.md\b", re.sub(r"[`*]", "", r_l.group(1))) if r_l else []
        return ((rc_path(f_s.group(1)), int(f_s.group(2))) if f_s else None), ([n_ for n_ in names_ if n_ in stems] or names_), names_
    def rc_records(pth_: Path, vid: str) -> list:
        """Every record under id `vid` in its worker file — a worker that repeats an id has each of them read."""
        out_ = []
        for b_ in re.split(r"\n(?=(?:#+ )?\[(?i:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*|CONFIRMED|LIKELY)\] VULN-)", worker_text.get(pth_, "")):
            h_ = ANY_RECORD_RX.match(b_)
            if h_ and h_.group(2).upper() == vid.upper():
                blk_ = re.split(r"\n(?=#{1,2} |<!-- LLM-SAST-COMPLETE)", b_, maxsplit=1)[0]
                e_l = re.search(r"^\s*(?:[-*+]\s+)?\**Entry point\**:\**\s*(.+)$", blk_, re.M | re.I)
                out_.append(rc_read(blk_) + ((e_l.group(1).strip() if e_l else None), blk_))
        return out_
    def rc_id_lines(pth_: Path, vid: str) -> str:
        # the lines naming the id outside its heading: a disposition list naming the record's entry points
        return "\n".join(l_ for l_ in worker_text.get(pth_, "").splitlines() if not ANY_RECORD_RX.match(l_) and re.search(r"(?<![A-Za-z0-9-])" + re.escape(vid) + r"(?![A-Za-z0-9-])", l_, re.I))
    def rc_meets(sink_cell: str, cls_cell: str | None, rec) -> bool:
        m_c = re.search(r"([^\s|:,;()]+):(\d+)", re.sub(r"[`*]", "", sink_cell or ""))
        stem_named = any(k_ in stems for k_ in rec[1])
        return (bool(m_c) and rec[0] is not None and rc_same(rc_path(m_c.group(1)), rec[0][0]) and int(m_c.group(2)) == rec[0][1]
                and (cls_cell is None or cls_cell in rec[1] or not stem_named))
    rc_off, blk_off, ep_off, rc_n, rc_none = [], [], [], 0, 0
    blk_off_ids: set = set()  # the body blocks whose `File:` or `Reference:` is not their record's: item (46) defers to this item
    blk_off_rec: dict = {}  # and each such block's record sink (path, line), which item (46) reads before it says "render again"
    rc_pe37: list = []  # rows whose record's own sink lies past the end of its file: withdrawn, never copied from the record
    rc_pe37_rows = 0  # of them, rows whose cells are not the record's

    def rec_pe37(rec_, rid_=None):
        """For a record whose `File:` sink lies past the end of a file of the target: its row's hint (with `rid_`), or True."""
        n_ = target_lines(rec_[0][0]) if rec_ and rec_[0] else None
        if n_ is None or rec_[0][1] <= n_:
            return None
        return True if rid_ is None else f"`{rid_}`'s record states its sink `{rec_[0][0]}:{rec_[0][1]}`, past the end of that file's {n_} lines: the row is `withdrawn` with a `citation:` line, as item (46) reads it — never copied from the record"
    rc_rows: dict[str, list] = {}
    for c in table_rows:
        if c[4].lower() in ("body", "merged"):
            rc_rows.setdefault(cell_id(c).upper(), []).append(c)
    for rid, rows_ in rc_rows.items():
        m_id = re.match(r"^([a-z][a-z-]*)/(p\d+)/(\S+)$", cell_id(rows_[0]), re.I)
        pth_ = cache / f"deep-{m_id.group(1).lower()}-{m_id.group(2).lower()}-results.md" if m_id else None
        recs_ = rc_records(pth_, m_id.group(3)) if m_id and pth_ in worker_text else []
        if not recs_:
            rc_none += len(rows_)  # a row naming no record is item (31)'s, as is a row beyond its id's records
            continue
        free_ = list(range(len(recs_)))  # one row per record: two rows under a repeated id meet two records
        for c in rows_:
            if not free_:
                rc_none += 1  # more rows than records under the id: item (31)'s
                continue
            rc_n += 1
            hit_ = next((k_ for k_ in free_ if rc_meets(c[2], c[3], recs_[k_])), None)
            if hit_ is not None:
                free_.remove(hit_)
                rec = recs_[hit_]
                # a record that states no `Entry point:` line leaves the writer the list's entry or `unavailable`: not read
                flow_ = re.search(r"^\s*(?:[-*+]\s+)?\**Flow\**:\**\s*(.+)$", rec[4], re.M | re.I)
                # the sink cell copied into the entry point column names the sink, unless the record's entry point is that line
                sink_copy = ep_norm(c[1]) == ep_norm(c[2]) and not (rec[3] and rec[0] and re.search(re.escape(Path(rec[0][0]).name) + r":" + str(rec[0][1]) + r"(?!\d)", re.sub(r"[`*]", "", rec[3])))
                # a merged row carries its body row's cell — the merge names one entry point, and item (4) reads merges
                if c[4].lower() == "body" and rec[3] and (sink_copy or not ep_meets(c[1], rec[3], flow_.group(1) if flow_ else "", rc_id_lines(pth_, m_id.group(3)), rec[0])):
                    ep_off.append(f"`{cell_id(c)}` reads `{c[1] if len(c[1]) <= 50 else c[1][:47] + '…'}` where its record states `Entry point: {rec[3] if len(rec[3]) <= 70 else rec[3][:67] + '…'}`")
            else:
                rec = recs_[free_[0]]
                if rec[0] is None:
                    rc_off.append(f"`{cell_id(c)}`'s record states no `path:line` on its `File:` line — the row is `unverifiable` with that reason, its block in the Unverifiable section")
                elif rec_pe37(rec):
                    rc_pe37.append(rec_pe37(rec, cell_id(c)))
                    rc_pe37_rows += 1
                else:
                    rc_off.append(f"`{cell_id(c)}` reads `{c[2] if len(c[2]) <= 60 else c[2][:57] + '…'}` / `{c[3]}` where its record states `{rec[0][0]}:{rec[0][1]}` / `{' or '.join(rec[1]) or 'no reference file'}`")
            b_ = block_id.get(c[6].upper()) if c[4].lower() == "body" and rec[0] is not None else None
            if b_:  # the block against the record, whether or not the row's cells are right
                bs_, _, bn_ = rc_read(b_)
                if not (bs_ and rc_meets(f"{bs_[0]}:{bs_[1]}", None, rec)) or (any(k_ in stems for k_ in rec[1]) and not any(n_ in rec[1] for n_ in bn_)):
                    blk_off_ids.add(c[6].upper())
                    blk_off_rec[c[6].upper()] = rec[0]
                    if rec_pe37(rec):  # the record itself is past the end: its row's hint says withdraw; not re-rendered
                        if not any(x_.startswith(f"`{cell_id(c)}`'s record states its sink") for x_ in rc_pe37):
                            rc_pe37.append(rec_pe37(rec, cell_id(c)))
                        continue
                    blk_off.append(f"`{c[6]}` states `{(bs_[0] + ':' + str(bs_[1])) if bs_ else 'no path:line on its File: line'}` / `{bn_[0] if bn_ else 'no reference file'}` where its record `{cell_id(c)}` states `{rec[0][0]}:{rec[0][1]}` / `{' or '.join(rec[1])}`")
    fix37 = []
    if rc_off:
        fix37.append(("the table is rebuilt from the worker files, one row per record — " if len(rc_off) * 2 > rc_n else "")
                     + f"a body or merged row's sink and class cells are its worker record's own — the first sink of its `File:` line and a stem its `Reference:` names — never a sink or class the writer would choose: {', '.join(rc_off[:3])}{' …' if len(rc_off) > 3 else ''}"
                     + " — each cell is copied from its record, then every merge is read again: a record whose entry point, sink and class no body row carries is a body row with its own block, and the histogram, the close-out and the ledger are re-derived from what is written")
    if ep_off:
        fix37.append(("the table's entry point cells are rebuilt from the worker files — " if len(ep_off) * 2 > rc_n else "")
                     + f"a body row's entry point cell names its worker record's entry point, as the scan-plan's `## Entry points` list names it — its `<file:line>` and name — or in the record's own words when the list holds none, never a word no record wrote: {', '.join(ep_off[:3])}{' …' if len(ep_off) > 3 else ''}"
                     + " — and each body block's `Entry point:` line is its row's cell; then every merge is read again, a merge being one entry point, sink and class")
    if rc_pe37:
        fix37.append("; ".join(rc_pe37[:3]) + (" …" if len(rc_pe37) > 3 else ""))
    if blk_off:
        fix37.append(f"a body block's `File:` and `Reference:` are its row's record's: {', '.join(blk_off[:3])}{' …' if len(blk_off) > 3 else ''} — the block is rendered from its record")
    emit("record cells", f"{rc_n - len(rc_off) - rc_pe37_rows} of {rc_n} body and merged rows keep their record's sink and class | rows that do not {len(rc_off) + rc_pe37_rows} | body blocks off their record {len(blk_off)} | body entry point cells off their record {len(ep_off)}" + (f" | rows naming no record or beyond their id's records {rc_none} (item 31's)" if rc_none else ""),
         None, not rc_off and not rc_pe37 and not blk_off and not ep_off, "; ".join(fix37) or None)

    # 9. header versions
    analyzer = row(report, "Analyzer:") or ""
    wrapper_row = row(plan, "wrapper:") or ""
    matches = 0
    detail = []
    for s in SKILLS:
        v = frontmatter_version(skills / s) if skills else None
        in_analyzer = bool(v) and re.search(re.escape(s) + r"\s+v" + re.escape(v) + r"(?![0-9.])", analyzer) is not None
        matches += in_analyzer
        detail.append(f"{s.replace('llm-sast-scanner-', '').replace('llm-sast-scanner', 'scanner')} v{v}:{'ok' if in_analyzer else 'NO'}")
    wrap_v = frontmatter_version(skills / SKILLS[0]) if skills else None
    wrap_ok = bool(wrap_v) and corrected_str(plan, "wrapper:").endswith(f"v{wrap_v}")
    # the header's `Base SHA:` is the plan's base-sha, the sha alone: the next run's same-commit carry reads it to tell a
    # report of its commit, so a rewritten one would pass this report's findings over there
    plan_sha9 = plan_base_sha(plan)
    rep_sha9 = header_sha(report)
    sha_ok9 = rep_sha9 == plan_sha9 if plan_sha9 else True  # without a base-sha row there is nothing to copy
    if matches == 3 and sha_ok9 and not wrap_ok:
        PLAN_ONLY.add("header versions")
    emit("header versions", f"{matches}/3 in Analyzer ({'; '.join(detail)}) | wrapper row {'ok' if wrap_ok else 'NO'} | Base SHA {'ok' if sha_ok9 else (rep_sha9 or 'absent')}", None, matches == 3 and wrap_ok and sha_ok9,
         None if sha_ok9 else f"the header's `Base SHA:` line reads `Base SHA: {plan_sha9}`, the scan-plan's `base-sha`, the sha alone — the next run's same-commit carry reads it to tell a report of its commit")

    # 10. headings
    heads = re.findall(r"^## (.*)$", report, re.M)
    # a `## ` line inside a fenced block (a quoted Makefile) is the snippet's, not a heading, for the stray and duplicate
    # counts only: a writer's stray fence can put a real heading "inside", and it must never cost the Appendix its place
    heads_out = re.findall(r"^## (.*)$", unfenced(report), re.M)
    dups = sum(v - 1 for v in Counter(h.strip() for h in heads_out).values() if v > 1)
    appendix_last = bool(heads) and heads[-1].strip() == "Appendix" and heads.count("Appendix") == 1
    stray = sum(1 for h in heads_out if re.search(r"working notes|draft|scratch|todo", h, re.I))
    emit("headings", f"{len(heads)} | duplicates {dups} | appendix last {'yes' if appendix_last else 'NO'} | stray {stray}", None, dups == 0 and appendix_last and stray == 0)

    # 11. maturity worker records
    mat_line = row(appendix, "maturity:") or ""
    wr = ints(r"worker records (\d+) vs", mat_line)
    prev_pair = re.search(r"worker records \d+ vs (\S+) \| body \d+ vs (\S+)", mat_line)
    prev_co_early = closeout_of(read(target / max(earlier_listed, key=lambda x: x[0])[0])) if earlier_listed else None  # the newest listed report's line
    exp_prev = (str(prev_co_early[0]), str(prev_co_early[4])) if prev_co_early else ("n/a", "n/a")
    prev_ok = bool(prev_pair) and (prev_pair.group(1), prev_pair.group(2)) == exp_prev
    worker_rows = len(table_rows) - len(carried_rows) - len(refuted_rows)
    emit("maturity worker records", f"{worker_rows} (table rows {len(table_rows)} minus carried {len(carried_rows)}{f' and refuted {len(refuted_rows)}' if refuted_rows else ''}) | previous pair {exp_prev[0]}/{exp_prev[1]} {'stated' if prev_ok else 'NOT stated'}", str(wr[0]) if wr else "absent", bool(wr) and wr[0] == worker_rows and prev_ok,
         None if (bool(wr) and wr[0] == worker_rows and prev_ok) else f"the maturity line's pairs read `worker records {worker_rows} vs {exp_prev[0]} | body {len(blocks)} vs {exp_prev[1]}` — this run's table rows and body blocks against the newest earlier report's close-out")

    # 12. new keys
    rep_new = ints(r"new keys (\d+)", mat_line)
    run_lines = re.findall(r"^run .*new-confirmed=(\d+)", memory, re.M)
    run_new = int(run_lines[-1]) if run_lines else None
    # a finding's key is its `File:` sink: a new row at a line only an `Also at:` line names is a key of no finding
    file_keys12 = {corrected_key(c[3], c[2]) for c in table_rows if c[4].lower() in ("body", "merged", "promoted", "carried")}
    also_new12 = sorted(k for k in ledger_keys if is_new(k) and k not in file_keys12 and k in also_rows(("body", "merged", "promoted")))
    emit("new keys", f"{new_keys} (run line new-confirmed={run_new})" + (f" | rows written for `Also at:` lines {len(also_new12)}" if also_new12 else ""),
         str(rep_new[0]) if rep_new else "absent", bool(rep_new) and rep_new[0] == new_keys and run_new == new_keys and not also_new12,
         f"the memory run line's `new-confirmed=` and the maturity line's `new keys` are both {new_keys}, the ledger keys this run added — not the body-block count"
         + (f"; a line on a finding's `Also at:` line is no key of its own — its row is not written: {', '.join('`' + k_ + '`' for k_ in also_new12[:4])}{' …' if len(also_new12) > 4 else ''}" if also_new12 else ""))

    # 13. required lines
    missing = [p for p in REQUIRED_PREFIXES if not re.search(r"^" + re.escape(p), report, re.M)]
    emit("required lines", f"{len(REQUIRED_PREFIXES) - len(missing)}/{len(REQUIRED_PREFIXES)}" + (f" missing: {', '.join(missing)}" if missing else ""), None, not missing)

    # 14. verdicts carried / voided / bare
    prev_name = args.previous or (max(earlier_listed, key=lambda x: x[0])[0] if earlier_listed else None)  # newest by timestamp, whatever the row's order
    prev_text = read(target / prev_name) if prev_name else ""
    # the listed earlier reports' body blocks, oldest to newest (read once; item 26 reuses them)
    listed_names = {name for name, _ in earlier_listed}
    if earlier_listed:
        earlier_paths = sorted(q for q in target.glob("sast_report-*.md") if q.name in listed_names)
    else:
        earlier_paths = sorted(q for q in target.glob("sast_report-*.md") if not report_name or q.name < report_name)
    src_blocks = {}
    for q in earlier_paths:
        qb = read(q).split("\n## Appendix", 1)[0]
        src_blocks[q.name] = [sb for sb in re.split(r"\n(?=(?:#+ )?\[(?i:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\] VULN-)", qb) if RECORD_RX.match(sb)]
    # a sink's DOWNGRADED/DISPUTED verdict stands from the report that gave it until a later report's block at that sink
    # opens `STANDING — previous downgrade voided:`; a bare STANDING in between does not clear it
    # keyed by (sink, class): a verdict given to one class's finding at a line says nothing about another class's finding there
    VOID_OPEN = "STANDING — previous downgrade voided:"

    def stem_of(b: str) -> str:
        m_ = re.search(r"references/([a-z0-9_]+)\.md", b)
        return m_.group(1) if m_ else ""

    def dd_key(b: str):
        f_ = file_of(b)
        return (f_, stem_of(b)) if f_ else None

    prev_dd: dict[tuple, str] = {}
    for name in sorted(src_blocks):
        down: dict[tuple, str] = {}
        voids: set = set()
        for sb in src_blocks[name]:
            k_, a_ = dd_key(sb), adversarial(sb) or ""
            if not k_:
                continue
            if a_.startswith(("DOWNGRADED", "DISPUTED")):
                down[k_] = a_.split(" ", 1)[0]
            elif a_.startswith(VOID_OPEN):
                voids.add(k_)
        for k_ in voids - set(down):
            prev_dd.pop(k_, None)
        prev_dd.update(down)

    def honours(a_: str, k_) -> bool:
        return a_.startswith(prev_dd.get(k_, "\0")) or a_.startswith(("DOWNGRADED", "DISPUTED")) or a_.startswith(VOID_OPEN)

    carried = voided = bare = changed = 0
    carried_dd = sum(1 for b in carried_blocks if dd_key(b) in prev_dd)
    carried_stale = sum(1 for b in carried_blocks if dd_key(b) in prev_dd and not honours(adversarial(b) or "", dd_key(b)))
    for b in blocks:
        if b in carried_blocks:
            continue  # a carried block copies its source verdict; the join covers worker-derived rows only
        k_ = dd_key(b)
        if not k_ or k_ not in prev_dd:
            continue
        a_ = adversarial(b) or ""
        if a_.startswith(prev_dd[k_]):
            carried += 1
        elif a_.startswith(("DOWNGRADED", "DISPUTED")):
            changed += 1  # a downgrade re-judged as a dispute or the reverse: carried with a changed word, never bare
        elif a_.startswith("STANDING — previous downgrade voided:"):
            voided += 1
        else:
            bare += 1
    rep_vc = ints(r"^verdicts carried:? (\d+) \| voided (\d+)", appendix)  # a colon after the label is punctuation, not a different number
    emit("verdicts carried", f"{carried + changed} (same word {carried}, changed word {changed}) | voided {voided} | bare or not run {bare} | carried blocks at such sinks {carried_dd} (stale {carried_stale}) (standing downgraded sinks {len(prev_dd)} across {len(src_blocks)} earlier reports)",
         f"{rep_vc[0]} | voided {rep_vc[1]}" if rep_vc else "absent", bool(rep_vc) and rep_vc[0] == carried + changed and rep_vc[1] == voided and bare == 0 and carried_stale == 0)

    # 15. entry points dispositioned
    ep_sec = plan.split("## Entry points", 1)[1].split("\n## ", 1)[0] if "## Entry points" in plan else ""
    ep_lines = [l for l in ep_sec.splitlines() if ENTRY_LINE_RX.match(l)]
    rep_ep = ints(r"^entry points dispositioned (\d+)/(\d+)", appendix)
    # an entry point no lens named may stand on an `unanalyzed` line only when its partition holds a `worker not run:`
    # pair — a partition nobody finished; in a run whose workers all passed, every entry point is dispositioned
    ep_known = {l.split(" | ", 1)[0].strip().lstrip("|").strip().strip("`") for l in ep_lines}
    unanalyzed = re.findall(r"^(?:[-*] )?(\S+) \| .+ \| (p\d+) \| unanalyzed\s*$", appendix, re.M)
    notrun_parts = {pr.split("/", 1)[1] for pr in re.findall(r"^worker not run: ([a-z-]+/p\d+)", plan, re.M)}
    unan_ok = all(part in notrun_parts and loc.strip("`") in ep_known for loc, part in unanalyzed) and len({loc.strip("`") for loc, _ in unanalyzed}) == len(unanalyzed)
    ep_ok = (bool(rep_ep) and rep_ep[1] == len(ep_lines) and len(ep_lines) > 0 and unan_ok
             and rep_ep[0] + len(unanalyzed) == rep_ep[1])
    emit("entry points dispositioned", f"list {len(ep_lines)} | unanalyzed lines {len(unanalyzed)}" + (f" (partitions {', '.join(sorted({pt for _, pt in unanalyzed}))}; worker-not-run partitions {', '.join(sorted(notrun_parts)) or 'none'})" if unanalyzed else ""),
         f"{rep_ep[0]}/{rep_ep[1]}" if rep_ep else "absent", ep_ok)

    # 16. ledger rows at start — and, when the cache is an earlier run's, the copy holds the ledger that run left: one STEP 1
    # re-created project-memory.md from the template before copying it, and `0 over an empty copy` read as true
    start_val = corrected(plan, "ledger rows at start:")
    import datetime
    def mtime_of(q_: Path):
        try:
            return q_.stat().st_mtime
        except OSError:
            return None  # a dangling link or an unreadable file dates nothing
    try:
        # this run began at `started:` — or at its first dispatch line, were that earlier (a `started:` written later than
        # the run's own dispatch is a plan no file time can be read against)
        first_d = min(re.findall(r"^[a-z-]+/p\d+: \S+ (\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}) ", plan, re.M) or [started or ""])
        st_ts16 = datetime.datetime.strptime(min(started, first_d) if first_d else started, "%Y-%m-%d_%H-%M-%S").timestamp() if started else None
    except ValueError:
        st_ts16 = None
    STAMP16 = r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}"
    older_ = set()  # the stamps of earlier runs that dispatched: their at-dispatch copies, their previous-run directories
    try:
        cache_items = list(cache.iterdir()) if cache.is_dir() else []
    except OSError:
        cache_items = []
    for q_ in cache_items:
        m_ = re.match(r"^(scan-plan\.md\.at-dispatch-|previous-run-)(" + STAMP16 + r")$", q_.name)
        if not (m_ and started and m_.group(2) < started):
            continue
        try:
            if m_.group(1).startswith("scan-plan") and q_.is_file():
                older_.add(m_.group(2))
            elif m_.group(1) == "previous-run-" and q_.is_dir() and (any(q_.glob("deep-*-results.md")) or "workers dispatched:" in read(q_ / "scan-plan.md")):
                older_.add(m_.group(2))  # a directory holding an earlier run's workers or dispatched plan — a plan alone is a STEP 1 begun again
        except OSError:
            continue
    # an earlier run's working files still older than this run's start: its worker files, prompts and tables
    old_files = []
    try:
        cands_ = list(cache.glob("deep-*-results.md")) + list((cache / "prompts").glob("*.md")) + [cache / n_ for n_ in ("disposition-table.md", "handoff-table.md", "writer-prompt.md", "repair-prompt.md")]
    except OSError:
        cands_ = []
    for q_ in cands_:
        mt_ = mtime_of(q_)
        if mt_ is not None and st_ts16 is not None and mt_ < st_ts16:
            old_files.append(q_)
    prior_run = bool(older_ or old_files)  # the cache is an earlier run's, kept: deleting it for a fresh run leaves none of these
    prev_stamp = max(older_) if older_ else None
    # what that run left, in order: its plan's last recomputed `recheck: ledger rows after` (the copy STEP 1 kept); the newest
    # report on disk written after it began that states `ledger rows before <n> | after <m>`; its own pre-write copy (a run
    # stopped before its report left the memory as it found it)
    ref_ = None
    if prior_run:
        prev16 = read(cache / f"previous-run-{started}" / "scan-plan.md") if started else ""
        la_ = re.findall(r"^recheck: ledger rows after (\d+)", prev16, re.M)
        if la_:
            ref_ = (int(la_[-1]), f"previous-run-{started}/scan-plan.md's last recheck")
        else:
            reps_ = []
            try:
                reps_ = sorted((m_.group(0), q_.name, q_) for q_ in target.glob("sast_report-*.md") for m_ in [re.search(STAMP16, q_.name)]
                               if m_ and (not started or m_.group(0) < started) and (not prev_stamp or m_.group(0) > prev_stamp))
            except OSError:
                pass
            for _, _, q_ in reversed(reps_):
                a_ = ints(r"^ledger rows before \d+ \| after (\d+)", read(q_))
                if a_:
                    ref_ = (a_[0], f"{q_.name}'s write")
                    break
            if ref_ is None and prev_stamp and (cache / f"project-memory.md.pre-write-{prev_stamp}").exists():
                pc_ = read(cache / f"project-memory.md.pre-write-{prev_stamp}")
                ps_ = pc_.split("## Confirmed findings ledger", 1)[1].split("\n## ", 1)[0] if "## Confirmed findings ledger" in pc_ else ""
                ref_ = (sum(1 for l_ in ps_.splitlines() if LEDGER_RX.match(l_.strip())), f"project-memory.md.pre-write-{prev_stamp} (that run stopped before its report)")
    carry_ok = ref_ is None or len(copy_rows) == ref_[0]
    emit("ledger rows at start", f"{len(copy_rows)} over {copy_path.name if copy_path else 'absent'} ({'present' if copy_path and copy_path.exists() else 'ABSENT'})"
         + (f" | the cache is an earlier run's: {ref_[1]} left {ref_[0]} ledger rows" if ref_ else ""),
         str(start_val) if start_val is not None else "absent", start_val is not None and copy_path is not None and copy_path.exists() and start_val == len(copy_rows) and (not rep_led or rep_led[0] == len(copy_rows)) and carry_ok,
         (None if start_val == len(copy_rows) or copy_path is None or not copy_path.exists() else f"a STEP 1 line: the row reads `ledger rows at start: {len(copy_rows)}` — the count in {copy_path.name}, never in another run's copy, as STEP 1's `python3 <this skill's directory>/recheck.py --ledger-start` prints it" + (f" — and the row is corrected by appending ` → corrected {len(copy_rows)} at <date +%Y-%m-%d_%H-%M-%S>` to the end of its line, never by retyping it" if start_val is not None else "")) if carry_ok else f"a STEP 1 line: the pre-write copy holds {len(copy_rows)} ledger rows where {ref_[1]} left {ref_[0]} — project-memory.md was re-created, rewritten or removed before STEP 1 copied it, and the ledger it held is not this run's to carry; an existing memory is copied before anything reads or writes it, never initialised from the template, and a run that finds this restores the cache or starts fresh with the cache deleted")

    # 17. non-stem classes
    non_ledger = sum(1 for m in ledger if m.group(1) not in stems)
    # a record with no `Reference:` has no class to give; its row is `unverifiable` with the literal class `unclassified`
    non_table = sum(1 for c in table_rows if c[3] not in stems and not (c[4].lower() == "unverifiable" and c[3].lower() == "unclassified"))
    emit("non-stem classes", f"{non_ledger}/{non_table} (stems {len(stems)})", None, bool(stems) and non_ledger == 0 and non_table == 0)

    # 18. rekeyed to stem — copy rows under a title class whose sink now stands under a stem, and their brief trail
    ledger_by_sink: dict[str, list] = {}
    for m in ledger:
        ledger_by_sink.setdefault(canon(m.group(2)), []).append(m)
    rekeyed = trail_missing = 0
    for m in copy_rows:
        old_cls, sink = m.group(1), canon(m.group(2))
        if old_cls in stems:
            continue
        # the ledger's stem rows at the sink, and a row this run archived there (a refuted key's), its trail kept
        now_rows = [r for r in ledger_by_sink.get(sink, []) if r.group(1) in stems] + [r for r in arch_moved if canon(r.group(2)) == sink and r.group(1) in stems]
        if now_rows:
            rekeyed += 1
            if not any(f" was {old_cls}" in r.group(3).split(" | ")[0] for r in now_rows):
                trail_missing += 1
    rep_rk = ints(r"rekeyed to stem (\d+)", appendix)
    emit("rekeyed to stem", f"{rekeyed} | trail missing {trail_missing}", str(rep_rk[0]) if rep_rk else "absent", bool(rep_rk) and rep_rk[0] == rekeyed and trail_missing == 0)

    # 19. checks — entry-point and line shares recomputed from the list and the manifests (the same function `--checks` runs)
    computed_ok, parts, _fails = partition_checks(plan, cache)
    checks_row = row(plan, "checks:") or ""
    stated = "pass" if checks_row.startswith("pass") else ("failed" if checks_row.startswith("failed") else "absent")
    computed = "pass" if computed_ok else "failed"
    # a failure is the skill's recorded outcome only when every one names a single file over the cap by itself
    irreducible = bool(_fails) and all("(one file: " in f_ for f_ in _fails) and re.sub(r"\s+", " ", checks_row) == f"failed — {'; '.join(_fails)} | {'; '.join(parts)}"
    emit("checks", f"{computed} ({'; '.join(parts) or 'no list or manifests'})" + (" — each failure one file over the cap by itself" if computed == "failed" and irreducible else ""),
         stated, computed == stated == "pass" or (computed == stated == "failed" and irreducible))

    # 20. STEP 1 rows unchanged — the scan plan above `workers dispatched:` against its copy taken at dispatch
    at_dispatch = cache / f"scan-plan.md.at-dispatch-{started}" if started else None
    if at_dispatch and at_dispatch.exists() and dispatched_row:
        def head(text: str) -> list[str]:
            m = re.search(r"^workers dispatched:.*$", text, re.M)
            lines = text[: m.start()].splitlines() if m else text.splitlines()
            # rows STEP 3 writes (`report:`, `continuity join:`) are not STEP 1 rows wherever the orchestrator puts them
            return [l for l in lines if l.strip() and not re.match(r"(report|continuity join):", l)]
        then, now = head(read(at_dispatch)), head(plan)
        then_set = set(then)
        edited = [l for l in now if l not in then_set and "→ corrected" not in l]
        now_set = set(now)
        removed = [l for l in then if l not in now_set and not any(n.startswith(l) and "→ corrected" in n for n in now)]
        emit("step 1 rows unchanged", f"{'yes' if not edited and not removed else 'NO'} | edited {len(edited)} | removed {len(removed)} | corrected appends {sum(1 for l in now if '→ corrected' in l)}", None, not edited and not removed)
    else:
        emit("step 1 rows unchanged", f"copy {at_dispatch.name if at_dispatch else 'scan-plan.md.at-dispatch-<started>'} ABSENT", None, False)

    # 21. maturity streak — derived from the previous run line, found-late and the body-block comparison
    prev_closeout = closeout_of(prev_text)
    prev_blocks = prev_closeout[4] if prev_closeout else None
    run_streaks = re.findall(r"^run .*maturity-streak=(\d+)", memory, re.M)
    prev_streak = int(run_streaks[-2]) if len(run_streaks) >= 2 else 0
    found_late = ints(r"found-late (\d+)", mat_line)
    this_blocks = closeout[4] if closeout else len(blocks)
    NEW_KEY_BOUND = 3
    # a partition nobody read says nothing about the union of findings: a `worker not run:` pair resets the streak
    not_run_pairs = sorted(set(re.findall(r"^worker not run: ([a-z-]+/p\d+)", plan, re.M)))
    derived = prev_streak + 1 if (found_late and found_late[0] == 0 and new_keys <= NEW_KEY_BOUND and not not_run_pairs) else 0
    rep_streak = ints(r"^maturity: streak (\d+)", appendix)
    # one run line per run: the memory holds exactly one more `run ` line than the pre-write copy (ten at most, the
    # oldest folded), so a writer that replaces the previous run's line instead of appending is seen
    run_now = len(re.findall(r"^run ", memory, re.M))
    run_copy = len(re.findall(r"^run ", copy_text, re.M)) if copy_text else 0
    run_ok = run_now == min(run_copy + 1, 10)
    header_mat = row(report, "Maturity:") or ""
    header_ok = bool(rep_streak) and header_mat.startswith(f"streak {rep_streak[0]} — ") and (("mature" in header_mat and "not mature" not in header_mat) == (derived >= 2))
    emit("maturity streak", f"{derived} (previous run line {prev_streak}, new keys {new_keys} bound {NEW_KEY_BOUND}, found-late {found_late[0] if found_late else 'absent'}, worker not run {len(not_run_pairs)}, body blocks {this_blocks} vs previous {prev_blocks}) | header {'consistent' if header_ok else 'INCONSISTENT'} | run lines {run_now} (copy {run_copy} + 1{' — replaced, not appended' if not run_ok else ''})",
         str(rep_streak[0]) if rep_streak else "absent", bool(rep_streak) and rep_streak[0] == derived and header_ok and run_ok)

    # 22. continuity join — the scan-plan's join line, its count, its listed ids and their cells
    join_m = re.search(r"^continuity join: (\d+) rows carry a previous verdict(?: — (.*))?$", plan, re.M)
    join_val = int(join_m.group(1)) if join_m else None
    join_tail = (join_m.group(2) or "") if join_m else ""
    join_fixes = re.findall(r"→ corrected (\d+) — (.*?)(?= at \S+|$)", join_tail)
    if join_fixes:  # a repair appended a correction: the corrected count and list are what the run settled on
        join_val = int(join_fixes[-1][0])
        join_tail = join_fixes[-1][1]
    join_lines = len(re.findall(r"^continuity join: ", plan, re.M))
    no_earlier = re.match(r"^(0|none)\b", (row(plan, "earlier-reports:") or "").lower()) is not None
    if join_m is None and no_earlier:  # nothing to join on a run without an earlier report: an absent line reads as 0
        join_val, join_lines = 0, 1
    listed = re.findall(r"VULN-[A-Za-z0-9-]*\d", join_tail.split("→ corrected")[0]) if join_m else []
    def carries(vid: str) -> bool:
        a = adversarial(block_id.get(vid.upper(), "")) or ""
        return a.startswith(("DOWNGRADED", "DISPUTED", "STANDING — previous downgrade voided:"))
    listed_bare = sum(1 for vid in listed if vid.upper() in block_id and not carries(vid))
    computed = carried + changed + voided + bare
    emit("continuity join", f"{computed} | listed {len(listed) if listed else 'ids absent'} | listed rows bare {listed_bare} | join lines {join_lines}{' | corrected' if join_fixes else ''}",
         str(join_val) if join_val is not None else "absent",
         join_val is not None and join_val == computed and len(listed) == join_val and listed_bare == 0 and join_lines == 1)

    # 23. sentinel — the report's last non-empty line
    last_line = next((l for l in reversed(report.splitlines()) if l.strip()), "")
    emit("sentinel", "present" if last_line.strip() == "<!-- LLM-SAST-COMPLETE -->" else f"ABSENT (last line: {last_line.strip()[:60]})", None, last_line.strip() == "<!-- LLM-SAST-COMPLETE -->")

    # 24. not re-found — at an unchanged commit, a copy row whose key holds no body record this run keeps its row and
    # its brief gains `not re-found <date>`; a row that lost its finding without the mark is a miss nobody recorded
    run_date = (started or "")[:10]
    carried_keys = {corrected_key(c[3], c[2]) for c in carried_rows}
    refuted_keys = {corrected_key(c[3], c[2]) for c in refuted_rows}  # withdrawn by Step 6 on a worker's line: item (47)'s, its row archived
    also_held = also_rows(("body", "merged", "promoted", "carried"))  # a key on a finding's (or a carried block's) `Also at:` line is held by it
    unfound = [k for k in {corrected_key(m.group(1), m.group(2)) for m in copy_rows} if k not in body_keys and k not in carried_keys and k not in refuted_keys and k not in also_held]
    marked = sum(1 for k in unfound if k in ledger_keys and any(f"not re-found {run_date}" in m.group(3) for m in ledger if key_of(m.group(1), m.group(2)) == k))
    gone = sum(1 for k in unfound if k not in ledger_keys)
    emit("not re-found", f"{marked}/{len(unfound)} rows without a body record this run carry `not re-found {run_date}` | rows gone from the ledger {gone}", None, marked == len(unfound) and gone == 0)

    # 25. wave rosters — rosters written at STEP 1 against the first-attempt dispatch lines grouped by start time
    rosters = [(int(k), re.findall(r"[a-z-]+/p\d+", body)) for k, body in re.findall(r"^wave roster (\d+):\s*(.*)$", plan, re.M)]
    dispatch = re.findall(r"^([a-z-]+/p\d+): \S+ (\S+) paths \d+/\d+(.*)$", plan, re.M)
    # first attempt = the earliest dispatch line of each pair, whatever its tail says (an orchestrator annotated a first
    # attempt with the reason it was later re-run, and the annotation dropped it from its wave)
    earliest: dict[str, str] = {}
    for pair, when, tail in dispatch:
        if pair not in earliest or when < earliest[pair]:
            earliest[pair] = when
    first = sorted(earliest.items())
    by_time: dict[str, list[str]] = {}
    # a first attempt belongs to the wave whose `started` time is the latest at or before its own, so a start retried after
    # a rate-limit interval stays in its wave; without a start time on every wave line, exact start times group them
    # one start per wave number: a wave written on two lines, or with a note before its `| started`, is one wave
    wave_nums: dict[int, str | None] = {}
    for l in plan.splitlines():
        m_w = re.match(r"^wave (\d+):", l)
        if m_w:
            st_ = re.search(r"\| started (\S+)", l)
            wave_nums[int(m_w.group(1))] = st_.group(1) if st_ else wave_nums.get(int(m_w.group(1)))
    wave_lines = list(wave_nums)
    wave_starts = sorted(v for v in wave_nums.values() if v)
    for pair, when in first:
        if wave_starts and len(wave_starts) == len(wave_lines):
            starts_before = [w for w in wave_starts if w <= when]
            key = starts_before[-1] if starts_before else when
        else:
            key = when
        by_time.setdefault(key, []).append(pair)
    waves_sorted = [by_time[w] for w in sorted(by_time)]
    all_pairs = [pr for _, r in rosters for pr in r]
    over_cap = sum(1 for _, r in rosters if len(r) > 15)
    matching = sum(1 for i, (_, r) in enumerate(sorted(rosters)) if i < len(waves_sorted) and sorted(r) == sorted(waves_sorted[i]))
    roster_ok = bool(rosters) and len(all_pairs) == len(set(all_pairs)) and over_cap == 0 and matching == len(rosters) == len(waves_sorted)
    # a wave's `complete` time, and the next wave's start, against its first attempts' files (pairs with no re-run line):
    # each file was sealed at or before its wave's completion and before the next wave started. File times are read only
    # when they are the run's own — every one written after the run's `started:` and before the time the report is named
    # for — never on a copied cache, whose files all carry the copy's time.
    local = lambda mt: time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime(mt))  # a file time as `date` prints it
    STAMP = r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}"
    wave_info: dict[int, list] = {}  # wave number -> [started, complete]; a wave written on two lines is one wave
    sep_co: dict[int, str] = {}  # a completion written on a line of its own, `wave <k> complete: <time>`
    for l in plan.splitlines():
        m_sep = re.match(r"^wave (\d+) complete:?\s*(" + STAMP + ")", l)
        if m_sep:
            sep_co[int(m_sep.group(1))] = m_sep.group(2)
            continue
        m_w = re.match(r"^wave (\d+):", l)
        if not m_w:
            continue
        st_m, co_m_ = re.search(r"\| started (" + STAMP + ")", l), re.search(r"\| complete (" + STAMP + ")", l)
        info = wave_info.setdefault(int(m_w.group(1)), [None, None])
        info[0] = st_m.group(1) if st_m else info[0]
        info[1] = co_m_.group(1) if co_m_ else info[1]
    for n_, co_ in sep_co.items():  # read for a wave that has its own `wave <k>:` line and no `complete` on it
        if n_ in wave_info and not wave_info[n_][1]:
            wave_info[n_][1] = co_
    first_t = [(pr, when) for pr, when in first if re.fullmatch(STAMP, when)]  # times compared as `date` prints them
    rerun_pairs = {pr for pr, _, tail in dispatch if "(re-run:" in tail}
    name_ts = re.search(STAMP, report_name or "")
    late_c, early_s, timing = [], [], None
    nums = sorted(wave_info)
    checked = {}  # wave number -> [(pair, file)]: a wave's first attempts lie from its `started` up to the next wave's
    for i_w, n_w in enumerate(nums):
        st_w = wave_info[n_w][0]
        nxt = nums[i_w + 1] if i_w + 1 < len(nums) else None
        nxt_st = wave_info[nxt][0] if nxt is not None else None
        if not st_w or (nxt is not None and not nxt_st):
            continue  # a wave without its own start, or before one: its bounds are not known
        checked[n_w] = [(pr, cache / f"deep-{pr.split('/')[0]}-{pr.split('/')[1]}-results.md") for pr, when in first_t
                        if when >= st_w and (nxt_st is None or when < nxt_st) and pr not in rerun_pairs]
    if checked and started and name_ts:
        mts = [f_.stat().st_mtime for fs in checked.values() for _, f_ in fs if f_.exists()]
        # stamps compare as strings in their one fixed-width form: no clock conversion, so no daylight-saving hour is
        # misread; `date` truncates to the second, so a file sealed after a stamp reads as a later string
        if mts and local(min(mts) + 1) >= started and local(max(mts)) < name_ts.group(0):
            timing = True
            for n_w, fs in checked.items():
                have = [(pr, f_.stat().st_mtime) for pr, f_ in fs if f_.exists()]
                if not have:
                    continue
                last_pr, last_mt = max(have, key=lambda x: x[1])
                co_w = wave_info[n_w][1]
                if co_w and local(last_mt) > co_w:
                    late_c.append(f"wave {n_w}'s `complete` reads {co_w}, before deep-{last_pr.replace('/', '-')}-results.md was sealed ({local(last_mt)})")
                later = [n_ for n_ in nums if n_ > n_w]
                nxt_st = wave_info[later[0]][0] if later else None
                if nxt_st and local(last_mt) > nxt_st:
                    early_s.append(f"wave {later[0]} started {nxt_st}, before wave {n_w}'s last file was sealed ({local(last_mt)})")
    # the lines a `wave <k>:` line summarizes stand beneath it; a second line of a wave already opened reopens nothing
    wave_of: dict[str, int | None] = {}  # pair -> the wave line its first attempt stands beneath
    late_pos, cur_w, seen_w = 0, None, set()
    for l in plan.splitlines():
        m_w = re.match(r"^wave (\d+):", l)
        if m_w:
            if int(m_w.group(1)) not in seen_w:
                cur_w = int(m_w.group(1))
                seen_w.add(cur_w)
            continue
        m_d = re.match(r"^([a-z-]+/p\d+): \S+ (\S+) paths \d+/\d+", l)
        if m_d and m_d.group(1) not in wave_of and earliest.get(m_d.group(1)) == m_d.group(2):
            wave_of[m_d.group(1)] = cur_w
            co_w = wave_info.get(cur_w, [None, None])[1]
            late_pos += bool(co_w and re.fullmatch(STAMP, m_d.group(2)) and m_d.group(2) >= co_w)
    # the same count by start times: where every wave's start is read and the plan's layout and its start times place a
    # line in different waves, either count is the definition's
    late_win, win_of = 0, {}
    all_st = bool(nums) and all(wave_info[n_][0] for n_ in nums)
    for i_w, n_w in enumerate(nums if all_st else []):
        st_w, co_w = wave_info[n_w]
        nxt_st = wave_info[nums[i_w + 1]][0] if i_w + 1 < len(nums) else None
        for pr, when in first_t:
            if when >= st_w and (nxt_st is None or when < nxt_st):
                win_of[pr] = n_w
                late_win += bool(co_w and when >= co_w)
    win_ok = all_st and any(win_of.get(pr) != wave_of.get(pr) for pr, _ in first_t)
    # a first attempt's dispatch line is written when its subagent starts, its time a `date` output read after its prompt
    # file was written and before its worker file was sealed. Read under the same guard: every such file's time the run's
    # own. A prompt written once one of its wave's workers had ended, once one of that wave's re-run prompts was written,
    # or once the run had rewritten, for a later re-run, a prompt whose worker had ended, may have been rebuilt since — an
    # original prompt precedes every worker of its wave — and is not read.
    early_d, after_d, odd_t, timing_d = [], [], [], False
    if started and name_ts:
        pf_ = {pr: cache / "prompts" / f"{pr.split('/')[0]}-{pr.split('/')[1]}.md" for pr, _ in first}
        wf_ = {pr: cache / f"deep-{pr.split('/')[0]}-{pr.split('/')[1]}-results.md" for pr, _ in first}
        pairs_f = [(pr, when) for pr, when in first if pr not in rerun_pairs]
        mts_d = [q.stat().st_mtime for pr, _ in pairs_f for q in (pf_[pr], wf_[pr]) if q.exists()]
        if mts_d and local(min(mts_d) + 1) >= started and local(max(mts_d)) < name_ts.group(0):
            timing_d = True
            ends: dict = {}  # wave -> the first time one of its workers ended or one of its re-run prompts was written
            for pr, _ in first:
                q = pf_[pr] if pr in rerun_pairs else wf_[pr]
                if q.exists():
                    w_ = wave_of.get(pr)
                    ends[w_] = min(ends.get(w_, q.stat().st_mtime), q.stat().st_mtime)
            # the first time the run rewrote a prompt after its own worker had ended, for a re-run dispatched then or later:
            # from then on it may rebuild any wave's — a sent prompt is written again only for a re-run
            rr_t = [t_ for _, t_, tl in dispatch if "(re-run:" in tl and re.fullmatch(STAMP, t_)]
            rebuilt0 = min((pf_[pr].stat().st_mtime for pr, _ in pairs_f if pf_[pr].exists() and wf_[pr].exists()
                            and local(pf_[pr].stat().st_mtime) > local(wf_[pr].stat().st_mtime)
                            and any(t_ >= local(pf_[pr].stat().st_mtime) for t_ in rr_t)), default=None)
            for pr, when in pairs_f:
                if not re.fullmatch(STAMP, when):
                    odd_t.append((pr, when))
                    continue
                p_m = pf_[pr].stat().st_mtime if pf_[pr].exists() else None
                w_t = local(wf_[pr].stat().st_mtime) if wf_[pr].exists() else None
                end_w = ends.get(wave_of.get(pr))
                if p_m is not None and local(p_m) > when and (end_w is None or p_m < end_w - 2) and (rebuilt0 is None or p_m < rebuilt0 - 2):
                    early_d.append((pr, when, local(p_m)))
                if w_t and when > w_t:
                    after_d.append((pr, when, w_t))
    stated_late = ints(r"^[-*]?\s*dispatch lines late:\s*(\d+)", appendix)
    late_ok = stated_late is None or stated_late[0] == late_pos or (win_ok and stated_late[0] == late_win)
    timing_txt = f" | completed before its files {len(late_c)} | started before the last wave's files {len(early_s)}" if timing else ""
    timing_txt += f" | dispatched before its prompt {len(early_d)} | dispatched after its file was sealed {len(after_d)}" if timing_d else ""
    timing_txt += f" | dispatch times not `date` outputs {len(odd_t)}" if odd_t else ""
    disp_msgs = [f"{', '.join(f'{pr} at {when}' for pr, when in odd_t[:3])}{' …' if len(odd_t) > 3 else ''} — dispatch time(s) not in the `date +%Y-%m-%d_%H-%M-%S` form, so their timing cannot be read"] if odd_t else []
    if early_d or after_d:
        disp_msgs.append("; ".join(
            ([f"{', '.join(f'{pr} at {when}' for pr, when, _ in early_d[:3])}{' …' if len(early_d) > 3 else ''} — dispatch line(s) timed before their prompt file was written ({early_d[0][2]}), a time composed rather than read"] if early_d else [])
            + ([f"{', '.join(f'{pr} at {when}' for pr, when, _ in after_d[:3])}{' …' if len(after_d) > 3 else ''} — dispatch line(s) timed after their worker file was sealed ({after_d[0][2]})"] if after_d else []))
            + " — a dispatch line is written as its subagent starts, its time a `date` output read then")
    comp_hint = ("; ".join(late_c + early_s) + " — a wave's `complete` time is a `date +%Y-%m-%d_%H-%M-%S` output read once its last file ends with its sentinel (the time `--roster <k>` prints then)") if (late_c or early_s) else ""
    hint_25 = "; ".join(x for x in (comp_hint, "; ".join(disp_msgs)) if x)
    emit("wave rosters", f"{matching}/{len(rosters) if rosters else 'absent'} waves match | over cap {over_cap} | dispatch groups {len(waves_sorted)} sized {','.join(str(len(w)) for w in waves_sorted)}" + timing_txt, None,
         roster_ok and not late_c and not early_s and not disp_msgs,
         (hint_25 + "; a STEP 2 line, left as it stands by the writer and named in its final message") if hint_25 else None)
    # the appendix's `dispatch lines late:` is the writer's line, counted from the plan as above
    emit("dispatch lines late", f"{late_pos} beneath their wave lines, {late_win} by start times" if win_ok and late_pos != late_win else str(late_pos),
         str(stated_late[0]) if stated_late else "absent", late_ok,
         None if late_ok else f"the appendix line reads `dispatch lines late: {late_pos}`, the first-attempt dispatch lines beneath each `wave <k>:` line timed at or after that wave's `complete`")

    # 26. carried — at an unchanged commit every open copy row without a body record this run is carried from the
    # report that last confirmed it, labelled; the label's source must exist and hold a block with the same class and sink
    # the copy's commit: its `last-scanned-sha`, or its last run line's sha for a copy whose header was dropped
    last_sha, sha_how = copy_commit(copy_text)
    sha_note = {"run line": " | commit read from the copy's newest run line (the copy has no last-scanned-sha)",
                "unreadable": " | the copy has no last-scanned-sha and no run line that names a commit"}.get(sha_how, "")
    base_sha = plan_base_sha(plan)  # the sha itself; `(HEAD)` or a note after it is ignored
    unchanged = same_commit(last_sha, base_sha)
    without_src = ints(r"^carried without source:\s*(\d+)", appendix)
    without_src = without_src[0] if without_src else 0
    if unchanged:
        open_copy = {corrected_key(m.group(1), m.group(2)) for m in copy_rows if m.group(3).split(" | ")[-1].strip() == "open"}
        judged_keys = {key_of(c[3], c[2]) for c in table_rows if c[4].lower() not in ("carried", "refuted")}  # any disposition a worker's record received
        # and every line its record's `Also at:` line names, at its class: one missing control's other sinks were judged with it
        judged_keys |= also_rows(tuple({c[4].lower() for c in table_rows} - {"carried", "refuted"}))
        # a `refuted` row is a source block Step 6 withdrew on a worker's `ledger refuted:` line: the key's other blocks are
        # still carried, and a key whose every block is withdrawn carries none (item 47 holds the rest)
        ref26 = Counter(corrected_key(c[3], c[2]) for c in refuted_rows)
        unjudged = sorted(k for k in open_copy if k not in judged_keys)
        # source: the newest earlier report holding blocks with the key's sink and a compatible reference stem; EVERY such
        # block is carried (one per entry point), each word for word — heading id, `Worker record:` and `Carried:` lines
        # aside, whitespace collapsed — and no source block twice
        # src_blocks: the listed earlier reports' blocks, built once for item 14 above
        # a source is a report written at this commit, its header's `Base SHA:` this run's base-sha: a report of another
        # commit judged other code — a row it confirmed that a changed-commit run left `open`, its sink's file unchanged,
        # may cite hops that moved since — so its blocks are no source (item 14 still reads them for verdicts)
        def report_sha(name_):
            return header_sha(read(target / name_))

        def at_this_commit(sha_):
            """A header sha naming this run's commit: the base-sha, or seven or more of its leading hex digits either way."""
            a_, b_ = (sha_ or "").lower(), (base_sha or "").lower()
            return bool(re.fullmatch(r"[0-9a-f]{7,64}", a_) and re.fullmatch(r"[0-9a-f]{7,64}", b_)) and (a_.startswith(b_) or b_.startswith(a_))
        src26 = {name_: bl_ for name_, bl_ in src_blocks.items() if at_this_commit(report_sha(name_))}

        def carry_norm(b):
            out = []
            for i, l in enumerate(b.split("\n## ", 1)[0].strip().splitlines()):
                s = " ".join(l.split())
                if not s:
                    continue
                if i == 0:
                    s = re.sub(r"^#+ ", "", s)
                    s = re.sub(r"VULN-[A-Za-z0-9-]*\d", "VULN-#", s, count=1)
                bare = s.lstrip("*")
                if bare.startswith("Worker record:") or bare.startswith("Carried: confirmed "):
                    continue
                out.append(s)
            return out

        def holds_key(sb, cls, sink):
            if file_of(sb) != sink:
                return False
            stem = re.search(r"references/([a-z0-9_]+)\.md", sb)
            # at a sink whose downgrade stands, only a block that honours it can be the source
            return (not stem or stem.group(1) == cls) and ((sink, cls) not in prev_dd or honours(adversarial(sb) or "", (sink, cls)))

        def key_candidates(k, pool=None):
            cls, sink = k.split("|", 1)
            pool = src26 if pool is None else pool
            for name in reversed(list(pool)):
                # a block citing a line past the end of a file of the target is no source: at an unchanged commit that line
                # never existed, so the block was never verified where it points
                cands = [carry_norm(sb) for sb in pool[name] if holds_key(sb, cls, sink) and not citations_of(sb)[1]]
                if cands:
                    return name, cands
            return None, []

        def past_end_sources(k):
            """The blocks of the key that cite past the end of a file and were passed over: in every listed report of this
            commit from the newest holding the key down to and including its source, or in all of them when it has none."""
            cls, sink = k.split("|", 1)
            passed = []
            for name in reversed(list(src26)):
                held = [sb for sb in src26[name] if holds_key(sb, cls, sink)]
                passed += [sb for sb in held if citations_of(sb)[1]]
                if any(not citations_of(sb)[1] for sb in held):
                    break
            return passed

        # a key the newest report holding it names only on the `Also at:` line of a block whose own key is carried this run —
        # one missing control an earlier report grouped — is carried with that block, never as a block of its own: the
        # older per-line blocks of a group are not carried back beside it
        unjudged_all = set(unjudged)

        def also_cover(k):
            """How the newest report holding the key holds it: None for a block at its own `File:` sink (carried as itself);
            ("with", fk) for the `Also at:` line of a block whose own key fk is carried this run — the key goes with that
            block; ("none", fk) for the `Also at:` line of a block whose key fk this run judged — the key has no source of
            its own, and no older per-line block is carried beside the group."""
            cls, sink = k.split("|", 1)
            for name in reversed(list(src26)):
                if any(holds_key(sb, cls, sink) for sb in src26[name]):
                    return None
                heads_ = []
                for sb in src26[name]:
                    stem = re.search(r"references/([a-z0-9_]+)\.md", sb)
                    if (stem and stem.group(1) != cls) or citations_of(sb)[1]:
                        continue
                    f_ = file_of(sb)
                    if f_ and canon(rel(sink)) in {canon(rel(s_)) for s_ in block_also(sb)}:
                        fk = corrected_key(cls, f_)
                        if fk != k:
                            heads_.append(fk)
                if heads_:
                    # any head carried this run carries it, whatever the blocks' order; a head refuted on a worker's line is
                    # carried by no block
                    carried_ = [fk for fk in heads_ if fk in unjudged_all and len(key_candidates(fk)[1]) > ref26.get(fk, 0)]
                    return ("with", carried_[0]) if carried_ else ("none", heads_[0])
            return None
        cover26 = {k: c_ for k in unjudged for c_ in [also_cover(k)] if c_}
        covered26 = {k: c_[1] for k, c_ in cover26.items() if c_[0] == "with"}
        nosrc_also26 = {k for k, c_ in cover26.items() if c_[0] == "none"}
        unjudged = [k for k in unjudged if k not in covered26]
        cand = {k: ((None, []) if k in nosrc_also26 else key_candidates(k)) for k in unjudged}
        computed_without = sum(1 for k in unjudged if not cand[k][1])
        past_end26 = sum(len(past_end_sources(k)) for k in unjudged if k not in nosrc_also26)
        expected = sum(max(0, len(c) - ref26.get(k, 0)) for k, (_, c) in cand.items())
        copy_lines: dict[str, set] = {}  # twin rows (`:20` and `:20-24`) share a canonical key: a carried row's line must be one of them
        for m in copy_rows:
            copy_lines.setdefault(corrected_key(m.group(1), m.group(2)), set()).add(m.group(0))
        verified = 0
        verbatim = 0
        claimed = set()
        unver26, unverb26, nosrc26_rows, pe26 = [], [], [], []  # the blocks that fail, with what their label or text should be, for the hint
        pe_norm_memo: dict = {}

        other_memo: dict = {}

        def other_note(k_):
            """Why a key with a block of its own in a listed report has no source: its source blocks are all in reports of another commit."""
            if k_ not in other_memo:
                if k_ in nosrc_also26:
                    other_memo[k_] = (f" — the newest report holding it names it only on the `Also at:` line of `{cover26[k_][1]}`'s block, which this "
                                      "run re-found or Step 6 withdrew: no older per-line block is carried beside that group")
                else:
                    other_memo[k_] = " — its only source blocks are in reports of another commit, whose `Base SHA:` is not this run's base-sha" if k_ and key_candidates(k_, src_blocks)[0] else ""
            return other_memo[k_]

        def pe_norms(k_):
            """The past-end blocks of a key's source report, as carry_norm reads them — or of every report of this commit
            holding it when it has no source. A carried copy of one of these is no source; a copy of a newer report's past-end block, the key
            carried from an older one, is re-copied from that report instead."""
            if k_ not in pe_norm_memo:
                cls_, sink_ = k_.split("|", 1)
                found_, all_pe = None, []
                for name in reversed(list(src26)):
                    held = [sb for sb in src26[name] if holds_key(sb, cls_, sink_)]
                    pe_ = [sb for sb in held if citations_of(sb)[1]]
                    all_pe += pe_
                    if len(pe_) < len(held):
                        found_ = pe_
                        break
                pe_norm_memo[k_] = [carry_norm(sb) for sb in (found_ if found_ is not None else all_pe)]
            return pe_norm_memo[k_]
        for b in carried_blocks:
            bad_b = citations_of(b)[1]
            # the row's `last-verified` cell is copied as the ledger holds it, spaces and all — one writer keeps it as
            # `<sha> <date>` — so the value runs, shortest first, to the ` at <sha> — not re-judged` that follows it
            lab = re.search(r"^Carried: confirmed (\S.*?) at (\S+) — not re-judged this run — source (\S+)", b, re.M)
            crow = next((c for c in carried_rows if c[6].upper() == RECORD_RX.match(b).group(2).upper()), None)
            key = corrected_key(crow[3], crow[2]) if crow else None  # canonical, class-corrected: a range or title-class cell still names the key
            newest, cands = (cand[key] if key in cand else key_candidates(key)) if key else (None, [])
            # the label's value is the row's `last-verified` cell in the copy and its sha the scan-plan's base-sha
            lv_cells = {ln.split(" | ")[-2].strip() for ln in copy_lines.get(key, set()) if len(ln.split(" | ")) >= 6} if key else set()
            label_ok = bool(lab) and lab.group(1) in lv_cells and lab.group(2) == base_sha
            bid26 = RECORD_RX.match(b).group(2)
            # a copy of a source block that is none: its key may keep other sources, but this block is not carried
            pe_copy = bool(bad_b) and key is not None and carry_norm(b) in pe_norms(key)
            if bad_b and (pe_copy or not newest):
                pe26.append(f"`{bid26}` cites `{bad_b[0][0]}`, past the end of that file's {bad_b[0][1]} lines" + (" — a copy of a block that is no source, beside its key's source blocks" if newest else ""))
            if label_ok and newest and lab.group(3) == newest:
                verified += 1
                hit26 = False
                if len(re.findall(r"^Carried: confirmed ", b, re.M)) == 1:
                    nb = carry_norm(b)
                    for i, cn in enumerate(cands):
                        if (key, i) not in claimed and cn == nb:
                            claimed.add((key, i))
                            verbatim += 1
                            hit26 = True
                            break
                if not hit26 and not pe_copy:
                    n_lab = len(re.findall(r"^Carried: confirmed ", b, re.M))
                    if n_lab > 1:
                        unverb26.append(f"`{bid26}` holds {n_lab} `Carried:` lines — one")
                    elif any(cn == carry_norm(b) for i, cn in enumerate(cands) if (key, i) in claimed):
                        unverb26.append(f"`{bid26}` repeats a block of `{key}` in {newest} another carried block already copies — each source block is carried once")
                    else:
                        unverb26.append(f"`{bid26}` differs from every unclaimed block of `{key}` in {newest}")
            elif not crow:
                unver26.append(f"`{bid26}` has no `carried` row")
            elif not newest:
                if not bad_b:  # a block citing past the end is told why above, with the legal path
                    nosrc26_rows.append(f"`{bid26}` at `{key}`" + (" — its row counts in `carried without source`" if key in cand else "") + other_note(key))
            else:
                want_lv = sorted(lv_cells)[0] if lv_cells else None
                if not lab:
                    got = re.search(r"^Carried:.*$", b, re.M)
                    unver26.append(f"`{bid26}` " + (f"reads `{got.group(0)[:160]}`" if got else "has no `Carried:` line") + f" where it reads `Carried: confirmed {want_lv or '<the copy row' + chr(39) + 's last-verified>'} at {base_sha} — not re-judged this run — source {newest}`")
                else:
                    # the value runs to the label's ` at `, spaces and all: one past 100 characters is quoted cut, the hint line under the reader's limit
                    lv26 = lab.group(1) if len(lab.group(1)) <= 100 else lab.group(1)[:98] + "…"
                    diff = ([f"date {lv26} where the copy row's `last-verified` reads {want_lv}" if want_lv else f"date {lv26} where the copy holds no `last-verified` cell for `{key}`"] if lab.group(1) not in lv_cells else []) \
                        + ([f"sha {lab.group(2)} where base-sha reads {base_sha}"] if lab.group(2) != base_sha else []) \
                        + ([f"source {lab.group(3)} where the newest listed report holding a block of `{key}` that is a source is {newest}"
                             + (" — the report it names is of another commit, its `Base SHA:` not this run's base-sha" if lab.group(3) in src_blocks and lab.group(3) not in src26 else "")] if lab.group(3) != newest else [])
                    unver26.append(f"`{bid26}` names " + " and ".join(diff))
                    if newest and cands and carry_norm(b) not in cands and not pe_copy:  # the whole fix at once: the one repair re-labels and re-copies
                        unverb26.append(f"`{bid26}` differs from every block of `{key}` in {newest} — it is copied anew from that report, its row's verdict cell, its heading and its severity section following the copied block and every count taken again")
        # a carried row's ledger line is left as it stands: the same line, byte for byte, in the copy and in the file
        # rows compared with their sink cell read by first line: a lone range row whose sink the writer wrote as its first line,
        # every other cell intact, is the same row
        def sink_norm(line: str) -> str:
            cells = line.split(" | ")
            if len(cells) >= 2:
                cells[1] = canon(cells[1])
            return " | ".join(cells)
        copy_lines = {k: {sink_norm(ln) for ln in v} for k, v in copy_lines.items()}
        now_lines: dict[str, set] = {}
        for m in ledger:
            now_lines.setdefault(key_of(m.group(1), m.group(2)), set()).add(sink_norm(m.group(0)))
        # every surviving row of a carried key is a copy row unchanged — or, when the copy held range twins of the key,
        # the one row their merge left: its sha, last-verified and status cells those of one twin, its brief holding every
        # twin's brief (STEP X joins them with `; `)
        def row_altered(k):
            return row_changed(now_lines.get(k, set()), copy_lines.get(k, set()))

        def row_changed(now, was):
            if not now:
                return True
            # a merge (range twins) or a class correction (a copy row under a non-stem class) leaves one row: its sha,
            # last-verified and status cells one copy row's, its brief holding every copy row's brief — a twin dropped
            # with its brief is a loss, even when the surviving row is byte-identical to the copy
            corrected = any(w.split(" | ")[0].strip() not in stems for w in was) if stems else False
            if len(now) == 1 and (len(was) > 1 or corrected):
                row = next(iter(now)).split(" | ")
                olds = [w.split(" | ") for w in was]
                if len(row) < 6 or any(len(w) < 6 for w in olds):
                    return True
                return not (any(row[3:] == w[3:] for w in olds) and all(w[2].strip() in row[2] for w in olds))
            return not now <= was
        altered_keys = sorted(k for k in {corrected_key(c[3], c[2]) for c in carried_rows} if row_altered(k))
        # a key without source is not carried and stays as the pre-write copy holds it, `open`, its brief gaining only
        # `not re-found <date>`: one run re-statused such a row `superseded` and rewrote its brief, and nothing read it
        # a row merged from range twins, or one STEP X rekeyed to its stem, is read as a carried key's is (row_changed)
        # a mark in any form item (24) reads — after `; `, a dash, a colon or a space, in brackets, with a trailing period
        mark_rx = re.compile(r"[\s;,.:\u2014\u2013-]*[(\[]?\s*not re-found (\d{4}-\d{2}-\d{2})\s*[)\]]?\.?")
        edge_ = " ;,.:\u2014\u2013-"

        def unmarked(line_: str) -> tuple[str, set]:
            """The row with its brief's `not re-found <date>` marks taken out, the brief's edges trimmed, and the marks' dates."""
            cells_ = line_.split(" | ")
            if len(cells_) < 3:
                return line_, set()
            dates_ = set(mark_rx.findall(cells_[2]))
            b_ = mark_rx.sub(" ; ", cells_[2])
            b_ = re.sub(r"\s*;(\s*;)+", ";", " ".join(b_.split()))
            cells_[2] = b_.strip(edge_)
            return " | ".join(cells_), dates_

        def brief_parts(b_: str, trails=()) -> set:
            """A brief as the set of its `; `-joined parts, every ` was <class>` trail STEP X appends for a class it corrects
            taken out — never another ` was <word>`, which is the brief's own text."""
            for c_ in trails:
                b_ = re.sub(r"\s+was " + re.escape(c_) + r"\b", "", b_)
            return {x_.strip(edge_) for x_ in b_.split(";") if x_.strip(edge_)}

        def nosrc_changed(k_):
            now_, was_ = now_lines.get(k_, set()), copy_lines.get(k_, set())
            if not now_:
                return False  # a row gone is item (24)'s
            nu_ = [unmarked(x_) for x_ in now_]
            wu_ = [unmarked(x_) for x_ in was_]
            marks_now = set().union(*(d_ for _, d_ in nu_))
            marks_was = set().union(*(d_ for _, d_ in wu_))
            # every mark the copy held stays, and the only mark added is this run's
            if not (marks_was <= marks_now and marks_now <= marks_was | {run_date}):
                return True
            corrected_ = any(w_.split(" | ")[0].strip() not in stems for w_ in was_) if stems else False
            if len(nu_) == 1 and (len(wu_) > 1 or corrected_):
                # the one row a twin merge or a class correction left: `open`, the sha and last-verified of a copy row, and
                # a brief made of the copy rows' briefs and nothing else — stricter than a carried key's, which only
                # holds them
                row_ = nu_[0][0].split(" | ")
                olds_ = [w_.split(" | ") for w_, _ in wu_]
                if len(row_) < 6 or any(len(w_) < 6 for w_ in olds_):
                    return True
                trails_ = sorted({w_[0].strip() for w_ in olds_ if stems and w_[0].strip() not in stems})
                return not (row_[5].strip() == "open" and any(row_[3:5] == w_[3:5] for w_ in olds_)
                            and brief_parts(row_[2], trails_) == set().union(*(brief_parts(w_[2], trails_) for w_ in olds_)))
            return not {x_ for x_, _ in nu_} <= {x_ for x_, _ in wu_}
        nosrc_alt = sorted(k_ for k_ in unjudged if not cand[k_][1] and nosrc_changed(k_))
        altered = len(altered_keys)
        mat_carried = ints(r"^maturity: .*\| carried (\d+) \|", appendix)
        mat_carried = mat_carried[0] if mat_carried else 0
        ok26 = (len(carried_rows) == expected and len(carried_blocks) == len(carried_rows) and verified == len(carried_blocks)
                and verbatim == len(carried_blocks) and altered == 0 and not nosrc_alt and mat_carried == len(carried_rows) and without_src == computed_without)
        ws = f"{without_src}" if without_src == computed_without else f"{without_src} (computed {computed_without})"
        # the fix, key by key: what each source report holds against what is carried, then each block that does not check
        per_key = Counter(corrected_key(c[3], c[2]) for c in carried_rows)
        short26, extra26 = [], []
        for k_ in unjudged:
            src_, cs_ = cand[k_]
            if cs_ and per_key.get(k_, 0) != max(0, len(cs_) - ref26.get(k_, 0)):
                short26.append(f"`{k_}`: {src_} holds {len(cs_)} source block(s) at that sink and class — one per entry point — and {per_key.get(k_, 0)} carried"
                               + (f", {ref26[k_]} withdrawn as `refuted` rows" if ref26.get(k_) else ""))
        for k_ in sorted(set(per_key) - set(unjudged)):
            if k_ in covered26:
                extra26.append(f"`{k_}` is carried as a block of its own though it goes with `{covered26[k_]}`'s carried block, whose `Also at:` line names it")
                continue
            extra26.append(f"`{k_}` is carried though " + ("Step 6 withdrew it on a worker's `ledger refuted:` line — its `refuted` rows are its disposition" if any(corrected_key(c[3], c[2]) == k_ for c in refuted_rows) else "a worker's record reached it this run — its row is that record's disposition" if k_ in judged_keys else "no open row of the pre-write copy holds it"))
        nosrc26 = [k_ for k_ in unjudged if not cand[k_][1]]
        cb_ids26 = {RECORD_RX.match(b).group(2).upper() for b in carried_blocks}
        all_ids26 = {RECORD_RX.match(b).group(2).upper() for b in blocks}
        alt26 = [k_ for k_ in altered_keys if k_ in cand]  # a key no open copy row holds is told to go (above), not to stand
        norow26 = []
        for c in carried_rows:
            if c[6].upper() in cb_ids26:
                continue
            k_ = corrected_key(c[3], c[2])
            if not (cand[k_] if k_ in cand else key_candidates(k_))[0]:  # no source: the row goes, it gains no block
                nosrc26_rows.append(f"`{c[6]}` at `{k_}`" + (" — its row counts in `carried without source`" if k_ in cand else "") + other_note(k_))
            else:
                norow26.append(f"`{c[6]}` " + ("has a block without the `Carried:` label" if c[6].upper() in all_ids26 else "has no block"))
        fix26 = [x_ for x_ in (
            ("every source block of an open key no worker re-confirmed — the blocks at its sink and class of the newest listed report holding one that is a source — is carried, each its own row and block: " + "; ".join(short26[:4]) + (" …" if len(short26) > 4 else "")) if short26 else "",
            "; ".join(extra26[:3]) + (" …" if len(extra26) > 3 else "") if extra26 else "",
            (f"`carried without source: {computed_without}` — the open keys no worker re-confirmed and no listed report holds a block that is a source for" + (f": {', '.join('`' + k_ + '`' + other_note(k_) for k_ in nosrc26[:4])}" if nosrc26 else "") + f" (it reads {without_src})") if without_src != computed_without else "",
            (f"each carried row renders one block, labelled `Carried: confirmed …`: {len(carried_rows)} rows, {len(carried_blocks)} blocks" + (f" — {', '.join(norow26[:4])}{' …' if len(norow26) > 4 else ''}" if norow26 else "")) if norow26 or (len(carried_blocks) != len(carried_rows) and not nosrc26_rows) else "",
            ("a row whose key no listed report holds a block that is a source for cannot be carried: " + "; ".join(nosrc26_rows[:4]) + (" …" if len(nosrc26_rows) > 4 else "")) if nosrc26_rows else "",
            (f"a block citing a line past the end of its file is no source: it is not carried, and not re-cited or re-keyed — its row and block go, and a key left with no source counts in `carried without source`, its ledger row `open` as the pre-write copy holds it with `not re-found {run_date}` added: " + "; ".join(pe26[:4]) + (" …" if len(pe26) > 4 else "")) if pe26 else "",
            ("each carried block's label names the copy row's `last-verified`, this run's base-sha and its source: " + "; ".join(unver26[:3]) + (" …" if len(unver26) > 3 else "")) if unver26 else "",
            ("each carried block is its source block word for word — its heading id, `Worker record:` and `Carried:` lines aside: " + "; ".join(unverb26[:3]) + (" …" if len(unverb26) > 3 else "")) if unverb26 else "",
            f"a carried key's ledger row stands as the pre-write copy holds it, its status `open` and its cells unchanged: {', '.join('`' + k_ + '`' for k_ in alt26[:4])}{' …' if len(alt26) > 4 else ''}" if alt26 else "",
            f"a key without source keeps its ledger row as the pre-write copy holds it — or the one row a range-twin merge or STEP X's class correction left — `open`, every mark it held kept and its brief gaining only `not re-found {run_date}`, never re-statused or rewritten: {', '.join('`' + k_ + '`' for k_ in nosrc_alt[:4])}{' …' if len(nosrc_alt) > 4 else ''}" if nosrc_alt else "",
            f"the maturity line's `carried` reads {mat_carried} and the close-out's {co_carried}, the carried rows {len(carried_rows)}" if (mat_carried != len(carried_rows) or co_carried != len(carried_rows)) else "") if x_]
        ok26_all = ok26 and co_carried == len(carried_rows)
        emit("carried", f"{len(carried_rows)} rows | blocks {len(carried_blocks)} | sources verified {verified}/{len(carried_blocks)} | verbatim {verbatim}/{len(carried_blocks)} | without source {ws} | sources citing past the end {past_end26} | expected {expected} | ledger rows altered {altered} | rows without source altered {len(nosrc_alt)}{sha_note}", f"{co_carried} (close-out) / {mat_carried} (maturity line)", ok26_all,
             None if ok26_all or not fix26 else "; ".join(fix26))
    else:
        why26 = ("base-sha unknown: no commit to compare" if (base_sha or "").lower() == "unknown"
                 else f"base-sha {base_sha} differs from the copy's commit {last_sha}" if sha_how == "run line"
                 else f"base-sha {base_sha}; the copy names no commit" if sha_how == "unreadable"
                 else f"base-sha {base_sha} differs from the copy's last-scanned-sha {last_sha}")
        emit("carried", f"not applicable ({why26}) | carried rows {len(carried_rows)}{sha_note}", None, len(carried_rows) == 0,
             None if not carried_rows else f"nothing is carried here ({why26}): the Same-commit carry holds only at an unchanged commit, so the {len(carried_rows)} carried row(s) and their blocks go, and every count that read them is taken again")

    # 47. refutations — at an unchanged commit a worker's `ledger refuted:` line at an open key no row of another
    # disposition holds is a claim STEP 3 tests with Step 6, block by block, before the key is carried: a withdrawn block
    # is a `refuted` row instead of a carried one; every block withdrawn, the key's ledger row is archived `superseded`
    # and a false-positive pattern holds it; none withdrawn, it is carried as (26) reads it; without a source block it
    # stays a row without source. One outcome per key, one appendix line naming it.
    refute47, unparsed47 = [], []  # (pair, class, sink, guard); lines that do not parse
    for pth_, txt_ in worker_text.items():
        m_f = re.match(r"^deep-(.+)-(p\d+)-results\.md$", Path(pth_).name)
        if not m_f:
            continue
        ok_, bad_ = refute_lines(txt_)
        refute47 += [(f"{m_f.group(1)}/{m_f.group(2)}", c_, s_, g_) for c_, s_, g_ in ok_]
        unparsed47 += [f"{m_f.group(1)}/{m_f.group(2)}: `{l_}`" for l_ in bad_]
    stated47 = ints(r"^[-*\s]*\**refutations:\**\s*(\d+)", appendix)
    app47: dict = {}
    for l_ in appendix.splitlines():
        m_ = re.match(r"^[-*+\s]*\**refuted:\**\s*`?([a-z][a-z0-9_]*)`?\s*\|\s*`?([^|`\s]+?:\d+(?:-\d+)?)`?[,;.]?(?:\s*[\u2014\u2013]\s*|\s+-{1,2}\s+)(.+)$", l_.strip())
        if not m_:
            continue
        out_ = re.split(r"\s*[\u2014\u2013]\s*|\s-{1,2}\s", m_.group(3))[-1].strip(" `*")
        word_ = next((w_ for w_ in ("partly withdrawn", "withdrawn", "stands", "no source") if out_.startswith(w_)), out_[:30])
        app47.setdefault(corrected_key(m_.group(1), m_.group(2)), []).append((word_, out_))
    if unchanged:
        record_keys = {key_of(c[3], c[2]) for c in table_rows if c[4].lower() not in ("carried", "refuted")}
        record_keys |= also_rows(tuple({c[4].lower() for c in table_rows} - {"refuted"}))  # and its `Also at:` lines, a carried block's too
        copy_keys47 = {corrected_key(m.group(1), m.group(2)) for m in copy_rows}
        car_ids: dict = {}
        for c in carried_rows:
            car_ids.setdefault(corrected_key(c[3], c[2]), set()).add(re.sub(r"[`*]", "", c[6]).strip().upper())
        live47: dict = {}
        off47 = []  # a parsed line naming no open key of the copy: the worker's error
        for pair_, cls_, sink_, guard_ in refute47:
            k_ = corrected_key(cls_, sink_)
            if k_ in open_copy and k_ not in record_keys:
                live47.setdefault(k_, []).append((pair_, guard_))
            elif k_ not in copy_keys47:
                off47.append(f"{pair_}: `{cls_} | {sink_}`")
        ref_at = Counter(corrected_key(c[3], c[2]) for c in refuted_rows)
        car_at = Counter(corrected_key(c[3], c[2]) for c in carried_rows)
        arch_status: dict = {}
        for m_a in arch_rows:
            arch_status.setdefault(corrected_key(m_a.group(1), m_a.group(2)), set()).add(m_a.group(3).split(" | ")[-1].strip(" |"))
        fp_sec = memory.split("## Confirmed false-positive patterns", 1)[1].split("\n## ", 1)[0] if "## Confirmed false-positive patterns" in memory else ""
        fp_keys = set()
        for l in fp_sec.splitlines():
            m_p = re.match(r"^\s*(?:[-*]\s+)?`?([a-z][a-z0-9_]*)`? \| `?([^|`]+?:\d+(?:-\d+)?)`?\s*\|", l)
            if m_p:
                fp_keys.add(corrected_key(m_p.group(1), m_p.group(2)))
        outcome, bad47 = {}, []
        for k_ in sorted(live47):
            n_src = len(key_candidates(k_)[1])
            r_, c_ = ref_at.get(k_, 0), car_at.get(k_, 0)
            if not n_src:
                outcome[k_] = "no source" if not (r_ or c_) else None
                if r_ or c_:
                    bad47.append(f"`{k_}` has no source block, so nothing of it is carried or withdrawn — it stays a row without source")
            elif r_ == n_src and not c_:
                outcome[k_] = "withdrawn"
                miss_ = (["its ledger row still in the ledger"] if k_ in ledger_keys else []) \
                    + (["no archive row with status `superseded`"] if "superseded" not in arch_status.get(k_, set()) else []) \
                    + (["no false-positive pattern row at its class and sink"] if k_ not in fp_keys else [])
                if miss_:
                    bad47.append(f"`{k_}` withdrawn in every block: " + ", ".join(miss_))
            elif not r_ and c_:
                outcome[k_] = "stands"
            elif 0 < r_ < n_src and r_ + c_ == n_src:
                outcome[k_] = "partly withdrawn"
                if k_ not in ledger_keys:
                    bad47.append(f"`{k_}` is withdrawn in {r_} of its {n_src} source blocks: the rest are carried, so its ledger row stays in the ledger as the copy holds it")
            else:
                outcome[k_] = None
                bad47.append(f"`{k_}` has {r_} `refuted` and {c_} carried row(s) for {n_src} source block(s) — each block is one or the other: Step 6's withdrawn blocks are `refuted` rows, the rest carried")
            got_ = [w_ for w_, _ in app47.get(k_, [])]
            if outcome[k_] and got_ == [outcome[k_]]:
                txt_ = app47[k_][0][1]
                ids_ = {x_.upper() for x_ in re.findall(r"(?i)VULN-[A-Za-z0-9-]*\d", txt_)}
                want_ids = car_ids.get(k_, set())
                nm_ = re.match(r"partly withdrawn:\s*(\d+)\s+of\s+(\d+)", txt_)
                if outcome[k_] == "partly withdrawn" and not (nm_ and int(nm_.group(1)) == r_ and int(nm_.group(2)) == n_src):
                    bad47.append(f"`{k_}`'s appendix line reads `{txt_[:60]}` where it reads `partly withdrawn: {r_} of {n_src} blocks, …`")
                if outcome[k_] in ("stands", "partly withdrawn") and ids_ != want_ids:
                    bad47.append(f"`{k_}`'s appendix line names {', '.join(sorted(ids_)) or 'no VULN id'} where the key's carried blocks are {', '.join(sorted(want_ids))}")
            if outcome[k_] and got_ != [outcome[k_]]:
                tail_ = {"stands": ", carried as <VULN ids>", "partly withdrawn": ": <n> of <m> blocks, carried as <VULN ids>", "no source": ", not tested"}.get(outcome[k_], "")
                bad47.append(f"`{k_}`'s appendix line " + (f"reads {', '.join('`' + g_ + '`' for g_ in got_)}" if got_ else "is absent") + f" where it names `{outcome[k_]}` — one line for the key, `refuted: <class> | <sink> — <lens>/p<n>[, …]: <the guards, joined with `; `> — {outcome[k_]}{tail_}`")
        stray_rows = sorted(k_ for k_ in ref_at if k_ not in live47)
        stray_lines = sorted(k_ for k_ in app47 if k_ not in live47)
        if stray_rows:
            bad47.append(f"`refuted` rows at {', '.join('`' + k_ + '`' for k_ in stray_rows[:4])} — no worker's `ledger refuted:` line names that open key, or a row of another disposition holds it this run: the row goes, and the key reads as it would without it")
        if stray_lines:
            bad47.append(f"`refuted:` lines at {', '.join('`' + k_ + '`' for k_ in stray_lines[:4])} — a line is written only for an open key a worker's `ledger refuted:` line names and no row of another disposition holds")
        if not ((stated47[0] == len(live47)) if stated47 else not live47):
            bad47.append(f"the appendix line reads `refutations: {len(live47)}`, the open keys a worker's `ledger refuted:` line names that no row of another disposition holds")
        # a worker's line the checker cannot read, or one naming no row of the copy, is shown, never a mismatch: its key is
        # carried as a key no line names, as before refutations were read
        worker47 = bool(unparsed47 or off47)
        unacc47 = sum(1 for k_ in live47 if outcome.get(k_) is None)
        counts47 = Counter(v_ for v_ in outcome.values() if v_)
        emit("refutations", f"{len(live47)} | withdrawn {counts47['withdrawn']} | partly withdrawn {counts47['partly withdrawn']} | stands {counts47['stands']} | no source {counts47['no source']} | refuted rows {len(refuted_rows)} | unaccounted {unacc47}"
             + (f" | worker lines unread {len(unparsed47)} | naming no ledger row {len(off47)} ({'; '.join((unparsed47 + off47)[:2])})" if worker47 else ""),
             str(stated47[0]) if stated47 else "absent", not bad47,
             "; ".join(bad47[:6]) + (" …" if len(bad47) > 6 else "") if bad47 else None)
    else:
        emit("refutations", f"not applicable (a refutation is tested only at an unchanged commit) | refuted rows {len(refuted_rows)} | lines {len(refute47)}", None, not refuted_rows,
             None if not refuted_rows else f"nothing is carried here, so nothing is refuted: the {len(refuted_rows)} `refuted` row(s) go and each key reads as it would without them")

    # 36. memory header — the written memory keeps the base skill's header above its ledger: `scanner-version`,
    # `last-scanned-sha` the plan's base-sha (what the next run's same-commit test reads), `last-updated` a date of this
    # run, and the hints notice. A write that dropped it once made the next run read an unchanged commit as changed.
    head_m = memory.split("## Confirmed findings ledger", 1)[0] if "## Confirmed findings ledger" in memory else memory
    h_sha = (re.search(r"^[ \t]*last-scanned-sha:[ \t]*(\S+)", head_m, re.M) or [None, None])[1]  # read as the next run's copy reads it
    h_upd = (re.search(r"^[ \t]*last-updated:[ \t]*(\d{4}-\d{2}-\d{2})", head_m, re.M) or [None, None])[1]
    h_ver = bool(re.search(r"^[ \t]*scanner-version:[ \t]*\S", head_m, re.M))
    h_hint = "Hints, never authority" in head_m
    # the run's dates: its `started` to the memory's own write (a writer that crosses midnight, or a later repair, writes
    # a later date), the report's name between them
    mem_path = cache / "project-memory.md"
    d_lo = (started or "")[:10] if re.match(r"\d{4}-\d{2}-\d{2}", started or "") else ""
    d_hi = max([d_ for d_ in (d_lo, name_ts.group(0)[:10] if name_ts else "", time.strftime("%Y-%m-%d", time.localtime(mem_path.stat().st_mtime)) if mem_path.exists() else "") if d_], default="")
    sha_ok36 = bool(h_sha) and (h_sha == base_sha if base_sha else True)
    upd_ok36 = bool(h_upd) and (not d_lo or d_lo <= h_upd <= d_hi)  # without a `started` row the date is not placed
    miss36 = [n_ for n_, ok_ in (("scanner-version", h_ver), ("last-scanned-sha", sha_ok36), ("last-updated", upd_ok36), ("hints notice", h_hint)) if not ok_]
    d_rng = (d_lo + (".." + d_hi if d_hi != d_lo else "")) if d_lo else "not placed"
    upd_want = d_rng if d_lo else "the write's date"
    emit("memory header", f"last-scanned-sha {h_sha or 'absent'} (base-sha {base_sha}) | last-updated {h_upd or 'absent'} (run {d_rng}) | scanner-version {'present' if h_ver else 'absent'} | hints notice {'present' if h_hint else 'absent'}",
         None, not miss36,
         None if not miss36 else f"the memory keeps the base skill's header above `## Confirmed findings ledger` — `scanner-version: <version>`, `last-scanned-sha: {base_sha or '<git rev-parse HEAD>'}`, `last-updated: <YYYY-MM-DD, {upd_want}>` and the `> Hints, never authority.` notice — as the base skill's template writes it ({', '.join(miss36)} wrong or absent); the next run reads `last-scanned-sha` to tell an unchanged commit")

    # 38. verdict scope — a body row's verdict follows its worker record's severity, the severity Step 6 saw: a Step 6
    # verdict when it is in `adv=`, `not run` outside it; a block rendered below its record's severity carries the
    # DOWNGRADED or DISPUTED verdict that lowered it; merged, withdrawn and unverifiable rows read `n/a`. One writer tabled
    # forty-six Low records STANDING or DISPUTED, and its repair, reading the block's severity, set `not run` on forty-six
    # Medium records Step 6 had disputed down to Low — erasing the verdicts that made them Low.
    SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    sev_key = lambda s_: "INFO" if (s_ or "").upper().startswith("INFO") else (s_ or "").upper()
    adv_inv = re.search(r"\badv=([A-Za-z,]+)", row(plan, "invocation:") or "")
    adv_txt = re.sub(r"[`*]", "", row(plan, "adv:") or "").strip() or (adv_inv.group(1) if adv_inv else "critical,high,medium")
    adv_words = re.findall(r"\b(critical|high|medium|low|info\w*)\b", adv_txt, re.I)  # `critical, high`, `default (critical,high,medium)`
    adv_set = set() if (re.match(r"^(none|off|skipped?)\b", adv_txt, re.I) or not adv_words) else {sev_key(a_) for a_ in adv_words}
    rec_sev_by: dict[str, list] = {}  # `<lens>/p<n>/<VULN id>` -> [(severity, first File: sink)] of its records
    for p_, t_ in worker_text.items():
        m_f = re.match(r"deep-([a-z][a-z-]*)-(p\d+)-results\.md$", Path(p_).name)
        for b_ in (re.split(r"\n(?=(?:#+ )?\[(?i:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*|CONFIRMED|LIKELY)\] VULN-)", t_) if m_f else []):
            h_ = RECORD_RX.match(b_)
            if h_:
                rec_sev_by.setdefault(f"{m_f.group(1)}/{m_f.group(2)}/{h_.group(2)}".upper(), []).append((sev_key(h_.group(1)), rc_read(b_)[0]))
    def row_sev(c_):
        """The severity of the record a row stands for — under a repeated id, the record at the row's own sink."""
        recs_ = rec_sev_by.get(cell_id(c_).upper()) or []
        if len(recs_) > 1:
            m_c = re.search(r"([^\s|:,;()]+):(\d+)", re.sub(r"[`*]", "", c_[2]))
            at_ = [r_ for r_ in recs_ if m_c and r_[1] and rc_same(rc_path(m_c.group(1)), r_[1][0]) and int(m_c.group(2)) == r_[1][1]]
            recs_ = at_ or recs_
        return recs_[0][0] if recs_ else None
    join_ids = {x_.upper() for x_ in listed}  # item (22)'s join line: a verdict it carries applies whatever adv= covers
    vs_in, vs_out, vs_low, vs_na, vs_n = [], [], [], [], 0
    for c in table_rows:
        d_ = c[4].lower()
        cell_ = " ".join(re.sub(r"[`*]", "", c[5]).split())
        if d_ in ("merged", "withdrawn", "unverifiable"):
            if cell_.lower() not in ("n/a", "na"):
                vs_na.append(f"`{cell_id(c)}` ({d_}) reads `{cell_[:40]}`")
            continue
        rs_ = row_sev(c) if d_ == "body" else None
        if rs_:
            for m_ in merged_rows:
                ms_ = sev_key(record_sev(m_[0])) if m_[6].upper() == c[6].upper() and group_merge(m_, c) else None
                if ms_ and SEV_RANK.get(ms_, 0) > SEV_RANK.get(rs_, 0):
                    rs_ = ms_
        if not rs_:
            continue  # a promoted row has no record of its own, a carried row's verdict is copied, an unknown id is item (31)'s
        vs_n += 1
        # a Step 6 verdict in one of its four forms: `STANDING`, `STANDING — downgrade voided: …`, `DOWNGRADED — <one of the
        # three triggers>: …`, `DISPUTED — …`; a `STANDING — <prose>` cell is none of them
        is_v = re.match(r"^STANDING(?:\s*—\s*downgrade voided:\s*\S.*)?$|^DOWNGRADED\s*—\s*(?:privileged position|non-default configuration|chained prerequisite)\s*:\s*\S|^DISPUTED\s*—\s*\S", cell_, re.I) is not None
        if c[6].upper() not in join_ids:
            if rs_ in adv_set and not is_v:
                vs_in.append(f"`{cell_id(c)}` (record {rs_}) reads `{cell_[:40]}`")
            elif rs_ not in adv_set and not cell_.lower().startswith("not run"):
                vs_out.append(f"`{cell_id(c)}` (record {rs_}) reads `{cell_[:40]}`")
        b_ = block_id.get(c[6].upper())
        bt_ = sev_key(RECORD_RX.match(b_).group(1)) if b_ else None
        if bt_ and SEV_RANK.get(bt_, 0) < SEV_RANK.get(rs_, 0) and not re.match(r"^(DOWNGRADED|DISPUTED)\b", cell_):
            vs_low.append(f"`{c[6]}` is [{bt_}] from a [{rs_}] record under `{cell_[:30]}`")
    fix38 = []
    if vs_in or vs_out:
        fix38.append(f"a body row's verdict follows its worker record's severity — the severity Step 6 saw, not the block's: in `adv={adv_txt}` a Step 6 verdict in its form (`STANDING`, `STANDING — downgrade voided: <named thing> is hop <n> of the Flow`, `DOWNGRADED — <privileged position | non-default configuration | chained prerequisite>: <named thing>`, `DISPUTED — <the concrete thing the doubt is about>: <the property in doubt>`; the rationale belongs to the block's line, not the cell), outside it `not run`, its block's line `Adversarial: not run (severity outside adv=)`; a record Step 6 disputed or downgraded below `adv=` keeps that verdict: {', '.join((vs_in + vs_out)[:4])}{' …' if len(vs_in) + len(vs_out) > 4 else ''}")
    if vs_low:
        fix38.append(f"a block below its record's severity carries the `DOWNGRADED` or `DISPUTED` verdict that lowered it, or is rendered at its record's severity: {', '.join(vs_low[:3])}{' …' if len(vs_low) > 3 else ''}")
    if vs_na:
        fix38.append(f"merged, withdrawn and unverifiable rows read `n/a` in the verdict cell: {', '.join(vs_na[:3])}{' …' if len(vs_na) > 3 else ''}")
    emit("verdict scope", f"adv={adv_txt} | {vs_n} body rows read against their record's severity | in adv= without a Step 6 verdict in its form {len(vs_in)} | outside adv= with one {len(vs_out)} | below their record's severity with no DOWNGRADED or DISPUTED verdict {len(vs_low)} | merged, withdrawn or unverifiable rows not n/a {len(vs_na)}",
         None, not (vs_in or vs_out or vs_low or vs_na), "; ".join(fix38) or None)

    # 39. section placement — a record stands under the heading of its own severity tag, and no Finding Format record stands
    # outside the five severity sections and the Unverifiable section: one report held two [MEDIUM] records under
    # `## Low Findings`, and every count, read by tag, agreed.
    SEC_SEV = {"critical findings": "CRITICAL", "high findings": "HIGH", "medium findings": "MEDIUM", "low findings": "LOW", "informational": "INFO", "informational findings": "INFO"}
    cur_sec, misplaced, outside = None, [], []
    for l_ in unfenced(body_text).splitlines():
        h_ = RECORD_RX.match(l_)  # read first: `## [MEDIUM] VULN-…` is a record, not a section
        m_s = None if h_ else re.match(r"^## (.+?)\s*$", l_)
        if m_s:
            cur_sec = re.sub(r"\s*\(\s*\d+\s*\)\s*$", "", m_s.group(1).strip())  # `## High Findings (5)` is the High section
            continue
        if not h_:
            continue
        want_ = SEC_SEV.get((cur_sec or "").lower())
        if want_ is None:
            if not (cur_sec or "").lower().startswith("unverifiable"):
                outside.append(f"`{h_.group(2)}` under `## {cur_sec}`")
        elif sev_key(h_.group(1)) != want_:
            misplaced.append(f"`{h_.group(2)}` [{h_.group(1).upper()}] under `## {cur_sec}`")
    emit("section placement", f"{len(blocks) - len(misplaced) - len(outside)} of {len(blocks)} records under their own severity heading | under another severity's {len(misplaced)} | outside the severity sections {len(outside)}",
         None, not misplaced and not outside,
         (f"a record stands under the heading of its own severity tag — `## <Severity> Findings`, `## Informational` for INFO — and nowhere else: {', '.join((misplaced + outside)[:4])}{' …' if len(misplaced) + len(outside) > 4 else ''} — move each block, then recount the sections, the Executive Summary table, the histogram and the Body/histogram reconciliation lines from where the records stand") if misplaced or outside else None)

    # 40. block layout — every body and promoted block reads STEP 3's one layout: the severity line, `Worker record:` its
    # row's id, `Entry point:` its row's entry point, then CWE, File, Description, Impact, Flow, Evidence as a fenced code
    # block, Judge, Adversarial, Remediation, Reference with no other line between them; its `Adversarial:` line opens with
    # the row's verdict cell followed by ` — ` and a rationale, `Adversarial: not run (severity outside adv=)` for a
    # `not run` row. Carried blocks are an earlier report's, copied, and item (26) reads them.
    LAYOUT = ["Worker record", "Entry point", "CWE", "File", "Description", "Impact", "Flow", "Evidence", "Judge", "Adversarial", "Remediation", "Reference"]
    lay_rows = {c[6].upper(): c for c in table_rows if c[4].lower() in ("body", "promoted")}
    lay_norm = lambda s_: " ".join(re.sub(r"[`*]", "", s_.replace("\\|", "|")).split())
    lay_o, lay_f, lay_w, lay_e, lay_a, lay_x, lay_n = [], [], [], [], [], [], 0
    for b in blocks:
        bid_ = RECORD_RX.match(b).group(2)
        c = lay_rows.get(bid_.upper())
        if not c:
            continue  # a carried row's block is an earlier report's, item (26)'s; a block no row holds is item (1)'s
        lay_n += 1
        labels, vals, fence_, in_ev, ev_fenced, stray, pend_ = [], {}, False, False, False, 0, 0  # a line counts once a field follows it
        for l_ in b.splitlines()[1:]:
            if not fence_ and re.match(r"^#{1,3} ", l_):
                break  # the block ends at the next heading — outside a fence: a `# comment` in Evidence is the snippet's
            if l_.strip().startswith(("```", "~~~")):
                fence_ = not fence_
                ev_fenced = ev_fenced or in_ev
                continue
            if fence_ or not l_.strip():
                continue
            m_l = re.match(r"^\**([A-Z][A-Za-z ]*?):\**\s*(.*)$", l_)
            if m_l and m_l.group(1) in LAYOUT:
                stray, pend_ = stray + (pend_ if labels else 0), 0
                labels.append(m_l.group(1))
                vals.setdefault(m_l.group(1), m_l.group(2).strip())
                in_ev = m_l.group(1) == "Evidence"
            else:
                pend_ += 1  # between two fields a stray line; after the last one a separator (`---`) or trailing text
                in_ev = False
        if labels != LAYOUT or stray:
            lay_o.append(f"`{bid_}` reads {' → '.join(labels[:14]) or 'no fields'}" + (f" with {stray} other line(s)" if stray else ""))
        if "Evidence" in labels and not ev_fenced:
            lay_f.append(f"`{bid_}`")
        if "Worker record" in vals and lay_norm(vals["Worker record"]) != lay_norm(c[0]):
            lay_w.append(f"`{bid_}` names `{vals['Worker record'][:50]}` where its row is `{c[0]}`")
        ep_form = lambda s_: re.sub(r"\s+[|/—–-]\s+", " ", lay_norm(s_))  # ` | `, ` / `, ` — ` between the site and its name are one form
        if "Entry point" in vals and ep_form(vals["Entry point"]) != ep_form(c[1]):
            lay_e.append(f"`{bid_}` reads `{vals['Entry point'][:50]}` where its row's cell is `{c[1][:50]}`")
        cell_ = lay_norm(c[5])
        av_ = lay_norm(vals.get("Adversarial", ""))
        if cell_.lower().startswith("not run"):
            adv_ok = re.match(r"^not run \(severity outside adv=[^)]*\)\.?$", av_) is not None
        else:
            # the cell, then its rationale — read by its words (three at least), not by the separator the writer chose;
            # the cell alone, or with a full stop after it, omits the rationale the rule never lets go
            adv_ok = bool(cell_) and av_.startswith(cell_) and len(av_[len(cell_):].strip(" .;:,—-").split()) >= 3
        if not adv_ok:
            lay_a.append(f"`{bid_}` reads `{av_[:60]}` for the cell `{cell_[:40]}`")
        # a body or promoted block keeps its record's `Also at:` line and the lines of each record of its class merged into
        # it, the same sinks — dropped, their keys would read as carried or missed by the next run — each a readable line
        if c[4].lower() in ("body", "promoted"):
            rec_al_ = set(record_also(c[0]))
            for m_r in table_rows:
                if m_r[4].lower() == "merged" and m_r[6].upper() == bid_.upper() and m_r[3] == c[3]:
                    rec_al_ |= set(record_also(m_r[0]))
            own_f_ = canon(rel(file_of(b) or ""))  # a merged record may name the kept block's own sink, which is its `File:`
            rec_al_ = sorted({canon(rel(s_)) for s_ in rec_al_} - {own_f_})
            blk_al_ = sorted({canon(rel(s_)) for s_ in block_also(b)} - {own_f_})
            bad_al_ = block_also_bad(b)
            if rec_al_ != blk_al_:
                lay_x.append(f"`{bid_}` names {len(blk_al_)} `Also at:` sink(s) where its record and the records of its class merged into it name {len(rec_al_)}")
            if bad_al_:
                lay_x.append(f"`{bid_}`: " + "; ".join(bad_al_[:2]))
    lay_bad = {x_ for lst_ in (lay_o, lay_f, lay_w, lay_e, lay_a, lay_x) for x_ in (s_.split("`")[1] for s_ in lst_)}
    fix40 = [f"{what_}: {', '.join(lst_[:3])}{' …' if len(lst_) > 3 else ''}" for what_, lst_ in (
        ("the fields in STEP 3's order — Worker record, Entry point, CWE, File, Description, Impact, Flow, Evidence, Judge, Adversarial, Remediation, Reference — with no other line between them", lay_o),
        ("Evidence as a fenced code block", lay_f), ("`Worker record:` the row's worker record id", lay_w), ("`Entry point:` the row's entry-point cell", lay_e),
        ("the `Adversarial:` line the row's verdict cell, then ` — ` and the one-sentence rationale, never omitted — `Adversarial: not run (severity outside adv=)` for a `not run` row", lay_a),
        ("the record's `Also at:` line after `Reference:`, its sinks as the record and the records of its class merged into it name them, one `<path>:<line>` each — no range, a file of the target", lay_x)) if lst_]
    emit("block layout", f"{lay_n - len(lay_bad)} of {lay_n} body and promoted blocks in the one layout | fields out of order, missing or with a line between {len(lay_o)} | Evidence not fenced {len(lay_f)} | Worker record not the row's {len(lay_w)} | Entry point not the row's {len(lay_e)} | Adversarial not the cell and a rationale {len(lay_a)}" + (f" | Also at not the record's {len(lay_x)}" if lay_x else ""),
         None, not lay_bad, ("every block is rendered from its row in the one layout — " + "; ".join(fix40)) if fix40 else None)

    # 41. appendix table — the appendix copies `disposition-table.md` in full, every row as the file holds it: three
    # reports put a sentence pointing at the file there, and nothing read the table the report says it holds
    def disp_rows(text_: str) -> list:
        out_ = []
        for l_ in text_.splitlines():
            s_ = l_.strip()
            if "|" in s_:  # as the table parser reads it: outer pipes and indentation aside
                cells_ = [" ".join(strip_cell(x_).split()) for x_ in s_.strip("|").split(" | ")]
                if len(cells_) == 7 and cells_[4].lower() in DISPOSITIONS:
                    out_.append(tuple(cells_))
        return out_
    at_file, at_app = Counter(disp_rows(read(cache / "disposition-table.md"))), Counter(disp_rows(appendix))
    at_missing, at_extra = sum((at_file - at_app).values()), sum((at_app - at_file).values())
    emit("appendix table", f"{sum(at_file.values()) - at_missing} of {sum(at_file.values())} rows of disposition-table.md copied | rows the file does not hold {at_extra}", None, at_missing == 0 and at_extra == 0,
         (f"the appendix's Worker record disposition copies `disposition-table.md` in full, every row as the file holds it — never a sentence pointing at the file: {at_missing} row(s) absent (first `{next(iter(at_file - at_app))[0]}`)" if at_missing else "the appendix copies `disposition-table.md` as it stands")
         + (f", {at_extra} row(s) the file does not hold (first `{next(iter(at_app - at_file))[0]}`)" if at_extra else "") if at_missing or at_extra else None)

    # 42. scope exclusions — the appendix reproduces `scope-excluded.txt`, every row, and `excluded: <p> paths / <l> lines`
    # with `p` its row count and `l` the lines of the regular files it names: one report wrote `excluded: 0 paths / 0 lines`
    # over eighteen rows. A listed file that grows during the run (the runtime's own log) reads by its size then, so `l`
    # lies between the lines of the files unchanged since `started` and all of them now.
    ex_rows = [l_.strip() for l_ in read(cache / "scope-excluded.txt").splitlines() if l_.strip() and not l_.strip().startswith("#")]
    ex_split = [re.split(r"\s+\|\s+|\t+|\s+[—–]\s+", r_, maxsplit=1) for r_ in ex_rows]  # `path | reason`, `path — reason`, a tab
    ex_paths = [x_[0].strip().strip("`") for x_ in ex_split]
    ex_reasons = [" ".join(x_[1].split()) if len(x_) > 1 else "" for x_ in ex_split]
    ex_sec_m = re.search(r"^###\s+Scope exclusions?\b.*$", appendix, re.M | re.I)
    ex_sec = appendix[ex_sec_m.end():].split("\n### ", 1)[0] if ex_sec_m else ""
    ex_st = re.search(r"^[-*]?\s*`?excluded:\s*(\d+)(?:\s*paths?)?(?:\s*/\s*(\d+)\s*lines?)?", appendix, re.M)
    def ex_given(p_: str, r_: str) -> bool:
        """The row stands in the section with a reason: a line naming the path and two words beside it — the file's own
        words or the writer's, since the point is a reader can tell a deliberate exclusion from a forgotten one."""
        for l_ in ex_sec.splitlines():
            if p_ in l_:
                rest_ = re.sub(r"[`*|—–:;,.()\[\]-]", " ", l_.replace(p_, " ", 1)).split()
                if len(rest_) >= 2 or not r_:
                    return True
        return False
    ex_missing = [p_ for p_, r_ in zip(ex_paths, ex_reasons) if not ex_given(p_, r_)]
    import datetime  # imported where it is used, as the script's other stamp readers do
    try:
        st_ts = datetime.datetime.strptime(started, "%Y-%m-%d_%H-%M-%S").timestamp() if started else None
    except ValueError:
        st_ts = None
    ex_lo = ex_hi = 0
    ex_unread = 0
    try:
        rep_mt = report_path.stat().st_mtime if report_path and report_path.exists() else None
    except OSError:
        rep_mt = None
    for p_ in ex_paths:
        f_ = target / p_
        try:
            if f_.is_file():
                with open(f_, "rb") as fh_:  # read in pieces: an excluded file can be large
                    n_ = sum(ch_.count(b"\n") for ch_ in iter(lambda: fh_.read(1 << 20), b""))
                mt_ = f_.stat().st_mtime
                if st_ts is not None and mt_ < st_ts:
                    ex_lo += n_  # unchanged since the run began: its count is the count the writer took
                    ex_hi += n_
                elif rep_mt is not None and mt_ > rep_mt:
                    ex_unread += 1  # changed after the report's write (the runtime's transcript, exported at its exit): no bound
                else:
                    ex_hi += n_  # grown during the run, before the report: the writer counted it at no more than this
        except OSError:
            ex_unread += 1  # a file this run cannot read bounds nothing from above
    ex_p, ex_l = (int(ex_st.group(1)), int(ex_st.group(2)) if ex_st.group(2) else (0 if ex_st.group(1) == "0" else None)) if ex_st else (None, None)
    ex_ok = ex_st is not None and ex_p == len(ex_paths) and not ex_missing and ex_l is not None and ex_lo <= ex_l and (ex_unread or ex_l <= ex_hi)
    emit("scope exclusions", f"{len(ex_paths) - len(ex_missing)}/{len(ex_paths)} rows of scope-excluded.txt reproduced | {len(ex_paths)} paths, {ex_lo}..{ex_hi if not ex_unread else '?'} lines" + (f" | unbounded (changed after the report, or unreadable) {ex_unread}" if ex_unread else ""),
         f"{ex_p} paths / {ex_l} lines" if ex_st else "absent", ex_ok,
         None if ex_ok else f"the appendix's Scope exclusions section reproduces `scope-excluded.txt` — every row, its path and reason — then `excluded: {len(ex_paths)} paths / <l> lines`, `l` the line count of the regular files it names (`wc -l`; a directory adds none), counted from the files" + (f"; rows not reproduced with their reason: {', '.join('`' + p_ + '`' for p_ in ex_missing[:4])}{' …' if len(ex_missing) > 4 else ''}" if ex_missing else ""))

    # 43. class clearances — `class clearances <n>` is one search over the worker files, the lines that hold a scoped
    # clearance `SAFE in p<n> — no <surface>`, never a writer's reading of what a clearance is
    cc_rx = re.compile(r"SAFE in p\d+\s*(?:—|–|--|-)\s*no\b")
    cc_n = sum(1 for t_ in worker_text.values() for l_ in t_.splitlines() if cc_rx.search(l_))
    cc_st = ints(r"class clearances\s*:?\s*(\d+)", appendix)
    emit("class clearances", str(cc_n), str(cc_st[0]) if cc_st else "absent", bool(cc_st) and cc_st[0] == cc_n,
         None if (cc_st and cc_st[0] == cc_n) else f"the STEP X line reads `class clearances {cc_n} | contradicted by body records <m>` — `{cc_n}` the lines across the `deep-*-results.md` files holding `SAFE in p<n> — no <surface>`, one search, never a count of what the writer reads as a clearance")

    # 44. pass log — one entry per pair, its passes copied from the worker file's sentinel `passes=` (`passes: none
    # (worker not run)` for a pair recorded `worker not run:`): one report wrote a sentence for all twenty-seven
    pl_m = re.search(r"^###\s+Per-lens-per-partition pass log\b.*$", appendix, re.M | re.I)
    pl_txt = appendix[pl_m.end():].split("\n### ", 1)[0] if pl_m else ""
    pl_pairs = sorted({pr for pr, _, _ in dispatch})
    pl_notrun = set(re.findall(r"^worker not run: ([a-z-]+/p\d+)", plan, re.M))
    pl_table: dict[str, str] = {}  # pair -> the passes cell of a pass-log table, under its `passes` header
    for tbl_ in re.findall(r"(?:^[ \t]*\|.*\n?)+", pl_txt, re.M):
        trs_ = [[strip_cell(x_) for x_ in l_.strip().strip("|").split("|")] for l_ in tbl_.splitlines() if l_.strip()]
        if len(trs_) < 2:
            continue
        hd_ = [x_.lower() for x_ in trs_[0]]
        pc_ = next((i_ for i_, x_ in enumerate(hd_) if re.match(r"^pass(es)?\b", x_)), None)
        if pc_ is None:
            continue
        lc_ = next((i_ for i_, x_ in enumerate(hd_) if x_ in ("lens", "lens name")), None)
        qc_ = next((i_ for i_, x_ in enumerate(hd_) if x_ in ("partition", "part")), None)
        for r_ in trs_[1:]:
            if all(re.fullmatch(r":?-{2,}:?", x_ or "-") for x_ in r_) or len(r_) <= pc_:
                continue
            pr_ = (f"{r_[lc_]}/{r_[qc_] if r_[qc_].startswith('p') else 'p' + r_[qc_]}" if lc_ is not None and qc_ is not None and len(r_) > max(lc_, qc_)
                   else next((m_.group(0) for x_ in r_ for m_ in [re.search(r"[a-z][a-z-]*/p\d+", x_)] if m_), None))
            v_ = re.search(r"\d+|none", r_[pc_], re.I)
            if pr_ and v_:
                pl_table.setdefault(pr_, v_.group(0).lower())
    pl_abs, pl_bad = [], []
    for pr in pl_pairs:
        lens_, part_ = pr.split("/")
        sent_ = re.search(r"LLM-SAST-COMPLETE[^>]*passes=(\d+)", read(cache / f"deep-{lens_}-{part_}-results.md"))
        want_ = "none" if pr in pl_notrun else (sent_.group(1) if sent_ else None)
        no_file = not (cache / f"deep-{lens_}-{part_}-results.md").exists()
        got_ = pl_table.get(pr)  # a pass-log table: its passes column, read by the header
        lines_ = [l_ for l_ in pl_txt.splitlines() if not l_.lstrip().startswith("|") and re.search(r"(?<![\w-])" + re.escape(pr) + r"(?![\w-])", l_)]
        if got_ is None and not lines_:
            pl_abs.append(pr)
            continue
        for l_ in ([] if got_ is not None else lines_):
            m_p = re.search(r"passes(?:\s+run)?\W{0,3}(\d+|none)\b|\b(\d+)\s+pass(?:es)?\b", l_, re.I)
            if m_p:
                got_ = (m_p.group(1) or m_p.group(2)).lower()
                break
            if pr in pl_notrun and no_file and re.search(r"no worker file", l_, re.I):
                got_ = "none"  # the SKILL's form for a pair recorded `worker not run:` with no file
                break
        if want_ is not None and got_ != want_:
            pl_bad.append(f"`{pr}` reads {got_ or 'no passes'} where its sentinel has {want_}")
    emit("pass log", f"{len(pl_pairs) - len(pl_abs) - len(pl_bad)}/{len(pl_pairs)} pairs with their entry | absent {len(pl_abs)} | passes not the sentinel's {len(pl_bad)}", None, not pl_abs and not pl_bad,
         None if not (pl_abs or pl_bad) else f"the pass log holds one entry per pair — passes run, what the last pass added, stop reason, converged yes/no — its passes copied from the worker file's sentinel `passes=`, `passes: none (worker not run)` for a pair recorded `worker not run:`: " + "; ".join(x_ for x_ in (f"absent: {', '.join('`' + p_ + '`' for p_ in pl_abs[:5])}{' …' if len(pl_abs) > 5 else ''}" if pl_abs else "", ", ".join(pl_bad[:3])) if x_))

    # 45. routed hand-offs — `routed: <n>` counts the rows of `handoff-table.md`, which exists: one report stated two
    # hand-offs and wrote no table
    ho_file = cache / "handoff-table.md"
    ho_rows = []
    ho_lines = [l_.strip() for l_ in read(ho_file).splitlines()]
    ho_sep = lambda l_: re.match(r"^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$", l_) is not None
    for i_, l_ in enumerate(ho_lines):
        if not l_.startswith("|") or ho_sep(l_) or (i_ + 1 < len(ho_lines) and ho_sep(ho_lines[i_ + 1])):
            continue  # a separator, or the header row above one, whatever its words
        cells_ = [strip_cell(x_).lower() for x_ in l_.strip("|").split("|")]
        if all(x_ in ("", "none", "—", "-", "n/a") for x_ in cells_):
            continue  # a row that says there were none
        ho_rows.append(l_)
    ho_st = ints(r"^[-*]?\s*`?routed:\s*(\d+)", appendix)
    ho_ok = ho_file.exists() and bool(ho_st) and ho_st[0] == len(ho_rows)
    emit("routed hand-offs", f"handoff-table.md {'present' if ho_file.exists() else 'ABSENT'} | {len(ho_rows)} rows", str(ho_st[0]) if ho_st else "absent", ho_ok,
         None if ho_ok else f"`handoff-table.md` holds one row per STEP Y hand-off, each with its final disposition, and the appendix's `routed: <n>` counts those rows: {len(ho_rows)} in the file" + ("" if ho_file.exists() else " — the file is absent: write it, a header alone when there were none"))

    # 46. citations — every `file:line` a block's `File:` and `Flow:` lines cite in a file of the target lies within it: one
    # carried block cited line 533 of a 496-line file across six reports, and a repair that corrected it had no legal path
    cit_n, cit_bad = 0, []
    for b in blocks:
        seen46, bad46 = citations_of(b)
        cit_n += seen46
        carried46 = bool(re.search(r"^Carried: confirmed ", b, re.M))
        cit_bad += [(RECORD_RX.match(b).group(2), c_, n_, carried46, k_) for c_, n_, k_ in bad46]
    cb46 = sorted({i_ for i_, _, _, c_, _ in cit_bad if c_})
    sinks46 = {i_ for i_, _, _, c_, k_ in cit_bad if not c_ and k_ == "sink"}
    pr46 = sorted(i_ for i_ in sinks46 if i_.upper() in promoted_ids)
    def rec_past46(i_):  # the record's own sink lies past the end: rendering the block again would cite it still
        r_ = blk_off_rec.get(i_.upper())
        n_ = target_lines(r_[0]) if r_ else None
        return n_ is not None and r_[1] > n_
    rend46 = sorted(i_ for i_ in sinks46 if i_.upper() in blk_off_ids and i_.upper() not in promoted_ids and not rec_past46(i_))
    sink46 = sorted(sinks46 - set(pr46) - set(rend46))
    fix46_ids = sorted({i_ for i_, _, _, c_, k_ in cit_bad if not c_ and k_ != "sink"} - sinks46)
    ids46 = lambda xs: ", ".join("`" + x_ + "`" for x_ in xs[:6]) + (" …" if len(xs) > 6 else "")
    rec46 = {c[6].upper(): cell_id(c) for c in table_rows if c[4].lower() == "body"}
    ids46r = lambda xs: ", ".join("`" + x_ + "`" + (f" (`{rec46[x_.upper()]}`)" if x_.upper() in rec46 else "") for x_ in xs[:6]) + (" …" if len(xs) > 6 else "")
    fix46 = [x_ for x_ in (
        (f"a worker's record whose `File:` sink lies past the end of its file fails Citation & Evidence Verification: its row is `withdrawn` with `withdrawn: <its worker record> — citation: <file>:<line> lies past the end of its <n> lines`, never re-cited — item (37) reads the sink against the record — every `merged` row whose own sink is that sink and whose body record is that VULN id is withdrawn the same way (one merged into it from another sink becomes its own `body` row, and a `duplicate candidate:` line naming a withdrawn row goes, `duplicate candidates:` taken again), and a key the pre-write copy holds keeps its ledger row with `not re-found <date>` added: {ids46r(sink46)}") if sink46 else "",
        (f"a body block whose `File:` sink is not its record's is rendered from its record — item (37): {ids46(rend46)}") if rend46 else "",
        (f"a promoted row's block whose sink lies past the end is rendered from its record when the record states a line that exists, else — and for a promotion with no record — the promoted row and its block go, with the record's withdrawal when it has one — never a second `withdrawn` row for one record, item (31): {ids46(pr46)}") if pr46 else "",
        (f"a `Flow:` hop or a `File:` range end past the end of its file is corrected from the source, as Citation & Evidence Verification requires, or the record withdrawn the same way: {ids46(fix46_ids)}") if fix46_ids else "",
        (f"a carried block citing a line past the end of its file — item (26) names what its key carries: {ids46(cb46)}") if cb46 else "") if x_]
    emit("citations", f"checked {cit_n} in {len(blocks)} blocks | past the end of their file {len(cit_bad)}"
         + (": " + ", ".join(f"{i_} {c_} ({n_} lines)" for i_, c_, n_, _, _ in cit_bad[:6]) + (" …" if len(cit_bad) > 6 else "") if cit_bad else ""),
         None, not cit_bad, "; ".join(fix46) or None)

    # 49. needs context — every line of a worker file outside its finding records that names a NEEDS CONTEXT judgement
    # (`--needs-context` lists them) has one `needs context: <lens>/p<n>:<line> — <answer>` line in the Unverifiable
    # section: `<path:line> — <what is missing>`, `carried by <the report's VULN or UNV id>`, or `mention: <what the line
    # restates>`. The base skill reports NEEDS CONTEXT under Unverifiable, and a worker writes it in its clearances, where
    # no row carries it: one run's writer brought five such observations into its Unverifiable section and left out two
    # candidates — a message-chosen sender address a worker called an `Unverifiable candidate`, and a secret in a URL query.
    # Reading the sink out of the prose was tried: over the earlier runs the cite nearest the words was the judgement's
    # sink in ten of nineteen and thirty of sixty-four named none, so the checker lists the lines and the writer, who can
    # read them, names the sink. One `mention:` text naming no line or id, over three or more lines of two or more worker
    # files, says what none of them is.
    nc_list = nc_lines(worker_files)
    nc_keys = {(p_.lower(), n_): l_ for p_, n_, l_ in nc_list}
    nc_pairs = {nc_pair(p_).lower() for p_ in worker_files}
    nc_sec = nc_section(report)
    # a key naming no worker file is no answer line — a prose bullet `Needs context: <file>:<line> — …` is the section's text
    nc_ans = {k_: v_ for k_, v_ in nc_answers(nc_sec).items() if k_[0] in nc_pairs}
    # an id the report gives a candidate: a body block's, a record heading's, a table row's `body record` cell, or one an
    # entry line of the Unverifiable section opens (`### [UNVERIFIABLE] UNV-001 — …`, `- \`UNVERIFIABLE-001\` (…)`, a
    # `[UNVERIFIABLE] VULN-012` heading) — never a worker record's own id, which the report names only beside `Worker
    # record:`, nor an id a sentence of the section mentions
    nc_idrx = r"[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9-]*\d"
    nc_ids = {k_.upper() for k_ in block_id}
    nc_ids |= {x_.upper() for x_ in re.findall(r"(?mi)^(?:#+\s*)?\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\]\s+`?(" + nc_idrx + r")(?![-\w])", body_text)}
    nc_ids |= {c_[6].strip("` ").upper() for c_ in table_rows if re.fullmatch(nc_idrx, c_[6].strip("` "))}
    entry_rx = re.compile(r"^[\s#>|*_`+-]*(?:(?:\d+[.)]|\(\d+\))\s*)?(?:[*_`]*\[(?:UNVERIFIABLE|CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\][*_`]*\s*)*"
                          r"(?:UNVERIFIABLE\s+)?[\s—–:*_`-]*(UNV(?:ERIFIABLE)?-\d{1,9}|VULN-[A-Za-z0-9-]*\d)(?![-\w])"
                          r"(?=[\s*_`]*(?:[—–:|(),\]-]|$))", re.I)
    for l_ in nc_sec.splitlines():
        h_ = None if NC_ANS_RX.match(l_) else entry_rx.match(l_)
        if h_ and (not h_.group(1).upper().startswith("VULN-") or re.search(r"(?i)\[UNVERIFIABLE\]", l_)):
            nc_ids.add(h_.group(1).upper())
    # a token is read as an id when its prefix is one the report's ids use — `VULN`, `UNV`, `UNVERIFIABLE` or an older
    # report's own (`F-012`) — so `CWE-639`, `SHA-256` or `us-east-1` beside an id is the text's, not a claim
    nc_pref = {"VULN", "UNV", "UNVERIFIABLE"} | {x_.split("-", 1)[0] for x_ in nc_ids}
    idlike_ = lambda x_: x_.split("-", 1)[0].upper() in nc_pref
    nc_unans, nc_noform, nc_kind, nc_same = [], [], Counter(), {}
    # a text read for repeats: its words, and the references it names kept as written — a line key, a VULN or UNV id, a
    # `path:line`, `line <n>` — so a counter `(2)` tells nothing apart while `restates injection/p2:215` does
    ref_rx = re.compile(r"[a-z][a-z0-9-]*(?:/p\d+)?:\d{1,9}|(?:vuln|unv)-[a-z0-9-]*\d|[\w.@+-]+(?:/[\w.@+-]+)*\.\w+:\d{1,9}|\bline\s+\d{1,9}", re.I)
    words_ = lambda s_: len(re.findall(r"[A-Za-z][A-Za-z'-]*", ref_rx.sub(" ", s_)))
    norm_ = lambda s_: " ".join(re.sub(r"[^a-z\s]", " ", ref_rx.sub(" ", s_.lower())).split())
    cite_rx = re.compile(r"^\[?`?([^`\s\]:;]+?):(\d{1,9})(?:[-–]\d{1,9})?`?\]?(?:\([^)\s]*\))?(.*)$")
    sep_ = lambda s_: re.sub(r"^[\s\u00a0:,;|/.=~\u00b7'\"\u2018\u2019\u201c\u201d\u2014\u2013\u2192()\[\]*_`<>-]+", "", s_)
    carry_rx = re.compile(r"(?i)(?<![A-Za-z])carried\s+by(?![A-Za-z])")
    # the carried form: `carried by` and, a word or three on, an id — `carried by` with no id after it is the missing
    # fact's own words
    cb_rx = re.compile(r"(?i)^carried\s+by(?![A-Za-z])(?:[\s*_`]+[a-z][a-z'-]*){0,3}?[\s:*_`\[(]*(" + nc_idrx + r")(?![-\w])")

    def nc_cite(path_, line_, shown_):
        """None when the cite names a line of a source file of the target, else what is wrong."""
        n_ = target_lines(path_)
        if n_ is None or re.match(r"(?i)(?:\.llm-sast-scanner-cache(?:/|$)|sast_report-[^/]*\.md$)", os.path.normpath(path_)):
            return f"cites `{shown_}`, no source file of the target — the sink's path from the target directory"
        if not 1 <= line_ <= n_:
            return f"cites `{shown_}`, past the end of its {n_} lines"
        return None

    def nc_ids_after(s_):
        """None when every id after a `carried by` in the text is one the report gives a candidate, else the first that is
        not — an id read by its prefix, a worker record's path (`lens/p2/VULN-…`) left out."""
        for cm_ in carry_rx.finditer(s_):
            for x_ in re.findall(r"(?<![/\w-])(" + nc_idrx + r")(?![-\w])", s_[cm_.end():]):
                if idlike_(x_) and x_.upper() not in nc_ids:
                    return (f"names `{x_}`, no id the report gives a candidate — a body block's or record heading's, a `body record` "
                            "cell's or an Unverifiable entry's — never a worker record's own")
        return None

    for k_ in nc_keys:
        got_ = nc_ans.get(k_, [])
        if len(got_) != 1:
            nc_unans.append(f"`{k_[0]}:{k_[1]}`" + (f" ({len(got_)} lines)" if got_ else ""))
            continue
        parts_ = re.split(r"[;；]\s*", got_[0])
        kind_, err_, last_ = None, None, None
        # the first answer in its full form: a cite then the missing fact, `carried by` or `mention:`, or no cite and one of
        # those two — whatever separator stands between the cite and the rest
        a_ = parts_[0]
        ob_ = cite_rx.match(a_)
        tail_ = sep_(ob_.group(3)) if ob_ else sep_(a_)
        if ob_:
            last_ = rel(ob_.group(1))
            err_ = nc_cite(last_, int(ob_.group(2)), f"{ob_.group(1)}:{ob_.group(2)}")
        cb_ = cb_rx.match(tail_)
        cb_ = cb_ if cb_ and idlike_(cb_.group(1)) else None
        mn_ = re.match(r"(?i)mention\s*:\s*(.*\S)?", tail_)
        if err_:
            pass
        elif cb_:
            kind_ = "carried"
        elif mn_:
            kind_ = "mention"
            if words_(mn_.group(1) or "") < 2:
                err_ = "reads `mention:` without two words saying what the line restates"
            elif not ref_rx.search(mn_.group(1)):  # a mention naming the line or id it restates points somewhere
                nc_same.setdefault(norm_(mn_.group(1)), []).append(k_)
        elif ob_:
            kind_ = "observation"
            if words_(tail_) < 2:
                err_ = f"cites `{last_}:{ob_.group(2)}` without two words naming what is missing"
        else:
            err_ = (f"reads `{a_[:40]}` — `<path:line> — <what is missing>`, the cite first, `carried by <VULN or UNV id>` or "
                    "`mention: <what the line restates>`")
        err_ = err_ or nc_ids_after(tail_)
        # each later answer of a `; ` line: its cites — `:<line>`s read in the file cited before them, a `path:line` whose
        # path is a file's (`localhost:3000` and `02:30` are words) — and every id after its `carried by`
        for q_ in parts_[1:]:
            if err_:
                break
            b_ = re.match(r"^[\s—–-]*(:\d{1,9}(?:[-–]\d{1,9})?(?:\s*(?:,|and|&)\s*:\d{1,9}(?:[-–]\d{1,9})?)*)(.*)$", q_)
            if b_:
                if not last_:
                    err_ = f"cites `{b_.group(1).split(',')[0].strip()}` with no file before it — the sink's path from the target directory"
                    break
                for n_ in re.findall(r":(\d{1,9})", b_.group(1)):
                    err_ = err_ or nc_cite(last_, int(n_), f"{last_}:{n_}")
                q_ = b_.group(2)
            else:
                # the cite read before the separators go, so a dotfile's (`.gitlab-ci.yml:37`) keeps its leading `.`
                c_ = cite_rx.match(re.sub(r"^[\s\u00a0,|=~\u00b7'\"\u2018\u2019\u201c\u201d\u2014\u2013\u2192()*_<>-]+", "", q_))
                q_ = sep_(q_)
                c_ = c_ or cite_rx.match(q_)
                # a line key (`protocol-infra/p3:130`) a mention lists is a line of the worker files, not a file's cite
                if c_ and re.search(r"/|\.\w+$", c_.group(1)) and not re.fullmatch(r"[a-z][a-z0-9-]*/p\d+", c_.group(1), re.I):
                    last_ = rel(c_.group(1))
                    err_ = nc_cite(last_, int(c_.group(2)), f"{c_.group(1)}:{c_.group(2)}")
                    q_ = c_.group(3)
            q_ = sep_(q_)
            if not err_ and re.match(r"(?i)mention\s*:", q_) and words_(q_[q_.index(":") + 1:]) < 2:
                err_ = "reads a later `mention:` without two words saying what the line restates"
            err_ = err_ or nc_ids_after(q_)
        if err_:
            nc_noform.append(f"`{k_[0]}:{k_[1]}` {err_}")
        else:
            nc_kind[kind_] += 1
    nc_stray = sorted(f"`{p_}:{n_}`" for p_, n_ in nc_ans if (p_, n_) not in nc_keys)
    # one `mention:` text naming no line or id, over three or more lines of two or more worker files, says what none of
    # them is; an observation is held to its sink and is never a dismissal
    nc_rep = sorted(((t_, v_) for t_, v_ in nc_same.items() if len(v_) >= 3 and len({k_[0] for k_ in v_}) >= 2), key=lambda x_: -len(x_[1]))
    fix49 = []
    if nc_unans:
        none_ = [x_ for x_ in nc_unans if "lines)" not in x_]
        many_ = [x_ for x_ in nc_unans if "lines)" in x_]
        fix49.append(f"{len(nc_unans)} NEEDS CONTEXT line(s) of the worker files have no `needs context:` line, or more than one, in the Unverifiable section"
                     + ("" if nc_sec else " (the report holds no `## Unverifiable` section: write it)") + " — read "
                     "each (`python3 .llm-sast-scanner-cache/recheck.py --needs-context` lists them) and write `needs context: <lens>/p<n>:<line> — "
                     "<path:line of the sink> — <what is missing>`, `— carried by <the report's id for it: its body block's or its Unverifiable "
                     "entry's, never a worker record's>` or `— mention: <what the line restates, when it judges nothing itself>`"
                     + (": no answer: " + ", ".join(none_[:8]) + (f" … and {len(none_) - 8} more" if len(none_) > 8 else "") if none_ else "")
                     + ("; " if none_ and many_ else ": " if many_ else "")
                     + ("answered more than once, keep the one answer that holds: " + ", ".join(many_[:8]) if many_ else ""))
    fix49 += nc_noform[:4] + ([f"… and {len(nc_noform) - 4} more answers in no form"] if len(nc_noform) > 4 else [])
    if nc_stray:
        fix49.append(f"`needs context:` lines at {', '.join(nc_stray[:3])} — no NEEDS CONTEXT line there: delete each, or move it to the line it "
                     "answers — a line is written only for a line `--needs-context` lists, and an earlier run's answer names that run's worker lines")
    if nc_rep:
        t_, v_ = nc_rep[0]
        fix49.append(f"one `mention:` text naming no line or id, `{t_[:80]}`, answers {len(v_)} lines of {len({k_[0] for k_ in v_})} worker files, so it says what none of them is: "
                     "read each and name its sink and missing fact, the id that carries it, or the line or id whose judgement it restates: " + ", ".join(f"`{k_[0]}:{k_[1]}`" for k_ in v_[:6]))
    emit("needs context", f"lines {len(nc_keys)} | answered observation {nc_kind['observation']} | carried {nc_kind['carried']} | mention {nc_kind['mention']} | "
         f"unanswered {len(nc_unans)} | lines at no marker {len(nc_stray)} | answers in no form {len(nc_noform)} | repeated mentions {len(nc_rep)}",
         None, not fix49, "; ".join(fix49) or None)

    # 27. summary table — the Executive Summary's severity table against the records under each heading and the histogram
    SEVS = ["Critical", "High", "Medium", "Low", "Informational"]
    summ_m = re.search(r"^## Executive Summary\s*$", body_text, re.M | re.I)
    summ_sec = body_text[summ_m.end():].split("\n## ", 1)[0] if summ_m else ""
    # the FIRST table of the section is the severity table (the template opens with it, after any warning a flow requires);
    # a later comparison table with a `| High | 5 | 7 |` row is not this table
    # the severity table is the first whose header opens `Severity`: a warning that lists uncovered partitions or
    # non-converged lenses in a table of its own comes first and is not this table; failing such a header, the first table
    summ_tables = re.findall(r"(?:^\|.*\n?)+", summ_sec, re.M)
    sev_headed = [x for x in summ_tables if re.match(r"^\|\s*\**\s*Severity\b", x, re.I)]
    summ_tbl = (sev_headed or summ_tables or [""])[0]
    summ_rows = [(m.group(1).capitalize(), int(m.group(2))) for m in re.finditer(r"^\|\s*\**(Critical|High|Medium|Low|Informational|Total)\**\s*\|\s*\**(\d+)\**\s*\|", summ_tbl, re.M | re.I)]
    table_counts = dict(summ_rows)
    summ_dup = len(summ_rows) - len(table_counts)  # one row each: a label twice is a table nobody can read off
    body_counts = {s: 0 for s in SEVS}
    for b in blocks:
        tag = RECORD_RX.match(b).group(1).upper()
        body_counts["Informational" if tag.startswith("INFO") else tag.capitalize()] += 1
    # the histogram's own lines (`Critical: <n>` or a `| Critical | <n> |` row) in its section; failing that, the stated
    # count of the Body/histogram reconciliation line `critical: <counted> / <stated>`
    hist_sec = appendix.split("Severity Histogram", 1)[1].split("\n###", 1)[0] if "Severity Histogram" in appendix else appendix
    hist_counts = {m.group(1).capitalize(): int(m.group(2)) for m in re.finditer(r"^\|?\s*\**(Critical|High|Medium|Low|Informational)\**\s*[:|]\s*(\d+)\s*\|?\s*$", hist_sec, re.M | re.I)}
    for m in re.finditer(r"^(critical|high|medium|low|informational):\s*(\d+)\s*/\s*(\d+)\s*$", appendix, re.M | re.I):
        hist_counts.setdefault(m.group(1).capitalize(), int(m.group(3)))
    summ_parts = [f"{s.lower()} {table_counts.get(s, 'absent')}={body_counts[s]}={hist_counts.get(s, 'absent')}" for s in SEVS]
    summ_total = table_counts.get("Total")
    summ_ok = all(s in table_counts and table_counts[s] == body_counts[s] == hist_counts.get(s) for s in SEVS) and summ_total == sum(body_counts.values()) and summ_dup == 0
    # the table's Confirmed and Likely columns split each severity by the confidence tag that closes its records' headings
    # (`[CONFIRMED]` or `[LIKELY]`), found by the header's own names so the columns may stand in either order
    hdr = next((l_ for l_ in summ_tbl.splitlines() if l_.strip().startswith("|")), "")
    cols = [re.sub(r"[*`_]", "", c_).strip().lower() for c_ in hdr.strip().strip("|").split("|")]
    i_c = cols.index("confirmed") if "confirmed" in cols else None
    i_l = cols.index("likely") if "likely" in cols else None
    conf_body = {s: [0, 0, 0] for s in SEVS}  # confirmed, likely, untagged
    for b in blocks:
        tag = RECORD_RX.match(b).group(1).upper()
        sev_ = "Informational" if tag.startswith("INFO") else tag.capitalize()
        ct = re.findall(r"\[(CONFIRMED|LIKELY)\]", b.splitlines()[0].upper())
        conf_body[sev_][0 if ct and ct[-1] == "CONFIRMED" else 1 if ct else 2] += 1
    conf_tbl = {}
    if i_c is not None and i_l is not None:
        for l_ in summ_tbl.splitlines():
            cells = [re.sub(r"[*`]", "", c_).strip() for c_ in l_.strip().strip("|").split("|")]
            lab = cells[0].capitalize() if cells else ""
            if lab in SEVS + ["Total"] and len(cells) > max(i_c, i_l) and cells[i_c].isdigit() and cells[i_l].isdigit():
                conf_tbl.setdefault(lab, (int(cells[i_c]), int(cells[i_l])))
    conf_want = {s: (conf_body[s][0], conf_body[s][1]) for s in SEVS}
    conf_want["Total"] = (sum(v[0] for v in conf_want.values()), sum(v[1] for v in conf_want.values()))
    untagged = sum(v[2] for v in conf_body.values())
    conf_ok = bool(conf_tbl) and all(conf_tbl.get(k) == conf_want[k] for k in SEVS + ["Total"]) and untagged == 0
    summ_ok = summ_ok and conf_ok
    fmt_c = lambda k: (f"{conf_tbl[k][0]}/{conf_tbl[k][1]}" if k in conf_tbl else "absent") + f"={conf_want[k][0]}/{conf_want[k][1]}"
    conf_part = (" | confirmed/likely " + " ".join(f"{k.lower()} {fmt_c(k)}" for k in SEVS + ["Total"]) if (i_c is not None and i_l is not None)
                 else " | confirmed/likely columns absent") + (f" | records without a [CONFIRMED] or [LIKELY] tag {untagged}" if untagged else "")
    summ_fix = None if conf_ok else ("the Executive Summary's severity table reads `| Severity | Findings | Confirmed | Likely |`, each row's Confirmed and Likely the records under that heading whose heading closes with `[CONFIRMED]` or `[LIKELY]`, the two summing to its Findings, Total's their sums: "
                                     + ", ".join(f"{k} {conf_want[k][0]}/{conf_want[k][1]}" for k in SEVS + ["Total"])
                                     + ("" if not untagged else f" — and every record's heading closes with its confidence tag: {untagged} do not"))
    emit("summary table", f"{'present' if table_counts else 'absent'} | " + " | ".join(summ_parts) + f" | total {summ_total if summ_total is not None else 'absent'} = {sum(body_counts.values())}" + (f" | duplicated rows {summ_dup}" if summ_dup else "") + conf_part, None, summ_ok, summ_fix)

    # 50. unverifiable summary — the Executive Summary's severity table holds, after Total, a row `| Unverifiable | <u> |`,
    # `u` the entries of the Unverifiable section, which Total does not count, and the summary's sentences name each entry
    # by its id: one report held nine Unverifiable entries two thousand lines down while its summary table showed only the
    # five severities. With no entry the row reads 0, or stands absent.
    unv_ids = []
    for l_ in nc_section(report).splitlines():
        h_ = None if NC_ANS_RX.match(l_) else entry_rx.match(l_)
        if h_ and (not h_.group(1).upper().startswith("VULN-") or re.search(r"(?i)\[UNVERIFIABLE\]", l_)) and h_.group(1).upper() not in unv_ids:
            unv_ids.append(h_.group(1).upper())
    # the row's label opens `Unverifiable` (`Unverifiable findings`, `Unverifiable (not in Total)`), its count the first
    # number of its second cell (`10`, `**10**`, `10 entries`)
    unv_row = re.search(r"(?mi)^\|\s*[*_`]*\s*Unverifiable\b[^|]*\|\s*[*_`]*\s*(\d+)[^|]*\|", summ_tbl)
    unv_n = int(unv_row.group(1)) if unv_row else None
    # the names are read in the summary outside its severity table: a second table listing the entries names them too
    summ_text = summ_sec.replace(summ_tbl, "\n").upper() if summ_tbl else summ_sec.upper()
    unv_unnamed = [x_ for x_ in unv_ids if not re.search(r"(?<![\w-])" + re.escape(x_) + r"(?![\w-])", summ_text)]
    # an UNV id on a line no entry opens — another line of the section that is not an answer, or the `body record` cell of
    # an `unverifiable` row — is an entry in a shape no item reads (`### UNV-001. <title>`) when the row stands absent or
    # counts more than the entries read: a count of the readable entries alone told a writer `| Unverifiable | 0 |` over
    # nine. A sentence's mention of another id, under a row that counts the entries, is no such entry.
    unv_loose = []
    for l_ in nc_section(report).splitlines():
        if not NC_ANS_RX.match(l_):
            unv_loose += [x_.upper() for x_ in re.findall(r"(?i)(?<![\w/-])(UNV(?:ERIFIABLE)?-\d{1,9})(?![-\w])", l_)]
    for c_ in table_rows:
        if c_[4].lower() == "unverifiable":
            unv_loose += [x_.upper() for x_ in re.findall(r"(?i)(?<![\w/-])(UNV(?:ERIFIABLE)?-\d{1,9})(?![-\w])", c_[6])]
    unv_unread = [x_ for x_ in dict.fromkeys(unv_loose) if x_ not in unv_ids]
    unv_shape = bool(unv_unread) and (unv_n is None or unv_n > len(unv_ids))
    unv_ok = (unv_n == len(unv_ids) if unv_ids else unv_n in (None, 0)) and not unv_unnamed and not unv_shape
    unv_names = (f": not named {', '.join('`' + x_ + '`' for x_ in unv_unnamed[:8])}{f' and {len(unv_unnamed) - 8} more' if len(unv_unnamed) > 8 else ''}"
                 if unv_unnamed else "")
    unv_fix = None if unv_ok else (
        (f"{len(unv_ids)} line{'' if len(unv_ids) == 1 else 's'} of the Unverifiable section read as entries, and {', '.join('`' + x_ + '`' for x_ in unv_unread[:8])}"
         f"{f' and {len(unv_unread) - 8} more' if len(unv_unread) > 8 else ''} {'is' if len(unv_unread) == 1 else 'are'} named outside any line that reads as one — an entry the checker cannot read is not an absent one: an entry's line opens with its id, "
         "after any `#` marks and its `[UNVERIFIABLE]` tag, then ` — ` and its title (`### [UNVERIFIABLE] UNV-001 — <title>`), and the Executive Summary's `| Unverifiable | <u> | n/a | n/a |` "
         "row after Total counts the entries, its sentences naming each by its id and title" + unv_names) if unv_shape else
        (f"the Executive Summary's severity table holds, after its Total row, `| Unverifiable | {len(unv_ids)} | n/a | n/a |` — the entries "
         "of the Unverifiable section, which Total does not count — and the summary's sentences name each entry by its id and title" + unv_names))
    emit("unverifiable summary", f"entries {len(unv_ids)} | table row {unv_n if unv_n is not None else 'absent'} | named in the summary {len(unv_ids) - len(unv_unnamed)}/{len(unv_ids)}"
         + (f" | ids no entry line opens {len(unv_unread)}" if unv_unread else ""), None, unv_ok, unv_fix)

    # 51. merge severity — a block never reads below a record merged into it by more than the one level a `DOWNGRADED` or
    # `DISPUTED` verdict on it names: of two records of one finding the higher worker severity is the kept one, and Step 6
    # alone may lower it (one same-key merge in sixteen in past reports kept the lower record, its block below a severity
    # no verdict had lowered); a merged record whose severity cannot be read is counted, not judged
    RANK51 = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "INFORMATIONAL": 1}
    n51, unread51, bad51 = 0, 0, []
    for c in merged_rows:
        t51 = body_by_id.get(c[6].upper())
        blk51 = block_id.get(c[6].upper()) if t51 else None
        if not t51 or not blk51:
            continue  # a merged row with no kept body block is item (4)'s and (1)'s
        n51 += 1
        m_sev = record_sev(c[0])
        h51 = RECORD_RX.match(blk51.splitlines()[0]) if blk51.strip() else None
        if not m_sev or not h51:
            unread51 += 1
            continue
        b_sev = h51.group(1).upper()
        adv51 = (adversarial(blk51) or "").lstrip("*` ")
        allow51 = 1 if re.match(r"(?i)(DOWNGRADED|DISPUTED)\b", adv51) else 0
        if RANK51.get(b_sev, 0) < RANK51.get(m_sev, 0) - allow51:
            bad51.append((c, t51, m_sev, b_sev, allow51))
    fix51 = None
    if bad51:
        # one hint per kept block: the highest record merged into it becomes the `body` row, every other record of the
        # finding — the kept one included — is merged into it
        by_blk51: dict = {}
        for c, t_, m_, b_, a_ in bad51:
            by_blk51.setdefault(t_[6].upper(), []).append((c, t_, m_, b_, a_))
        hints51 = []
        for grp_ in by_blk51.values():
            top_ = max(grp_, key=lambda g_: RANK51.get(g_[2], 0))
            c, t_, m_, b_, a_ = top_
            if group_merge(c, t_):
                # a group overlap stays in the block that holds the group's line: the block is raised, never turned round
                hints51.append(f"`{t_[6]}` is a {b_} block holding the group overlap `{c[0]}` ({m_}) — a group's block reads at the highest severity among its lines: render it at {m_}, its row's verdict Step 6's at {m_}")
                continue
            others_ = [f"`{t_[0]}`"] + [f"`{g_[0][0]}`" for g_ in grp_ if g_ is not top_]
            hints51.append(f"`{t_[6]}` is a {b_} block{' whose verdict allows one level' if a_ else ''} holding "
                           + ", ".join(f"`{g_[0][0]}` ({g_[2]})" for g_ in grp_)
                           + f" — keep `{c[0]}`'s record as the `body` row at {m_} (its `Worker record:` line and cells follow it), "
                           + f"make {' and '.join(others_)} `merged` into it, and let Step 6 judge any downgrade")
        fix51 = "; ".join(hints51[:4]) + (f" … and {len(hints51) - 4} more blocks" if len(hints51) > 4 else "")
    emit("merge severity", f"merged records above their kept block {len(bad51)} | unreadable {unread51} | merged rows read {n51}",
         None, not bad51, fix51)

    # 52. long lines — no line of the report outside a fenced code block is longer than LINE_LIMIT bytes: a file reader
    # keeps only a line's first 2,000 bytes, and a later run reads this report (its carried blocks, its verdicts) and
    # a repair reads its draft; a block's field stays one line, as STEP 3's layout reads it (item 40), so it is shortened,
    # a table row is shortened cell by cell, and any other line is broken between its sentences or items. A carried
    # block's lines are not counted: item (26) holds them to the earlier report's words
    # a carried block is an earlier report's, copied word for word: its lines are exactly the ones item (26) compares
    # with its source — the body split at record headings as `blocks` splits it, each carried block up to its first
    # `## ` line — so no line item (26) holds to the source's words is one this item asks to change
    rep_lines52 = report.split("\n")
    carried52 = set()
    starts52 = [m_.start() + 1 for m_ in re.finditer(r"\n(?=(?:#+ )?\[(?i:CRITICAL|HIGH|MEDIUM|LOW|INFO[A-Z]*)\] VULN-)", body_text)]
    for a_, b_ in zip(starts52, starts52[1:] + [len(body_text)]):
        blk_ = body_text[a_:b_].rstrip("\n")  # its last line, never the newline before the next record's heading
        if not RECORD_RX.match(blk_) or not re.search(r"^Carried: confirmed ", blk_, re.M):
            continue
        cut_ = blk_.find("\n## ")
        end_ = a_ + (cut_ if cut_ >= 0 else len(blk_))
        first_ = body_text.count("\n", 0, a_) + 1
        carried52.update(range(first_, body_text.count("\n", 0, end_) + 2))  # 1-based line numbers of the region
    long52 = [(n_, b_) for n_, b_ in long_text_lines(report) if n_ not in carried52]
    def kind52(n_: int) -> str:
        l_ = rep_lines52[n_ - 1].lstrip()
        if l_.startswith("|"):
            return ("a table row: shorten its cells — a disposition-table row in `disposition-table.md`, which the appendix "
                    "copies, then the row copied again and its block re-rendered from it")
        if ALSO_RX.match(l_):
            return "an `Also at:` list: continue it on a further `Also at:` line right after it, no sink dropped"
        if re.match(r"^\**([A-Z][A-Za-z ]*?):\**\s", l_) and re.match(r"^\**([A-Z][A-Za-z ]*?):", l_).group(1) in ("Worker record", "Entry point", "CWE", "File", "Description", "Impact", "Flow", "Evidence", "Judge", "Adversarial", "Remediation", "Reference"):
            return "a block field, which stays one line: shorten it"
        return "prose: break it between its sentences or items"
    fix52 = ("a file reader keeps only a line's first 2,000 bytes (UTF-8 — an em dash counts three): "
             + "; ".join(f"line {n_} ({b_} bytes) is {kind52(n_)}" for n_, b_ in long52[:4])
             + (f" … and {len(long52) - 4} more" if len(long52) > 4 else "")) if long52 else None
    emit("long lines", f"{len(long52)} over {LINE_LIMIT} bytes outside code blocks" + (f" (lines {', '.join(str(n_) for n_, _ in long52[:6])}{' …' if len(long52) > 6 else ''})" if long52 else ""),
         None, not long52, fix52)

    # 53. dispute clauses — a `DISPUTED` doubt names the concrete thing the record cites that it is about and what about it
    # is uncertain (base skill, Step 6's verdict table and the note after it): a fact the repository does not show and a
    # doubt that names nothing are no grounds. Read mechanically: a fresh block (never a same-commit carried one, which
    # keeps its source's words) whose `DISPUTED` clause cites nothing but its own sink — its `File:` path, with or without
    # its line — or nothing at all, in words, identifiers set aside, that such clauses at two other sinks share, is
    # boilerplate: one fresh run disputed 78 of 355 findings in two such sentences, each citing its own sink, and every one
    # passed item (2) and the identical-text rule because the sinks differed; one doubt about the code at one sink, which
    # several routes reach (one record per route), is one doubt, however many rows repeat it
    def sink_only53(clause_: str, sink_: str | None) -> bool:
        ids_ = [(x_ + z_ or y_).strip() for x_, z_, y_ in re.findall(r"`([^`]+)`(:[0-9]+(?:[-\u2013][0-9]+)?)?|([A-Za-z0-9_./-]+:[0-9]+(?:[-\u2013][0-9]+)?(?::[0-9]+)?)", clause_)]
        if not ids_:
            return True
        if not sink_:
            return False
        s_path, _, s_line = sink_.partition(":")
        s_line = s_line.split("-")[0]
        for i_ in ids_:
            # a path with or without its line (and a column), `./` or `/` before it; its components match the sink's
            # from the end — `Dockerfile:12` and `.env:3` are paths, `a.py` is no suffix of `src/data.py`, `sslmode` no path
            m_ = re.match(r"^(?:\./|/)?(.*?)(?::(\d+)(?:[-\u2013](\d+))?)?(?::\d+)?$", i_)
            if not m_ or not m_.group(1):
                return False
            i_path = m_.group(1)
            if not (i_path == s_path or s_path.endswith("/" + i_path) or i_path.endswith("/" + s_path)):
                return False
            if m_.group(2) and s_line.isdigit():
                lo_, hi_ = int(m_.group(2)), int(m_.group(3) or m_.group(2))
                if not lo_ <= int(s_line) <= hi_:
                    return False
        return True
    def shape53(clause_: str) -> str:
        s_ = re.sub(r"`[^`]+`(?::[0-9]+(?:[-\u2013][0-9]+)?)?|[A-Za-z0-9_./-]+:[0-9]+(?:[-\u2013][0-9]+)?(?::[0-9]+)?", "<id>", clause_)
        return re.sub(r"[\s.;,:!]+$", "", re.sub(r"\s+", " ", s_)).strip().lower()
    disputed53, cands53 = 0, []
    for b_ in blocks:
        a_ = adversarial(b_) or ""
        if not a_.startswith("DISPUTED") or re.search(r"^Carried: confirmed ", b_, re.M):
            continue
        disputed53 += 1
        clause_ = a_.split(" — ", 2)[1] if a_.count(" — ") >= 1 else ""
        if not clause_.strip():
            continue  # a cell with no clause is item (2)'s, which counts it invalid
        if sink_only53(clause_, file_of(b_)):
            cands53.append((RECORD_RX.match(b_).group(2), shape53(clause_), file_of(b_) or ""))
    sinks53: dict[str, set] = {}
    for _, s_, k_ in cands53:
        sinks53.setdefault(s_, set()).add(k_)
    kinds53 = [s_ for s_, ks_ in sorted(sinks53.items(), key=lambda kv: -len(kv[1])) if len(ks_) >= 3]
    boiler53 = [(v_, s_) for v_, s_, _ in cands53 if s_ in kinds53]
    shapes53 = Counter(s_ for _, s_ in boiler53)
    fix53 = ("a `DISPUTED` doubt names the concrete thing the record cites that it is about — a check, a value, a condition, in "
             "backticks or as its `file:line` — and the property of it in doubt; a fact the repository does not show and a doubt "
             "that names no property but the finding's exploitability or impact are no grounds (the base skill's note after "
             "Step 6's verdict table): "
             + "; ".join(f"`{s_ if len(s_) <= 90 else s_[:90].rsplit(' ', 1)[0] + ' …'}` on {shapes53[s_]} blocks ({', '.join([v_ for v_, x_ in boiler53 if x_ == s_][:3])}"
                         f"{' …' if shapes53[s_] > 3 else ''})" for s_ in kinds53[:3])
             + " — re-judge each: `STANDING` with the open question in its rationale, `DOWNGRADED` for a trigger that holds, or "
             "`DISPUTED` naming the property in doubt; a verdict the continuity join carried is voided as STEP 3's continuity "
             "rule gives") if boiler53 else None
    emit("dispute clauses", f"{len(boiler53)} boilerplate in {len(kinds53)} shapes (of {disputed53} disputed)", None, not boiler53, fix53)

    # 54. withdrawn guards — a Step 6 withdrawal drops a finding the Judge passed, so its appendix line cites the
    # `file:line` of the code its reason rests on — for a guard that stops the attack, the guard's; a dependency's at the
    # line of its code that shows it, never a version alone; another ground at the line that shows it — a line of a file
    # the target holds, never the row's own sink (base skill, Step 6's verdict table and the note after it): one
    # writer, told a settled question decides, withdrew three findings on "the pinned library encodes it" and cited nothing
    step6_54 = [(n_, why) for n_, why in wd_lines if re.search(r"(?i)\bstep[\s-]*6\b", why) and not re.match(r"(?i)^[\s`*_:]*citation\b", why)]
    wd_sink54 = {cell_id(c).upper(): canon(rel(c[2])) for c in table_rows if c[4].lower() == "withdrawn"}
    def cites54(n_: str, why: str) -> bool:
        # a line of a file the target holds, within it, and not the withdrawn row's own sink: the code the reason rests on
        own_ = wd_sink54.get(n_.upper())
        for m_ in FILE_LINE_RX.finditer(why):
            path_, _, ln_ = m_.group(0).rpartition(":")
            n_l = target_lines(path_)
            if n_l is None or not ln_.isdigit() or not 1 <= int(ln_) <= n_l:
                continue
            if own_ and canon(rel(m_.group(0))) == own_:
                continue
            return True
        return False
    bare54 = [n_ for n_, why in step6_54 if not cites54(n_, why)]
    fix54 = ("a Step 6 withdrawal cites the `file:line` of the code its reason rests on, a line of a file the target holds and "
             "never the row's own sink — a guard that stops the attack on every path and target, at its `file:line`; a "
             "dependency's at the line of its code that shows it, never a version alone; operator self-harm or a test-only "
             "caller at the line that shows it, such as the entry point the operator runs: "
             + ", ".join(f"`{v_}`" for v_ in bare54[:4]) + (" …" if len(bare54) > 4 else "")
             + " — its line reads `withdrawn: <worker record> — Step 6: <guard file:line> <one line>`, or the record is re-judged "
             "as the rest of Step 6 gives") if bare54 else None
    emit("withdrawn guards", f"{len(bare54)} Step 6 withdrawals citing no file:line (of {len(step6_54)})", None, not bare54, fix54)

    # 28. previous run residual — STEP 1 preserved the previous plan as previous-run-<started>/scan-plan.md and recorded its
    # last `recheck: mismatches` line as `previous run residual: <n> — <items>` (or `none` on a run with no earlier plan)
    prev_plan_path = cache / f"previous-run-{started}" / "scan-plan.md" if started else None
    prev_plan = read(prev_plan_path) if prev_plan_path else ""
    # an empty previous-run directory is no earlier run: only one holding something (moved worker files) proves a plan was left behind
    try:
        prev_dir_exists = bool(prev_plan_path and prev_plan_path.parent.is_dir() and any(prev_plan_path.parent.iterdir()))
    except OSError:
        prev_dir_exists = False
    # the cache is an earlier run's (item 16's reading): its plan existed, so a copy of it must stand in previous-run-<started>/
    prev_dir_exists = prev_dir_exists or prior_run
    # a copy is the previous plan as it stood: its own `started:` earlier than this run's, and — when that run's report was
    # written — more than the at-dispatch copy it took (a plan copied at dispatch holds no line the run wrote after it)
    # a plan an earlier version of this skill wrote holds none of the rows this flow's STEP 1 writes — no `started:`, no
    # `workers dispatched:`, no `recheck:` set and no residual row — so it resolved nothing this flow reads: its residual
    # is `none`, and its missing `started:` proves nothing about the copy. A cache holding an earlier stamped run (item
    # 16's at-dispatch copies and previous-run directories) came after that version, so a copy there without those rows
    # is a skeleton, not an earlier version's plan
    legacy28 = bool(prev_plan) and not older_ and not re.search(r"(?m)^(?:started:|workers dispatched:|recheck: mismatches|previous run residual:)", prev_plan)
    copy_fake = None
    if prev_plan and started and not legacy28:
        ps_m = re.search(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", row(prev_plan, "started:") or "")
        if not ps_m or ps_m.group(0) >= started:
            copy_fake = f"its `started:` {ps_m.group(0) if ps_m else 'is absent'}{' is not earlier than this run' if ps_m else ''}"
        else:
            ad_ = cache / f"scan-plan.md.at-dispatch-{ps_m.group(0)}"
            try:
                rep_after = any(m_.group(0) > ps_m.group(0) and m_.group(0) < started for q_ in target.glob("sast_report-*.md") for m_ in [re.search(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", q_.name)] if m_)
            except OSError:
                rep_after = False
            if rep_after and ad_.exists() and read(ad_) == prev_plan:
                copy_fake = "it is that run's at-dispatch copy, though the run went on to write its report"
    # the command suffix is cut before parsing: `recheck: mismatches 0 — python3 …` has no items, and a lazy group once took the command as one
    last_mm = [m for m in (re.match(r"^recheck: mismatches (\d+)(?: — (.*))?$", l.split(" — python3", 1)[0].rstrip()) for l in prev_plan.splitlines() if l.startswith("recheck: mismatches ")) if m]
    last_mm = [(m.group(1), m.group(2)) for m in last_mm]
    has_mm_line = any(l.startswith("recheck: mismatches ") for l in prev_plan.splitlines())
    if last_mm:
        n_res, items_res = int(last_mm[-1][0]), {s.strip() for s in (last_mm[-1][1] or "").split(",") if s.strip()}
        expected_res = f"{n_res}" + (f" — {', '.join(sorted(items_res))}" if items_res else "")
    else:
        # a previous run that ended before its recheck set (stopped, killed, crashed) resolved nothing: its own
        # `previous run residual:` row is what this run inherits, so the copy's row is the expectation when it has no recheck line
        n_res, items_res = None, set()
        expected_res = ("copy present, recheck line unreadable" if has_mm_line else "copy present, no recheck set and no residual row") if prev_plan else (("copy absent" + (f" — the cache holds an earlier run's files ({'from ' + prev_stamp if prev_stamp else str(len(old_files)) + ' older than started:'}), so its plan was overwritten, not copied to previous-run-{started}/" if prior_run else "")) if prev_dir_exists else "none")
    inherited = row(prev_plan, "previous run residual:") if (prev_plan and not last_mm and not has_mm_line) else None
    if legacy28:
        expected_res = "none (an earlier version's plan: no recheck set, no residual row)"
    row_res = row(plan, "previous run residual:")
    def res_parse(text: str | None):
        """`<n>` and its items (after ` — `), or None; a trailing parenthetical or note after the count is ignored, and so is
        the recheck line's own trailing command (` — python3 .llm-sast-scanner-cache/recheck.py`), which a row copied from
        the line carries and which names no item."""
        text = re.sub(r"\s+—\s+python3?\s+\S*recheck\.py\b.*$", "", (text or "").strip())
        m = re.match(r"^(\d+)\b(.*)$", text)
        if not m:
            return None
        tail = m.group(2)
        return int(m.group(1)), (tail.split(" — ", 1)[1] if " — " in tail else "")
    rm = res_parse(row_res)
    def items_of(text: str) -> set:
        # `0 — none` and `0` say the same thing: no items
        return {s.strip() for s in (text or "").split(",") if s.strip() and s.strip().lower() != "none"}
    if last_mm:
        res_ok = bool(rm) and rm[0] == n_res and items_of(rm[1]) == items_res
    elif inherited is not None:
        im = res_parse(inherited)
        if im:
            n_inh, items_inh = im[0], items_of(im[1])
            expected_res = f"{n_inh}" + (f" — {', '.join(sorted(items_inh))}" if items_inh else "") + " (inherited: the copy has no recheck set)"
            res_ok = bool(rm) and rm[0] == n_inh and items_of(rm[1]) == items_inh
        else:
            expected_res = f"{inherited} (inherited: the copy has no recheck set)"
            res_ok = (row_res or "").strip().lower().split()[:1] == inherited.strip().lower().split()[:1]  # the word itself, decoration aside
    elif legacy28:
        res_ok = re.match(r"^none\b", (row_res or "").strip().lower()) is not None  # `0 — none` would claim a set it never recorded
    elif prev_plan or prev_dir_exists:
        res_ok = False  # an earlier plan existed and its residual could not be read: the copy is missing, or its recheck line does not parse
    else:
        res_ok = re.match(r"^none\b", (row_res or "").strip().lower()) is not None  # `none`, or `none — no earlier plan`
    # `stale worker files moved: <n>` counts the worker files the previous-run directory holds: one STEP 1 wrote `0` and
    # left twenty-seven earlier files where this run's workers would write
    stale_v = corrected(plan, "stale worker files moved:")  # a row above `workers dispatched:` is corrected by appending
    try:
        stale_dir = len(list(prev_plan_path.parent.glob("deep-*-results.md"))) if prev_plan_path and prev_plan_path.parent.is_dir() else 0
    except OSError:
        stale_dir = 0
    # an earlier file still where this run's workers write: never moved (a completed run's workers overwrote theirs)
    stale_left = sorted(q_.name for q_ in old_files if q_.name.startswith("deep-") and q_.parent == cache) if prior_run else []
    stale_ok = (not prior_run or (stale_v is not None and stale_v == stale_dir)) and not stale_left
    if copy_fake:
        res_ok = False
    # D1 keeps architecture-threat-model.md across a re-scan at an unchanged commit; in this flow STEP 1 writes it anew
    # when the previous plan's `wrapper:` row differs from this run's (or it holds none), its entry points read under
    # rules the new version changed — one run built its entry list from such a kept model and missed a listed kind
    tm28 = None
    tm_p28 = cache / "architecture-threat-model.md"
    # the rule holds from the wrapper version that wrote it: a run whose plan names an earlier version kept the model rightly
    v28_ = re.search(r"v(\d+)\.(\d+)\.(\d+)", row(plan, "wrapper:") or "")
    rule28 = bool(v28_) and tuple(int(x_) for x_ in v28_.groups()) >= (2, 26, 11)
    if rule28 and prev_plan and not copy_fake and st_ts16 is not None and tm_p28.exists():
        pw_, tw_ = (row(prev_plan, "wrapper:") or "").strip(), (row(plan, "wrapper:") or "").strip()
        if pw_ != tw_:
            t_ = mtime_of(tm_p28)
            if t_ is not None and t_ < st_ts16:
                tm28 = (pw_ or "none", tw_ or "none")
    hint28 = [x_ for x_ in (
        f"the previous run's plan is copied as it stands to previous-run-{started}/scan-plan.md before this plan is written, and its last `recheck: mismatches` line becomes `previous run residual:`" if (prior_run and not prev_plan) else "",
        f"the copy in previous-run-{started}/ is not the previous plan as it stood — {copy_fake}" if copy_fake else "",
        f"`stale worker files moved: <n>` counts the earlier worker files moved into previous-run-{started}/ — every `deep-*-results.md` older than `started:`" + (f", {len(stale_left)} still in the cache (first `{stale_left[0]}`)" if stale_left else f", {stale_dir} there") if not stale_ok else "",
        ("a copy an earlier version of this skill wrote — no `started:`, `workers dispatched:`, recheck set or residual row — gives `previous run residual: none`" if legacy28 else f"`previous run residual:` reads the copy's last `recheck: mismatches` line: `{expected_res}`") if (not res_ok and prev_plan and not copy_fake) else "",
        f"the skill version changed since `architecture-threat-model.md` was written (`{tm28[0]}` → `{tm28[1]}`): STEP 1 writes it anew and derives the entry list from the code" if tm28 else "") if x_]
    emit("previous run residual", expected_res + (f" | copy not the previous plan: {copy_fake}" if copy_fake else "") + (" | threat model kept across a version change" if tm28 else "") + (f" | stale worker files moved {stale_v if stale_v is not None else 'absent'}, {stale_dir} in previous-run-{started}/" if prior_run else "") + (f" | earlier worker files left in the cache {len(stale_left)}" if stale_left else ""),
         row_res if row_res is not None else "absent", res_ok and stale_ok and not tm28,
         None if (res_ok and stale_ok and not tm28) or not hint28 else "a STEP 1 line: " + "; ".join(hint28))

    # 29. uncovered partitions — roster pairs whose worker file is absent or does not end with a complete sentinel, against the
    # plan's `worker not run:` lines and the report's `uncovered:` lines; no pair may hold more than three dispatch lines
    SENT_RX = re.compile(r"^<!-- LLM-SAST-COMPLETE lens=([a-z-]+) partition=(p\d+) files=([\d,]+)/([\d,]+) lines=([\d,]+)/([\d,]+) passes=(\d+)[^\n]*-->\s*$")
    def num(s: str) -> int:
        return int(s.replace(",", ""))
    text_by_name = {p.name: t for p, t in worker_text.items()}
    pairs29 = sorted(set(all_pairs) or {pr for pr, _, _ in dispatch})
    def complete(pair: str) -> bool:
        lens, part = pair.split("/", 1)
        text = text_by_name.get(f"deep-{lens}-{part}-results.md")
        if text is None:
            return False
        tail = [l for l in text.splitlines() if l.strip()]
        m = SENT_RX.match(tail[-1].strip()) if tail else None
        return bool(m) and m.group(1) == lens and m.group(2) == part and num(m.group(3)) >= num(m.group(4)) and num(m.group(5)) >= num(m.group(6)) and int(m.group(7)) > 0
    # a complete sentinel is not a passed gate: the pair's LAST `gate:` line may still fail on header, pinning, phrase, paths,
    # headings, references or copied, and the cap records that pair `worker not run:` just the same
    GATE_RX = GATE_LINE_RX
    last_gate = {m.group(1): m for m in GATE_RX.finditer(plan)}
    def gate_failed(pair: str) -> bool:
        m = last_gate.get(pair)
        if not m:
            return False  # no parseable gate line: the sentinel check alone decides
        return gate_line_passes(m.group(0)) is False  # `0/0` paths on a file with records is a fail, as the gate rule states
    sentinel_short = [pr for pr in pairs29 if not complete(pr)]
    gate_fails = [pr for pr in pairs29 if gate_failed(pr)]
    unfinished = sorted(set(sentinel_short) | set(gate_fails))
    not_run = not_run_pairs  # read once, above item 21, where a not-run pair also resets the streak
    uncovered_rep = sorted(set(re.findall(r"^(?:[-*] )?uncovered: ([a-z-]+/p\d+)", report, re.M)))
    attempts = Counter(pr for pr, _, _ in dispatch)
    over_cap = sorted(pr for pr, n in attempts.items() if n > 3)
    # a recorded gate line is the file as it was gated: one worker rewrote its file after its sentinel and its gate, 47
    # records to 40, and every item read the new file while the plan held the old verdict's line
    _, now29_l = gate_lines(target, cache, plan, skills, "all", with_copied=False) if skills else (True, [])
    now29 = {m_.group(1): m_.group(0) for m_ in (GATE_LINE_RX.match(l_) for l_ in now29_l) if m_}
    # a pair recorded `worker not run:` is uncovered whatever its file holds: its line is not read against the file
    stale29 = [(pr, gate_line_diff(last_gate[pr].group(0), now29[pr])) for pr in pairs29 if pr in last_gate and pr in now29 and pr not in not_run]
    stale29 = [(pr, d_) for pr, d_ in stale29 if d_]
    # whose change: the session's STEP 2 checks every gate line field by field before the writer starts, so a file that
    # changed after the writer's prompt was written changed under the writer or a repair, never the session's line
    wp_m = (cache / "writer-prompt.md").stat().st_mtime if (cache / "writer-prompt.md").is_file() else None
    def _m29(pr: str) -> float:
        try:
            return (cache / f"deep-{pr.split('/')[0]}-{pr.split('/')[1]}-results.md").stat().st_mtime
        except OSError:
            return 0.0
    stale_post = [(pr, d_) for pr, d_ in stale29 if wp_m is not None and _m29(pr) > wp_m + 1]
    stale_pre = [x for x in stale29 if x not in stale_post]
    unc_ok = unfinished == not_run == uncovered_rep and not over_cap and not stale29
    if not unc_ok and uncovered_rep == not_run and not stale_post:
        PLAN_ONLY.add("uncovered partitions")  # the report repeats the plan: what differs is the session's record
    emit("uncovered partitions",
         f"{len(unfinished)}" + (f" — {', '.join(unfinished)}" if unfinished else "") + f" (sentinel short {len(sentinel_short)}, gate failed {len(gate_fails)})" + f" | attempts over cap {len(over_cap)}" + (f" ({', '.join(f'{pr} {attempts[pr]}' for pr in over_cap)})" if over_cap else ""),
         f"worker not run {len(not_run)}" + (f" — {', '.join(f'{pr} ({attempts.get(pr, 0)} attempts)' for pr in not_run)}" if not_run else "") + f" | report uncovered {len(uncovered_rep)}" + f" | recorded gate lines off the file {len(stale29)}",
         unc_ok, "; ".join(x_ for x_ in (
             ("a worker file changed after its sentinel and its gate, before the writer started, and its recorded line was not read again — a STEP 2 line the writer leaves as it stands and names in its final message, the file's last change never gated: "
              + "; ".join(f"{pr} ({', '.join(d_)})" for pr, d_ in stale_pre[:4]) + (" …" if len(stale_pre) > 4 else "")) if stale_pre else "",
             ("a worker file changed after the writer's prompt was written — the writer and a repair read the worker files and never write them: "
              + "; ".join(f"{pr} ({', '.join(d_)})" for pr, d_ in stale_post[:4]) + (" …" if len(stale_post) > 4 else "") + " — the report is read from a file no gate read") if stale_post else "") if x_) or None)

    # 30. report name: its timestamp is the moment the report was written — never before the run's start, never after the
    # file it names. One writer named its report 22-30-00 while writing it at 22-0x and said so; no line caught it.
    if report_name:
        import datetime
        m_ts = re.search(r"sast_report-(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.md$", report_name)
        rp = target / report_name
        st_m = re.search(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", row(plan, "started:") or "")
        if not m_ts and rp.exists():
            st_n = rp.stat()
            born = getattr(st_n, "st_birthtime", None) or st_n.st_mtime
            users_n = bool(st_m) and datetime.datetime.fromtimestamp(born).strftime("%Y-%m-%d_%H-%M-%S") < st_m.group(0)
            emit("report name", f"{report_name} | no `sast_report-<date +%Y-%m-%d_%H-%M-%S>.md` timestamp in the name" + (" | a file from before this run" if users_n else ""), None, False,
                 "the `report:` row names a file from before this run's start: that file belongs to the user and is never renamed, rewritten or deleted — this run's report is written under a fresh `date +%Y-%m-%d_%H-%M-%S` name and that name appended as a new `report:` row" if users_n
                 else "rename the report to `sast_report-` and a fresh `date +%Y-%m-%d_%H-%M-%S` output, and append that name to `.llm-sast-scanner-cache/scan-plan.md` as a new `report:` row")
        if m_ts and rp.exists():
            stamp = lambda s: datetime.datetime.strptime(s, "%Y-%m-%d_%H-%M-%S").timestamp()
            # the file's last write, or its rename: `mv` keeps the write time and moves the change time, so a report
            # renamed to a fresh `date` output is read at the moment of its rename, and an invented later name at neither
            st_r = rp.stat()
            ts, wrote = stamp(m_ts.group(1)), max(st_r.st_mtime, st_r.st_ctime)
            later = ts > wrote + 1
            before = bool(st_m) and ts < stamp(st_m.group(0))
            # ownership by the file's creation, never its change time: a tag, a touch or an index write moves ctime on the
            # user's own old report; a rename keeps the creation time (st_birthtime; mtime where the platform has none)
            created = getattr(st_r, "st_birthtime", None) or st_r.st_mtime
            users = bool(st_m) and created < stamp(st_m.group(0))  # the file itself predates the run: an earlier run's report
            emit("report name", f"{m_ts.group(1)} | started {st_m.group(0) if st_m else 'absent'} | file written or renamed {datetime.datetime.fromtimestamp(wrote).strftime('%Y-%m-%d_%H-%M-%S')} | "
                 + ("a file from before this run" if users else "LATER than the file it names" if later else "BEFORE the run's start" if before else "in order"), None, not later and not before and not users,
                 "rename the report to a fresh `date +%Y-%m-%d_%H-%M-%S` output and append that name to `.llm-sast-scanner-cache/scan-plan.md` as a new `report:` row — a report's name is the moment it is written, never a chosen time" if not users else
                 "the `report:` row names a report from before this run's start: that file belongs to the user and is never renamed, rewritten or deleted — this run's report is written under a fresh `date +%Y-%m-%d_%H-%M-%S` name and that name appended as a new `report:` row")
    # recorded sets — a reading, not an item: each `recheck: mismatches` line in the plan closes a full set; a lone one is a subagent's own run
    # appended where only the session records (a reading, not a mismatch: a plan line is never removed)
    sets, lone = count_sets(read_raw(cache / "scan-plan.md"))
    STEP12 = {"script sha256", "ledger rows at start", "checks", "step 1 rows unchanged", "wave rosters", "previous run residual"}
    if MISMATCHES and all(m_ in STEP12 or m_ in PLAN_ONLY for m_ in MISMATCHES):
        # a reading, not an item: these lines are the session's STEP 1 and STEP 2 record, which no writer or repair changes
        LINES.append(f"recheck: repair none — every mismatch reads a STEP 1 or STEP 2 line ({', '.join(MISMATCHES)}), which the writer and a repair leave standing — {CMD}")
    LINES.append(f"recheck: recorded sets {sets - len(lone)} | lone mismatches lines {len(lone)}"
                 + (f" (plan line {', '.join(map(str, lone))} — a subagent's own run appended; a set enters the plan only when the session records it)" if lone else "") + f" — {CMD}")

    LINES.append(f"recheck: mismatches {len(MISMATCHES)}" + (f" — {', '.join(MISMATCHES)}" if MISMATCHES else "") + f" — {CMD}")
    put_set(LINES)
    return 1 if MISMATCHES else 0


def run() -> int:
    """main() with a guaranteed tail: an item that raises becomes a `recheck: script error` line — itself a mismatch — followed
    by the `recheck: mismatches` line, so one broken item never hides the others or leaves a set without its last line."""
    try:
        return main()
    except Exception as exc:  # noqa: BLE001 — every failure must surface as a recheck line
        import traceback
        tb = traceback.extract_tb(exc.__traceback__)
        own = [fr for fr in tb if os.path.abspath(fr.filename) == os.path.abspath(__file__)]
        where = f"line {(own or tb)[-1].lineno}" if tb else "unknown line"
        mode = next((a for a in sys.argv[1:] if a.split("=")[0] in ("--gate", "--contracts", "--roster", "--prompt", "--paths", "--checks", "--ledger-start", "--duplicates", "--needs-context", "--overlaps")), None)
        if mode:
            # a STEP 1 or STEP 2 command checks no report: its failure is its own error line, never a report mismatch
            print(f"{mode.split('=')[0][2:]}: error — script error {type(exc).__name__}: {str(exc)[:160]} at {where}; nothing checked")
            return 2
        last = LINES[-1].split(" — ")[0][len("recheck: "):][:60] if LINES else "none"  # the whole last line up to its command
        LINES.append(f"recheck: script error {type(exc).__name__}: {str(exc)[:160]} at {where}, after item `{last}` — {CMD}")
        MISMATCHES.append("script error")
        LINES.append(f"recheck: mismatches {len(MISMATCHES)} — {', '.join(MISMATCHES)} — {CMD}")
        put_set(LINES)
        return 1


if __name__ == "__main__":
    sys.exit(run())
