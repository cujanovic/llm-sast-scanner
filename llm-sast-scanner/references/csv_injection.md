---
name: csv_injection
description: CSV / formula injection when exporting user-controlled data to spreadsheets (CWE-1236)
---

# CSV / Formula Injection (CWE-1236)

Spreadsheet programs (Excel, LibreOffice Calc, Google Sheets) interpret cell values starting with `=`, `+`, `-`, `@`, or `\t` as formulas. Exporting untrusted web input into CSV/TSV without neutralization can lead to formula injection: exfiltration via `=HYPERLINK`, remote code in some configurations, or social-engineering payloads when a victim opens the export.

## Source -> Sink Pattern

**Sources** (Python):
- `RemoteFlowSource` — HTTP request parameters, form fields, DB rows originating from user input

**Sinks**:
- `CsvWriter.getAnInput()` — any CSV writer input slot (Python model)
- Web export endpoints writing `text/csv` responses
- Server-side report generators (`csv.writer`, pandas `to_csv`, Ruby CSV, Java OpenCSV)

**Sanitizers** (Python):
- `ConstCompareBarrier` — input compared to safe constant before write
- `startswith` barrier guard on object (`DataFlow::BarrierGuard<startsWithCheck>`) — prefix checks that strip/escape formula triggers

## Vulnerable Conditions

- User-supplied names, comments, ticket titles written directly to CSV download endpoints.
- Admin "export users" feature includes profile fields without formula escaping.
- Formula characters only stripped from some columns, not all free-text fields.
- UTF-8 BOM + formula combo bypassing naive filters.

## Safe Patterns

- Prefix risky cells with single quote `'` or tab so spreadsheet treats them as text (Excel).
- Strip or escape leading `=`, `+`, `-`, `@`, `\t`, `\r` (OWASP CSV Injection guidance).
- Use `.xlsx` export libraries that mark cells as text type explicitly.
- Warn users before opening exports from untrusted tenants; disable external links in Excel policy.

**Recognized sanitizers**: `startswith` checks used as barrier guards; constant-compare barriers.

## Language Patterns

### Python
- **VULN**: `writer.writerow([user_comment])` where `user_comment` from `request.form` starts with `=cmd|`
- **SAFE**: prepend `'` to cells matching `^[=+\-@]`; use OWASP escape helper before `writerow`

### JavaScript / Node
- **VULN**: `` res.send(`name,${req.query.name}\n`) `` with `name==1+1`
- **SAFE**: escape formula prefix: `if (/^[=+\-@]/.test(v)) v = "'" + v`

### Java
- **VULN**: OpenCSV writing user biography field to export servlet
- **SAFE**: `StringEscapeUtils` custom prefix; Apache Commons CSV with quoted fields + prefix neutralization

### Ruby
- **VULN**: `CSV.generate { |csv| csv << [params[:title]] }`
- **SAFE**: sanitize leading formula chars before append

For JavaScript, Java, Go, C#, Ruby, or Rust CSV export sinks, grep for `csv.write`, `to_csv`, `text/csv` responses manually.

## Example

```python
# BAD — user CSV field written directly
@app.route('/bad1')
def bad1():
    csv_data = request.args.get('csv')
    csvWriter = csv.writer(open("test.csv", "wt"))
    csvWriter.writerow(csv_data)  # formula injection if csv_data starts with =

# GOOD — prefix neutralization for = + - @
def sanitize_for_csv(data):
    unsafe_prefixes = ("+", "=", "-", "@")
    if isinstance(data, str) and data.startswith(unsafe_prefixes):
        return "'" + data
    return data
```

Sink: `CsvWriter.getAnInput()`. Sanitizer: `startswith` barrier on object before write.

## Export Surfaces in Web Apps

- Admin "Download CSV" on user tables (support tickets, CRM notes, audit logs).
- Scheduled report jobs emailed as `.csv` attachments.
- API `Accept: text/csv` content negotiation on search endpoints.
- GDPR "export my data" self-service — high-value target for stored formula payloads.

## Common False Alarms

- Internal-only exports with no user-controlled columns.
- JSON/Excel exports that do not invoke formula interpreter (verify cell type is text).
- Prefix sanitizer that only handles `=` but not `+`/`-`/`@` — partial fix, still vuln.

## Business Risk

- One malicious support ticket → finance analyst opens export → credential exfil via `HYPERLINK` to attacker server.
- Reputational harm when branded reports execute unexpected formulas.
- SOC2/ISO evidence exports become delivery vector for targeted phishing.
- B2B SaaS multi-tenant exports: one tenant poisons shared admin CSV download affecting operator workstation.

## Core Principle

Treat every CSV cell as a formula slot. Neutralize formula-leading characters on all untrusted text columns before write, or export formats that cannot execute expressions.

## Analyst Notes

1. Formula injection requires victim to **open** export in Excel/Calc — social engineering may be part of chain.
2. Tab (`\t`) and carriage-return prefixes also trigger formulas in some locales — OWASP lists `=`, `+`, `-`, `@`; extend sanitizers accordingly.
3. CSV injection is **stored** when malicious data sits in DB until periodic export — tag both `csv_injection` and root input validation gap.
4. Python CSV injection rules are heuristic — confirm sink matches `CsvWriter` model; pandas `to_csv` may need manual taint review.
5. Excel DDE and older macro vectors are out of scope for automated CSV rules; focus on formula metacharacter prefix defense.
6. Quote-doubling CSV escaping (`""`) does not neutralize formula prefixes — prefix with `'` or strip metacharacter separately from RFC-4180 quoting.
7. For Java/JS exports without automated coverage, grep `text/csv`, `Content-Disposition.*\.csv`, and `csv.writer` / `papaparse` unescaped writes.
8. Severity: typically Medium (user interaction + desktop app); raise to High when export is bulk-mailed to finance/admin roles automatically.
