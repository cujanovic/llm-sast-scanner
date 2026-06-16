---
name: ldap-injection
description: LDAP injection (CWE-090) where untrusted input alters directory search filters or distinguished names
---

# LDAP Injection (CWE-090)

LDAP injection occurs when user input is concatenated into an LDAP distinguished name (DN) or search filter without escaping. Attackers inject metacharacters to broaden searches, bypass authentication, or exfiltrate directory entries. Filter and DN injection use different metacharacter sets and escaping rules — do not apply filter escaping to DNs or vice versa.

## Filter vs DN Injection

Two distinct sinks; taint tracking and sanitizers must match the sink type.

| Sink | Example API | Injection effect |
|------|-------------|------------------|
| **Search filter** | `DirContext.search(base, filter, …)`, `DirectorySearcher.Filter`, `ldap_search(..., filter, …)` | Boolean logic tampering: `*)(uid=*))(|(uid=*` broadens `(uid=alice)` to match all users |
| **Distinguished name (DN)** | `DirContext.lookup(dn)`, `DirectoryEntry(path)`, `ldap_bind(conn, dn, …)`, ldapjs `client.search(dn, …)` | Path traversal in tree: `cn=admin)(|(cn=*` or `cn=x,ou=users` appended to base changes target entry |

- **Filter injection**: user input inside `(...)` filter expression — Polish notation, operators `&`, `|`, `!`, comparators `=`, `~=`, `>=`, `<=`.
- **DN injection**: user input in RDN components (`cn=`, `uid=`, `ou=`) or full bind DN — comma-separated RDN chain, not boolean logic.
- **Dual sink**: login flows often concat username into both filter (`(uid=…)`) and bind DN (`uid=…,dc=…`) — flag both independently.

## Escaping Rules

### Search filter (RFC 4515)

Escape only inside **assertion values** (right-hand side of `attr=value`), not attribute names or operators.

| Char | Escape |
|------|--------|
| `(` | `\28` or `\(` |
| `)` | `\29` or `\)` |
| `*` | `\2a` or `\*` |
| `\` | `\5c` or `\\` |
| NUL | `\00` |

`/`, `#`, `,`, `;` are **not** filter metacharacters — do not treat DN rules as filter rules.

### Distinguished name (RFC 4514)

Escape in **attribute values** when building RDN strings:

| Char / condition | Escape |
|------------------|--------|
| `\` | `\\` |
| `#` (leading) | `\#` |
| `+`, `<`, `>`, `,`, `;`, `"`, `=` | `\` prefix |
| Leading/trailing space | `\` prefix |
| Leading `#` | `\#` |

`* ( ) . & - _ [ ] ~ \| @ $ % ^ ? : { } ! '` — allowed unescaped in DN values per RFC 4514.

## Source -> Sink Pattern

**Sources**
- `ActiveThreatModelSource` — HTTP params, headers, cookies, request body (Java, Python, Ruby)
- JavaScript: remote HTTP inputs via `LdapJSSink` — same remote-input sources as other web taint queries

**Sinks**
- **Java**: JNDI `DirContext.search` filter and base DN; Spring LDAP `LdapTemplate.search/query`; `LdapQueryBuilder.filter()/base()`; `HardcodedFilter`; UnboundID `Filter.create*`, `SearchRequest` base/filter; Apache LDAP API `SearchRequest.setFilter/setBase`, `Dn` constructor — all via `ldap-injection` sinks and framework tracking
- **Python**: `LdapExecution.getBaseDn()`, `LdapExecution.getFilter()` — `ldap`/`ldap3` search calls
- **JavaScript**: `ldapjs` client call arg 0 (DN); `SearchOptions` filter/baseDN; `parseDN` argument
- **Ruby**: `LdapExecution.getQuery()` — Net::LDAP search filter/base
- **C#**: `DirectoryEntry` `Path` constructor/setter; `DirectorySearcher.Filter`; `System.DirectoryServices.Protocols.SearchRequest` filter/ldapFilter; `ldap-injection` sinks
- **PHP**: `ldap_search`/`ldap_list`/`ldap_read` base DN and filter args; `ldap_bind` bind DN; `ldap_escape` when absent before concat
- **Go**: `go-ldap`/`ldap` `NewSearchRequest` args (base DN, filter); `SearchRequest.BaseDN`; `go-ldap-client` `Authenticate`/`GetGroupsOfUser`; `LDAPClient.Base`

**Sanitizers / barriers**
- Java: `SimpleTypeSanitizer` (primitives/boxed types); Spring `LdapQueryBuilder.where(...).is(value)` parameterization; UnboundID `Filter.encodeValue`; Spring `LdapEncoder.filterEncode/nameEncode`; ESAPI `encodeForLDAP/encodeForDN`
- Python: `ldap.dn.escape_dn_chars`, `ldap.filter.escape_filter_chars` (py2); `ldap3.utils.dn.escape_rdn`, `ldap3.utils.conv.escape_filter_chars`; `LdapDnEscaping`, `LdapFilterEscaping` sanitizer nodes; `ConstCompareBarrier`
- JavaScript: replace-chain sanitizer for `*`, `(`, `)`, `\`, `/` in LDAP filter strings
- Ruby: `Net::LDAP::Filter.escape`; `StringConstCompareBarrier`; `StringConstArrayInclusionCallBarrier`
- C#: methods matching `LDAP.*Encode.*` (AntiXSS); `SimpleTypeSanitizedExpr`, `GuidSanitizedExpr`; model `ldap-injection` barriers
- Go: `ldap.EscapeFilter` from `go-ldap`/`gopkg.in/ldap.v2/v3`; heuristic names `sanitizedUserQuery`, `sanitizedUserDN`, etc.
- PHP: `ldap_escape($val, "", LDAP_ESCAPE_FILTER|LDAP_ESCAPE_DN)` — context flag required; no built-in sanitizer nodes in most SAST models — treat as manual barrier when present

## Vulnerable Conditions

- Filter built by string concat: `"(uid=" + username + ")"`
- DN built from user input: `"cn=" + user + ",dc=example,dc=com"`
- User value passed to `HardcodedFilter` or raw filter string APIs
- Spring `LdapQueryBuilder.query().filter("(uid=" + user + ")")` — taint tracked through builder chain
- Bind DN built from username: `ldap_bind($conn, "uid=" . $user . ",dc=example,dc=com", $pass)` — DN injection + auth bypass
- User input in filter **attribute name** slot: `( + attr + =value)` — attribute-name injection bypasses value-only escaping
- DN built with only filter escaping (or vice versa) applied to wrong context

## Safe Patterns

- Spring `LdapQueryBuilder.query().base(buildDn()).where("objectclass").is("person").and("uid").is(username)` — framework escapes filter values
- UnboundID: `Filter.createEqualityFilter("uid", username)` instead of string filter
- Python: `escape_filter_chars(username)` before embedding in filter
- ESAPI / Spring LDAP encoders before concatenation (Java safe variant uses encoders before concat)
- **Context-specific encoding**: `LdapEncoder.filterEncode(v)` / `encodeForLDAP()` for filters; `LdapEncoder.nameEncode(v)` / `encodeForDN()` for DN components — never swap
- **Parameterized filter APIs**: builder `.where(attr).is(value)` or typed `Filter.createEqualityFilter(attr, value)` — framework binds value, not raw filter string
- **Attribute allowlist**: hardcode attribute names (`uid`, `mail`); reject or map user-supplied attribute names — prevents `(userAttr=value)` injection when attr is tainted
- **Input allowlist** (defense-in-depth): restrict username/DN components to `[A-Za-z0-9._-@]` before LDAP use; does not replace escaping

Commonly affected languages: Java, Python, C#, JavaScript, Ruby, Go, PHP.

**Framework paths (Java)**: JNDI, Spring LDAP, UnboundID, Apache Directory API — including taint through `LdapName`, `Filter.toString()`, and `SearchRequest` setters.

## Bind-with-User-DN Pitfalls

- **VULN**: app searches with service account, then `ldap_bind(userDn, password)` where `userDn = "uid=" + username + ",ou=users,dc=example,dc=com"` — DN injection selects wrong/principal entry
- **VULN**: filter finds entry, bind uses different DN built separately from same tainted username — one path escaped, other not
- **SAFE**: derive bind DN only from **directory-returned** `entry.getDN()` after parameterized search — never re-concat username into DN post-search
- **SAFE**: service-account search with `(uid={0})` style + bind with returned DN; or direct bind-only with fully escaped DN from allowlisted username

## Java / Spring

- **VULN**: `ctx.search("ou=users," + userDn, "(uid=" + username + ")", controls)` — JNDI filter + base DN concat
- **VULN**: `ctx.lookup("cn=" + user + ",dc=example,dc=com")` — JNDI DN concat
- **VULN**: `new HardcodedFilter("(uid=" + username + ")")` — Spring raw filter
- **VULN**: `new LdapName("uid=" + username + ",ou=users")` — tainted DN assembly
- **SAFE**: `LdapQueryBuilder.query().base(buildBase()).where("uid").is(username)` — Spring parameterized filter
- **SAFE**: `Filter.createEqualityFilter("uid", username)` — UnboundID typed filter (no string filter)
- **SAFE**: `LdapEncoder.filterEncode(username)` in filter; `LdapEncoder.nameEncode(username)` in DN — match sink type
- **SAFE**: ESAPI `encodeForLDAP(username)` / `encodeForDN(username)` before manual concat

## Python

- **VULN**: `conn.search_s(base + user_input, ldap.SCOPE_SUBTREE, f"(uid={username})")` — DN + filter concat
- **VULN**: `conn.simple_bind_s(f"uid={username},dc=example,dc=com", password)` — bind DN concat
- **SAFE**: `from ldap3.utils.conv import escape_filter_chars; from ldap3.utils.dn import escape_rdn`
- **SAFE**: `filter_str = f"(uid={escape_filter_chars(username)})"` — filter context only
- **SAFE**: `rdn = f"uid={escape_rdn(username)}"; dn = f"{rdn},dc=example,dc=com"` — DN context
- **SAFE**: `conn.search(search_base=base, search_filter=f"(uid={escape_filter_chars(username)})", attributes=["uid"])` — ldap3 with fixed attribute list

## JavaScript (ldapjs)

- **VULN**: `client.search(userDn, { filter: '(uid=' + req.query.user + ')' })`
- **SAFE**: validate `typeof req.query.user === 'string'` and use `$eq`-style literal object or library escape before filter construction

## Ruby

- **VULN**: `ldap.search(filter: "(uid=#{params[:user]})")`
- **SAFE**: `Net::LDAP::Filter.eq('uid', params[:user])` or `Net::LDAP::Filter.escape(params[:user])`

## C#

- **VULN**: `new DirectorySearcher("LDAP://dc=example,dc=com", "(uid=" + username + ")")` — filter concat
- **VULN**: `new DirectoryEntry("LDAP://cn=" + user + ",ou=users,dc=example,dc=com")` — DN in path
- **VULN**: `searcher.Filter = "(uid=" + username + ")"` — property assignment after construction
- **SAFE**: `Encoder.LdapFilterEncode(username)` before filter concat — RFC 4515
- **SAFE**: `Encoder.LdapDistinguishedNameEncode(username)` before DN/path concat — RFC 4514
- **SAFE**: `new DirectorySearcher(baseDn) { Filter = "(&(objectClass=user)(uid=" + Encoder.LdapFilterEncode(username) + "))" }`

## PHP

- **VULN**: `ldap_search($conn, $base . $user, "(uid=" . $_POST['user'] . ")", $attrs)` — base DN + filter concat
- **VULN**: `ldap_bind($conn, "uid=" . $username . ",dc=example,dc=com", $password)` — bind DN concat
- **VULN**: `ldap_list($conn, "ou=" . $_GET['ou'] . ",dc=example,dc=com", $filter)` — OU in DN from request
- **SAFE**: `ldap_escape($username, "", LDAP_ESCAPE_FILTER)` for filter values
- **SAFE**: `ldap_escape($username, "", LDAP_ESCAPE_DN)` for RDN/DN components (PHP ≥ 5.6)
- **SAFE**: fixed filter template + escaped value: `"(&(objectClass=person)(uid=" . ldap_escape($user, "", LDAP_ESCAPE_FILTER) . "))"`

## Go

- **VULN**: `ldap.NewSearchRequest(userDn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, nil, nil)`
- **SAFE**: `ldap.EscapeFilter(userInput)` before embedding in filter string

## Detection Indicators (grep)

**Filter concat (high signal)**
```bash
rg -n '\+\s*(username|user|login|filter|query|input|param)|HardcodedFilter\s*\(|Filter\s*=\s*"\(|\.filter\s*\("\(|ldap_search\s*\([^)]+\+'
```

**DN / bind path concat**
```bash
rg -n 'LDAP://|DirectoryEntry\s*\(|simple_bind|ldap_bind\s*\(|\.lookup\s*\(|getBaseDn|BaseDN|NewSearchRequest\s*\([^,]*\+|"uid=.*\+|"cn=.*\+'
```

**Missing escape near concat**
```bash
rg -n '\(uid=|\(cn=|\(mail=' -g '!*test*' | rg '\+' | rg -v 'escape_filter|EscapeFilter|LdapFilterEncode|LdapEncoder|encodeForLDAP|ldap_escape|Filter\.eq|createEqualityFilter|\.is\('
```

**Attribute-name injection**
```bash
rg -n '\(\s*\+\s*(attr|field|column|key)|filter\s*=\s*"\(\s*\+'
```

Flag: remote input reaches sink without intervening sanitizer node from Source -> Sink section; filter and DN sinks on same code path both need matching escape/API.

## Common False Alarms

- Numeric or boolean LDAP attributes (Java `SimpleTypeSanitizer`)
- Constant-comparison guards on allowlisted values (Python/Ruby `ConstCompareBarrier`)
- Fully static filter strings with no remote input
- Spring LDAP criteria API with `.is(userValue)` — builder `.is()` is safe parameter binding when not using `HardcodedFilter`

## Business Risk

- Authentication bypass by manipulating bind/search filters
- Mass directory enumeration and credential harvesting
- Privilege escalation when LDAP backs authorization or SSO

## Core Principle

LDAP filters and DNs are parsed, not quoted like SQL literals. Never concatenate untrusted input — use framework filter builders or context-appropriate escaping (RFC 4515 for filters, RFC 4514 for DNs) for every user-controlled component. Hardcode attribute names; escape or parameterize values only.
