---
name: ldap-injection
description: LDAP injection (CWE-090) where untrusted input alters directory search filters or distinguished names
---

# LDAP Injection (CWE-090)

LDAP injection occurs when user input is concatenated into an LDAP distinguished name (DN) or search filter without escaping. Attackers inject metacharacters (`*`, `(`, `)`, `\`, `/`, NUL) to broaden searches, bypass authentication, or exfiltrate directory entries.

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
- **Go**: `go-ldap`/`ldap` `NewSearchRequest` args (base DN, filter); `SearchRequest.BaseDN`; `go-ldap-client` `Authenticate`/`GetGroupsOfUser`; `LDAPClient.Base`

**Sanitizers / barriers**
- Java: `SimpleTypeSanitizer` (primitives/boxed types); Spring `LdapQueryBuilder.where(...).is(value)` parameterization; UnboundID `Filter.encodeValue`; Spring `LdapEncoder.filterEncode/nameEncode`; ESAPI `encodeForLDAP/encodeForDN`
- Python: `ldap.dn.escape_dn_chars`, `ldap.filter.escape_filter_chars` (py2); `ldap3.utils.dn.escape_rdn`, `ldap3.utils.conv.escape_filter_chars`; `LdapDnEscaping`, `LdapFilterEscaping` sanitizer nodes; `ConstCompareBarrier`
- JavaScript: replace-chain sanitizer for `*`, `(`, `)`, `\`, `/` in LDAP filter strings
- Ruby: `Net::LDAP::Filter.escape`; `StringConstCompareBarrier`; `StringConstArrayInclusionCallBarrier`
- C#: methods matching `LDAP.*Encode.*` (AntiXSS); `SimpleTypeSanitizedExpr`, `GuidSanitizedExpr`; model `ldap-injection` barriers
- Go: `ldap.EscapeFilter` from `go-ldap`/`gopkg.in/ldap.v2/v3`; heuristic names `sanitizedUserQuery`, `sanitizedUserDN`, etc.

## Vulnerable Conditions

- Filter built by string concat: `"(uid=" + username + ")"`
- DN built from user input: `"cn=" + user + ",dc=example,dc=com"`
- User value passed to `HardcodedFilter` or raw filter string APIs
- Spring `LdapQueryBuilder.query().filter("(uid=" + user + ")")` — taint tracked through builder chain

## Safe Patterns

- Spring `LdapQueryBuilder.query().base(buildDn()).where("objectclass").is("person").and("uid").is(username)` — framework escapes filter values
- UnboundID: `Filter.createEqualityFilter("uid", username)` instead of string filter
- Python: `escape_filter_chars(username)` before embedding in filter
- ESAPI / Spring LDAP encoders before concatenation (Java safe variant uses encoders before concat)

Commonly affected languages: Java, Python, C#, JavaScript, Ruby, Go.

**Framework paths (Java)**: JNDI, Spring LDAP, UnboundID, Apache Directory API — including taint through `LdapName`, `Filter.toString()`, and `SearchRequest` setters.

## Java / Spring

- **VULN**: `ctx.search("ou=users," + userDn, "(uid=" + username + ")", controls)` — JNDI concat
- **VULN**: `new HardcodedFilter("(uid=" + username + ")")` — Spring raw filter
- **SAFE**: `LdapQueryBuilder.query().base(buildBase()).where("uid").is(username)` — parameterized filter
- **SAFE**: `Filter.createEqualityFilter("uid", username)` — UnboundID typed filter

## Python

- **VULN**: `conn.search_s(base + user_input, ldap.SCOPE_SUBTREE, f"(uid={username})")`
- **SAFE**: `filter_str = f"(uid={escape_filter_chars(username)})"` with `ldap3.utils.conv.escape_filter_chars`

## JavaScript (ldapjs)

- **VULN**: `client.search(userDn, { filter: '(uid=' + req.query.user + ')' })`
- **SAFE**: validate `typeof req.query.user === 'string'` and use `$eq`-style literal object or library escape before filter construction

## Ruby

- **VULN**: `ldap.search(filter: "(uid=#{params[:user]})")`
- **SAFE**: `Net::LDAP::Filter.eq('uid', params[:user])` or `Net::LDAP::Filter.escape(params[:user])`

## C#

- **VULN**: `new DirectorySearcher("LDAP://dc=example,dc=com", "(uid=" + username + ")")`
- **VULN**: `new DirectoryEntry("LDAP://cn=" + user + ",ou=users,dc=example,dc=com")`
- **SAFE**: AntiXSS `Encoder.LdapFilterEncode(username)` before filter concat

## Go

- **VULN**: `ldap.NewSearchRequest(userDn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, nil, nil)`
- **SAFE**: `ldap.EscapeFilter(userInput)` before embedding in filter string

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

LDAP filters and DNs are parsed, not quoted like SQL literals. Never concatenate untrusted input — use framework filter builders or RFC 4515 escaping for every user-controlled component.
