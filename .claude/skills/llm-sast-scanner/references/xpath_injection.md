---
name: xpath-injection
description: XPath injection (CWE-643), XQuery injection (CWE-652), and XML injection (CWE-091) via untrusted expression or markup construction
---

# XPath / XQuery / XML Injection (CWE-643, CWE-652, CWE-091)

These classes share a pattern: untrusted input is embedded into XPath/XQuery expressions or raw XML without parameterization or escaping, letting attackers alter query logic or document structure.

## Source -> Sink Pattern

**Sources**
- Active threat-model sources — HTTP request data (Java, Python, Go, C#, JavaScript, Ruby)
- JavaScript XPath: document URL (`location`) as additional source

**Sinks — XPath (CWE-643)**
- **Java**: `javax.xml.xpath.XPath.compile/evaluate`; dom4j `XPath`/`XPathPattern` constructors; model `xpath-injection` sinks
- **Python**: XPath construction and execution APIs — `lxml`, `xml.etree`, stdlib
- **JavaScript**: `xpath`/`xpath.js` — `parse`, `select`, `select1`, `useNamespaces()` callback arg; DOM `document.evaluate`, `document.createExpression`
- **Go**: XPath expression strings — antchfx/xpath, moovweb/gokogiri, christrenkamp/goxpath, santhosh-tekuri/xpathparser
- **C#**: `XPathExpression.Compile`, `SelectNodes`, `Evaluate` with concatenated expression string
- **Ruby**: nokogiri/rexml/libxml xpath evaluation

**Sinks — XQuery (CWE-652)**
- **Java**: dynamically constructed XQuery string passed to Saxon/XQJ execution — use `bindString` for parameters

**Sinks — XML Injection (CWE-091)**
- **C#**: `System.Xml.XmlWriter.WriteRaw` with user-controlled string — allows tag breakout and extra element insertion

**Sanitizers / barriers**
- Java: `XPath.setXPathVariableResolver` / precompiled query with variable references; model `xpath-injection` barriers
- C# XPath: custom `XsltContext` with `ResolveVariable` + `XsltArgumentList`; `XmlWriter` high-level element APIs auto-escape
- C# XML: escape before `WriteRaw`; prefer `WriteElementString`/`WriteAttributeString`
- Go: XPath sanitizer nodes
- Python: constant-comparison barriers; no built-in XPath escape sanitizer — parameterization preferred

Commonly affected languages: Java, Python, JavaScript, Go, C#, Ruby.

## Vulnerable Conditions

- XPath string concat: `"//user[name='" + input + "' and pass='" + pass + "']"`
- User input in dom4j `DocumentHelper.createXPath(...)`
- JavaScript: `` xpath.select(`//item[@name='${req.query.name}']`, doc) ``
- C#: `doc.SelectNodes("//user[name='" + username + "']")`
- C# XML: `writer.WriteRaw("<employee><name>" + userName + "</name></employee>")`

## Safe Patterns

- **Java XPath**: compile once, bind via `setXPathVariableResolver`
- **XQuery**: `bindString("var", userValue)` instead of concat
- **C# XPath**: hardcoded expression with variables resolved through custom `XsltContext`
- **C# XML**: `WriteElementString("name", userName)` — auto-escaped; or `SecurityElement.Escape` before `WriteRaw`
- **JavaScript**: never build XPath from template literals with user fragments

## Java

- **VULN**: `xpath.evaluate("//users/user[name/text()='" + name + "' and password/text()='" + pass + "']", doc)`
- **SAFE**: precompiled XPath with `setXPathVariableResolver` supplying `name` and `pass` as variables

## Python

- **VULN**: `tree.xpath(f"//user[@name='{username}']")` — lxml string xpath
- **SAFE**: parameterized xpath with variable map where supported, or strict allowlist validation before concat

## JavaScript

- **VULN**: `xpath.select('//book[@name="' + req.query.name + '"]', doc)`
- **VULN**: `document.evaluate(location.hash.slice(1), doc, ...)`
- **SAFE**: static XPath expression; user value passed through validated lookup table, not embedded in expression text

## Go

- **VULN**: `xpath.Compile("//item[@name='" + r.URL.Query().Get("name") + "']")`
- **SAFE**: fixed expression with post-filter on results, or library-specific variable binding

## C#

- **VULN (XPath)**: `nav.Select("//users/user[name = '" + username + "']")`
- **SAFE (XPath)**: compiled expression + `XsltArgumentList` variables via custom context
- **VULN (XML)**: `writer.WriteRaw("<name>" + userInput + "</name>")`
- **SAFE (XML)**: `writer.WriteElementString("name", userInput)`

## Ruby

- **VULN**: `doc.xpath("//user[@name='#{params[:name]}']")` — nokogiri
- **SAFE**: sanitize/validate input before xpath; use XPath variable binding where available

## Common False Alarms

- Fully static XPath/XQuery strings with no data flow from remote sources
- C# `WriteElementString` / `WriteAttributeString` — auto-escaped, not flagged
- Go/Java numeric simple-type sanitizers when input is provably non-string
- JavaScript DOM xpath where expression is string literal constant

## Business Risk

- Authentication bypass against XML-backed credential stores
- Unauthorized data extraction from XML databases
- XML document corruption, privilege injection via extra elements (`WriteRaw`)
- XQuery injection enabling arbitrary XML data retrieval

## Core Principle

XPath and XQuery are expression languages — concatenation gives attackers grammar control. Use variable binding, precompiled queries, or structured XML APIs; never embed raw user text into expression or markup syntax.
