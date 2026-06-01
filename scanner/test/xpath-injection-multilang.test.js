// XPath injection (CWE-643) — Java/Python/JS (existing) + PHP/Go/Ruby/C#/Kotlin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanXPathInjection as s } from '../src/sast/xpath-injection.js';

const fires = (fp, code) => s(fp, code).some((f) => f.cwe === 'CWE-643');
const clean = (fp, code) => s(fp, code).every((f) => f.cwe !== 'CWE-643');

test('PHP — DOMXPath->query concat fires; literal clean', () => {
  assert.ok(fires('x.php', `<?php $u=$_GET["u"]; $xp = new DOMXPath($doc); $xp->query("//user[@name='" . $u . "']");`));
  assert.ok(clean('x.php', `<?php $xp = new DOMXPath($doc); $xp->query("//user[@name='admin']");`));
});

test('C# — SelectNodes concat / interpolation fires; literal clean', () => {
  assert.ok(fires('X.cs', `using System.Xml;\nclass X { void q(string u, XmlDocument d){ d.SelectNodes("//user[@name='" + u + "']"); } }`));
  assert.ok(fires('X.cs', `using System.Xml;\nclass X { void q(string u, XmlDocument d){ d.SelectSingleNode($"//user[@name='{u}']"); } }`));
  assert.ok(clean('X.cs', `using System.Xml;\nclass X { void q(XmlDocument d){ d.SelectNodes("//user[@name='admin']"); } }`));
});

test('Ruby — Nokogiri xpath interpolation fires; literal clean', () => {
  assert.ok(fires('x.rb', `require "nokogiri"\ndef q(doc, u)\n  doc.xpath("//user[@name='#{u}']")\nend\n`));
  assert.ok(clean('x.rb', `require "nokogiri"\ndef q(doc)\n  doc.xpath("//user[@name='admin']")\nend\n`));
});

test('Go — htmlquery/xmlpath concat fires; literal clean', () => {
  assert.ok(fires('x.go', `package main\nimport "github.com/antchfx/htmlquery"\nfunc q(doc *html.Node, u string){ htmlquery.Find(doc, "//user[@name='" + u + "']") }`));
  assert.ok(fires('x.go', `package main\nimport "gopkg.in/xmlpath.v2"\nfunc q(u string){ xmlpath.Compile("//user[@name='" + u + "']") }`));
  assert.ok(clean('x.go', `package main\nimport "github.com/antchfx/htmlquery"\nfunc q(doc *html.Node){ htmlquery.Find(doc, "//user[@name='admin']") }`));
});

test('Kotlin — XPath.compile/evaluate concat / interpolation fires', () => {
  assert.ok(fires('X.kt', `import javax.xml.xpath.*\nclass X { fun q(u: String, xp: XPath, doc: Any) { xp.evaluate("//user[@name='" + u + "']", doc) } }`));
  assert.ok(fires('X.kt', `import javax.xml.xpath.*\nclass X { fun q(u: String, xp: XPath) { xp.compile("//user[@name='\${u}']") } }`));
});

test('Java/Python/JS regression — concat still fires', () => {
  assert.ok(fires('X.java', `class X { void q(String u, javax.xml.xpath.XPath xp) throws Exception { xp.compile("//user[name='" + u + "']"); } }`));
  assert.ok(fires('x.py', `def q(tree, u):\n    return tree.xpath("//user[@name='" + u + "']")\n`));
});

test('non-XPath files produce nothing', () => {
  assert.deepEqual(s('x.go', 'package main\nfunc add(a,b int) int { return a+b }'), []);
});
