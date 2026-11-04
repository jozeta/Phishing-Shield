// popup.js runs as-is in a vm with a fake document and a fake chrome.tabs, once per URL; the tests
// check the verdict badge, how the host is split, and that the attacker-controlled URL only ever
// reaches the DOM as text.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("../popup.js", import.meta.url), "utf8");

// A minimal fake DOM: just enough for popup.js (createElement, createTextNode, replaceChildren).
// Rendered URL parts come back as [{ className, text }] so tests can see exactly what is shown.
function fakeElement(tag) {
  return {
    tagName: tag, className: "", textContent: "", children: [],
    replaceChildren(...nodes) { this.children = nodes; this.textContent = ""; },
  };
}

async function inspect(url) {
  const els = { urlDisplay: fakeElement("div"), securityStatus: fakeElement("div") };
  let onReady;
  const context = {
    URL,
    document: {
      addEventListener: (type, fn) => { if (type === "DOMContentLoaded") onReady = fn; },
      getElementById: (id) => els[id],
      createElement: (tag) => fakeElement(tag),
      createTextNode: (text) => ({ nodeType: 3, textContent: text }),
    },
    chrome: { tabs: { query: async () => [url === null ? {} : { url }] } },
  };
  vm.runInNewContext(source, context);
  await onReady();
  const nodes = els.urlDisplay.children;
  return {
    status: els.securityStatus.textContent,
    badge: els.securityStatus.className,
    nodes,
    parts: nodes.filter((n) => n.tagName === "span").map((n) => ({ className: n.className, text: n.textContent })),
    text: els.urlDisplay.textContent,
  };
}

// The highlighted (bold) part of the rendered URL: the registrable domain.
const mainDomain = (r) => r.parts.find((p) => p.className.split(" ").includes("url-main")).text;
const partClass = (r, text) => r.parts.find((p) => p.text === text).className;

test("a normal HTTPS site is validated", async () => {
  const r = await inspect("https://www.example.com/path?q=1");
  assert.match(r.status, /VALIDATED STANDARD HTTPS DOMAIN/);
  assert.match(r.badge, /status-safe/);
  assert.equal(mainDomain(r), "example.com");
});

test("plain HTTP is flagged", async () => {
  const r = await inspect("http://example.com/");
  assert.match(r.status, /UNENCRYPTED CONNECTION/);
  assert.match(r.badge, /status-danger/);
});

test("punycode on the registrable domain is flagged", async () => {
  const r = await inspect("https://login.xn--pple-43d.com/");
  assert.match(r.status, /PUNYCODE SPOOFING/);
  assert.equal(mainDomain(r), "xn--pple-43d.com");
});

test("a raw IP address as host is flagged", async () => {
  assert.match((await inspect("https://192.168.1.10/admin")).status, /RAW IP ADDRESS/);
  assert.match((await inspect("https://[::1]/")).status, /RAW IP ADDRESS/);
});

test("second-level TLDs like co.uk keep three labels in the main domain", async () => {
  const r = await inspect("https://secure.bank.co.uk/");
  assert.equal(mainDomain(r), "bank.co.uk");
  assert.equal(r.parts[1].text, "secure.");
});

test("userinfo before the host doesn't fool the split", async () => {
  const r = await inspect("https://paypal.com@evil.example.org/");
  assert.equal(mainDomain(r), "example.org");
});

test("an unparsable URL is shown as plain text, never as markup", async () => {
  const payload = "<img src=x onerror=alert(1)>";
  const bad = await inspect(payload);
  assert.match(bad.status, /UNPARSABLE/);
  // Only our own span exists; the payload is its text, not an element.
  assert.deepEqual(bad.parts, [{ className: "url-main url-danger", text: payload }]);
  assert.equal(bad.nodes.length, 1);
});

test("URL parts are text nodes in spans, so markup in the path stays text", async () => {
  const r = await inspect('https://example.com/<img src=x onerror=alert(1)>"');
  assert.ok(r.nodes.every((n) => n.tagName === "span" || n.nodeType === 3));
  assert.match(r.parts[3].text, /%3Cimg/); // URL percent-encodes it; either way it is only text
});

test("the whole URL stays readable: parts joined with spaces, as before", async () => {
  const r = await inspect("https://www.example.com/path?q=1");
  assert.deepEqual(r.parts.map((p) => p.text), ["https://", "www.", "example.com", "/path?q=1"]);
  assert.equal(r.nodes.length, 7); // 4 spans + 3 separating spaces
});

test("characters URL lets through, like an underscore, are flagged on the core domain", async () => {
  const r = await inspect("https://pay_pal.com/");
  assert.match(r.status, /SUSPICIOUS CORE DOMAIN CHARACTERS/);
});

test("punycode in a subdomain is flagged and the subdomain is marked", async () => {
  const r = await inspect("https://xn--pypal-4ve.example.com/");
  assert.match(r.status, /PUNYCODE LOOK-ALIKE IN SUBDOMAIN/);
  assert.match(r.badge, /status-danger/);
  assert.equal(partClass(r, "xn--pypal-4ve."), "url-danger");
  assert.equal(partClass(r, "example.com"), "url-main");
});

test("a punycode TLD on its own (e.g. .xn--p1ai) is not treated as spoofing", async () => {
  const r = await inspect("https://example.xn--p1ai/");
  assert.match(r.status, /VALIDATED/);
});

test("no tab URL: a plain message, nothing rendered as HTML", async () => {
  const r = await inspect(null);
  assert.match(r.text, /Unable to inspect/);
  assert.equal(r.nodes.length, 0);
});
