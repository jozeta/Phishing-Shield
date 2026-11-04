// popup.js runs as-is in a vm with a fake document and a fake chrome.tabs, once per URL; the tests
// check the verdict badge, how the host is split, and that the attacker-controlled URL is escaped.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("../popup.js", import.meta.url), "utf8");

async function inspect(url) {
  const els = { urlDisplay: { innerHTML: "", textContent: "" }, securityStatus: { className: "", textContent: "" } };
  let onReady;
  const context = {
    URL,
    document: {
      addEventListener: (type, fn) => { if (type === "DOMContentLoaded") onReady = fn; },
      getElementById: (id) => els[id],
    },
    chrome: { tabs: { query: async () => [url === null ? {} : { url }] } },
  };
  vm.runInNewContext(source, context);
  await onReady();
  return { status: els.securityStatus.textContent, badge: els.securityStatus.className, html: els.urlDisplay.innerHTML, text: els.urlDisplay.textContent };
}

// The highlighted (bold) part of the rendered URL: the registrable domain.
const mainDomain = (html) => html.match(/font-weight: bold;">([^<]*)</)[1];

test("a normal HTTPS site is validated", async () => {
  const r = await inspect("https://www.example.com/path?q=1");
  assert.match(r.status, /VALIDATED STANDARD HTTPS DOMAIN/);
  assert.match(r.badge, /status-safe/);
  assert.equal(mainDomain(r.html), "example.com");
});

test("plain HTTP is flagged", async () => {
  const r = await inspect("http://example.com/");
  assert.match(r.status, /UNENCRYPTED CONNECTION/);
  assert.match(r.badge, /status-danger/);
});

test("punycode on the registrable domain is flagged", async () => {
  const r = await inspect("https://login.xn--pple-43d.com/");
  assert.match(r.status, /PUNYCODE SPOOFING/);
  assert.equal(mainDomain(r.html), "xn--pple-43d.com");
});

test("a raw IP address as host is flagged", async () => {
  assert.match((await inspect("https://192.168.1.10/admin")).status, /RAW IP ADDRESS/);
  assert.match((await inspect("https://[::1]/")).status, /RAW IP ADDRESS/);
});

test("second-level TLDs like co.uk keep three labels in the main domain", async () => {
  const r = await inspect("https://secure.bank.co.uk/");
  assert.equal(mainDomain(r.html), "bank.co.uk");
  assert.match(r.html, />secure\.</);
});

test("userinfo before the host doesn't fool the split", async () => {
  const r = await inspect("https://paypal.com@evil.example.org/");
  assert.equal(mainDomain(r.html), "example.org");
});

test("an unparsable URL is shown escaped, never as markup", async () => {
  const r = await inspect('javascript-ish:<img src=x onerror=alert(1)>"');
  // A custom scheme parses, so try one that doesn't:
  const bad = await inspect("<img src=x onerror=alert(1)>");
  assert.match(bad.status, /UNPARSABLE/);
  assert.doesNotMatch(bad.html, /<img/);
  assert.match(bad.html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(r.html, /<img/);
});

test("no tab URL: a plain message, nothing rendered as HTML", async () => {
  const r = await inspect(null);
  assert.match(r.text, /Unable to inspect/);
  assert.equal(r.html, "");
});
