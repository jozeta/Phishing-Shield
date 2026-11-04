// popup.js runs as-is in a vm with a fake document and a fake chrome.tabs, once per URL; the tests
// check the verdict badge, how the host is split, and that the attacker-controlled URL only ever
// reaches the DOM as text.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

// The scripts popup.html loads, in the same order. Add new lib files here too.
const SCRIPTS = ["lib/psl-data.js", "lib/brands.js", "lib/analyze.js", "popup.js"];
const sources = SCRIPTS.map((f) => [f, readFileSync(new URL(`../${f}`, import.meta.url), "utf8")]);

// A minimal fake DOM: just enough for popup.js (getElementById, createElement, replaceChildren).
// Rendered URL parts come back as [{ className, text }] so tests can see exactly what is shown.
function fakeElement(tag) {
  return {
    tagName: tag, className: "", textContent: "", children: [], checked: false, listeners: {},
    replaceChildren(...nodes) { this.children = nodes; this.textContent = ""; },
    addEventListener(type, fn) { this.listeners[type] = fn; },
  };
}

// Runs the popup's scripts against one tab URL, like opening the popup on that page.
async function inspect(url, chromeExtras = {}) {
  const els = {};
  let onReady;
  const context = {
    URL,
    console,
    document: {
      addEventListener: (type, fn) => { if (type === "DOMContentLoaded") onReady = fn; },
      getElementById: (id) => (els[id] ??= fakeElement("div")),
      createElement: (tag) => fakeElement(tag),
    },
    chrome: { tabs: { query: async () => [url === null ? {} : { url }] }, ...chromeExtras },
  };
  context.globalThis = context;
  vm.createContext(context);
  for (const [file, code] of sources) vm.runInContext(code, context, { filename: file });
  await onReady();
  const nodes = els.urlDisplay.children;
  return {
    status: els.securityStatus.textContent,
    badge: els.securityStatus.className,
    nodes,
    parts: nodes.filter((n) => n.tagName === "span").map((n) => ({ className: n.className, text: n.textContent })),
    more: (els.moreFindings?.children ?? []).map((n) => n.textContent),
    text: els.urlDisplay.textContent,
    els,
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
  assert.ok(r.nodes.every((n) => n.tagName === "span"));
  assert.match(r.parts.at(-1).text, /%3Cimg/); // URL percent-encodes it; either way it is only text
});

test("the parts join back into the exact URL, with no spaces added", async () => {
  const r = await inspect("https://www.example.com/path?q=1");
  assert.deepEqual(r.parts.map((p) => p.text), ["https://", "www.", "example.com", "/path?q=1"]);
  assert.equal(r.parts.map((p) => p.text).join(""), "https://www.example.com/path?q=1");
  assert.equal(r.nodes.length, 4);
});

test("empty parts (no subdomain) render no span", async () => {
  const r = await inspect("https://example.com/");
  assert.deepEqual(r.parts.map((p) => p.text), ["https://", "example.com", "/"]);
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

const shown = (r) => r.parts.map((p) => p.text).join("");

test("a trailing dot (FQDN) doesn't hide the real domain", async () => {
  const r = await inspect("https://paypal.com.evil.com./login");
  assert.equal(mainDomain(r), "evil.com.");
  assert.equal(shown(r), "https://paypal.com.evil.com./login");
});

test("on shared hosting, the user's own label belongs to the highlighted domain", async () => {
  assert.equal(mainDomain(await inspect("https://paypal-login.github.io/")), "paypal-login.github.io");
  assert.equal(mainDomain(await inspect("https://a.b.netlify.app/")), "b.netlify.app");
  assert.equal(mainDomain(await inspect("https://github.io/")), "github.io");
});

test("browser and local pages are not called unencrypted websites", async () => {
  for (const url of ["chrome://extensions/", "file:///Users/me/doc.pdf", "about:blank", "chrome-extension://abc/page.html"]) {
    const r = await inspect(url);
    assert.match(r.status, /NOT A WEBSITE/, url);
    assert.match(r.badge, /status-neutral/, url);
    assert.equal(shown(r), url, url); // shown exactly, e.g. about:blank not about://blank
  }
});

test("several findings: the most serious is the headline, the rest are listed below", async () => {
  const r = await inspect("http://login.xn--pple-43d.com/");
  assert.match(r.status, /PUNYCODE SPOOFING/);
  assert.deepEqual(r.more, ["⚠️ UNENCRYPTED CONNECTION (NON-HTTPS)"]);
  assert.deepEqual((await inspect("https://example.com/")).more, []);
});

test("a login part before @ is flagged: it disguises the real site", async () => {
  const r = await inspect("https://paypal.com@evil.example.org/");
  assert.match(r.status, /TEXT BEFORE "@" DISGUISES THE REAL SITE/);
  assert.match(r.badge, /status-danger/);
  assert.equal(partClass(r, "paypal.com@"), "url-danger");
  assert.match((await inspect("https://user:secret@example.com/")).status, /DISGUISES/);
});

test("an unusual port is a warning; the default ports are not", async () => {
  const r = await inspect("https://example.com:8443/login");
  assert.match(r.status, /UNUSUAL PORT :8443/);
  assert.match(r.badge, /status-warn/);
  assert.equal(partClass(r, ":8443"), "url-warn");
  // URL drops :443 on https and :80 on http, so these show no port at all.
  assert.match((await inspect("https://example.com:443/")).status, /VALIDATED/);
  assert.doesNotMatch((await inspect("http://example.com:80/")).status, /PORT/);
});

test("the Public Suffix List decides where the registrable domain starts", async () => {
  const cases = {
    "https://shop.example.pp.se/": "example.pp.se",          // Swedish second-level suffix
    "https://a.b.example.com.au/": "example.com.au",
    "https://evil.example.ck/": "evil.example.ck",            // wildcard rule *.ck
    "https://foo.www.ck/": "www.ck",                          // exception rule !www.ck
    "https://bucket.s3.amazonaws.com/": "bucket.s3.amazonaws.com", // private-domain section
    "https://x.paypal-login.pages.dev/": "paypal-login.pages.dev",
    "https://localhost/": "localhost",
    "https://www.example.xn--p1ai/": "example.xn--p1ai",      // .рф
  };
  for (const [url, expected] of Object.entries(cases)) {
    assert.equal(mainDomain(await inspect(url)), expected, url);
  }
});

test("look-alikes of brand domains are flagged", async () => {
  const cases = {
    "https://paypa1.com/": "PAYPAL.COM",            // 1 for l
    "https://www.paypai.com/signin": "PAYPAL.COM",  // i for l
    "https://micros0ft-support.com/": "MICROSOFT.COM",
    "https://netfllx.com/": "NETFLIX.COM",
    "https://bankld.se/": "BANKID.COM",
    "https://handelsbankem.se/": "HANDELSBANKEN.SE", // one letter off, long name
    "https://arnazon.com/": "AMAZON.COM",           // rn for m
  };
  for (const [url, brand] of Object.entries(cases)) {
    const r = await inspect(url);
    assert.equal(r.status, `🚨 LOOK-ALIKE OF ${brand}`, url);
    assert.ok(r.parts.some((p) => p.className === "url-main url-danger"), url);
  }
});

test("a brand name in a domain the brand doesn't own is flagged", async () => {
  let r = await inspect("https://paypal.com.secure-login.net/");
  assert.match(r.status, /"PAYPAL" ON A SITE THAT ISN'T PAYPAL\.COM/);
  assert.equal(partClass(r, "paypal.com."), "url-danger");
  r = await inspect("https://swedbank-login.se/");
  assert.match(r.status, /"SWEDBANK" ON A SITE THAT ISN'T SWEDBANK\.SE/);
  assert.match((await inspect("https://secure-paypal.netlify.app/")).status, /"PAYPAL"/);
});

test("a brand name alone on an unexpected ending is a warning", async () => {
  for (const url of ["https://paypal.support/", "https://swedbank.co/"]) {
    const r = await inspect(url);
    assert.match(r.status, /NAME ON AN ENDING .* DOESN'T USE/, url);
    assert.match(r.badge, /status-warn/, url);
  }
});

test("the brands' own domains and ordinary words are not flagged", async () => {
  for (const url of [
    "https://www.paypal.com/", "https://login.microsoftonline.com/", "https://www.google.se/",
    "https://www.amazon.co.uk/", "https://contoso.sharepoint.com/", "https://www.swedbank.se/",
    "https://app.bankid.com/", "https://www.getswish.se/", "https://klara.se/", "https://apply.com/",
    "https://www.swiss.com/", "https://hotel-booking.com/", "https://goggle.com/", "https://nordic.se/",
    "https://stackoverflow.com/", "https://www.dn.se/", "https://user.github.io/",
  ]) {
    assert.match((await inspect(url)).status, /VALIDATED/, url);
  }
});

test("ordinary words and near-miss names are not mistaken for brands", async () => {
  for (const url of [
    "https://trader.com/", "https://blocked.com/", "https://mint-finance.se/", "https://revolt.com/",
    "https://airexpress.com/", "https://scandia.com/", "https://nordnetwork.se/", "https://postnorden.se/",
    "https://weather-outlook.com/", "https://apple-pie-recipes.com/", "https://chase-the-sun.com/",
    "https://swish-basketball.com/", "https://telegraph.co.uk/", "https://appleinsider.com/",
  ]) {
    assert.match((await inspect(url)).status, /VALIDATED/, url);
  }
});

test("brand names padded with phishing words are caught", async () => {
  for (const [url, word] of [
    ["https://paypalsecure.com/", "PAYPAL"], ["https://myswedbanklogin.com/", "SWEDBANK"],
    ["https://apple-id-verify.com/", "APPLE"], ["https://ups-tracking.net/", "UPS"],
    ["https://outlook-login.info/", "OUTLOOK"],
  ]) {
    assert.match((await inspect(url)).status, new RegExp(`"${word}" ON A SITE`), url);
  }
  assert.match((await inspect("https://netfilx.com/")).status, /LOOK-ALIKE OF NETFLIX\.COM/);
  assert.match((await inspect("https://amzaon.com/")).status, /LOOK-ALIKE OF AMAZON\.COM/);
  // Known gap, on purpose: one changed letter in a name under 8 letters (spotity, blocked) isn't
  // flagged, because ordinary words come that close too (blocked/blocket, trader/tradera).
  assert.match((await inspect("https://spotity.com/")).status, /VALIDATED/);
});
