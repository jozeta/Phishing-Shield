# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Phishing Shield is a tiny Manifest V3 browser-extension popup that inspects the active tab's URL
and highlights phishing/spoofing signs: non-HTTPS, punycode (`xn--`) homographs and non-ASCII
characters in the registrable domain. Plain HTML/CSS/JS, no build, no runtime dependencies (ESLint is dev-only).

## Running

`chrome://extensions` → Developer mode → **Load unpacked** → this folder, then pin it and click
the icon on any page. After edits, press **Reload** on the extension card. `npm test` runs
`popup.js` against fake tabs (verdicts, host splitting, escaping); still check a normal HTTPS site,
an `http://` site, a punycode domain (e.g. `xn--` test domains) and a `co.uk`-style domain by hand.

## Code

- `manifest.json`: MV3, popup action only, permission `activeTab`.
- `popup.js`: gets the URL via `chrome.tabs.query`, parses it with `URL`, splits subdomain from
  main domain in `extractMainDomain` (small list of second-level TLDs like `co.uk`; IPv4 left
  as-is), runs the checks and renders a colour-coded breakdown and a status badge.
- `popup.html`, `popup.css`: markup and styles; `icons/icon16.png`.

## Rules

- **Escape everything** derived from the URL with `escapeHtml` before inserting it into the
  DOM. The URL is attacker-controlled.
- Keep permissions minimal (`activeTab` only); no network requests, no remote code.
- These are heuristics, not verdicts; keep the README's limitations honest.
- README screenshots in `docs/screenshots/` were rendered from the real popup with a stubbed
  `chrome.tabs.query`; regenerate them if the popup's look changes.

## App standards

This repo follows the app standards in `~/Desktop/code/tools/standards/STANDARDS.md` (rule IDs,
severities; decisions and waivers in `.claude-standards`). `claude-check --repo .` checks it.

```sh
npm ci && npm run lint   # ESLint (dev-only), incl. the no-unsanitized rule; CI runs it too
npm test                 # the tests CI runs
```

Unsafe DOM sinks and unused variables are lint **warnings** for now (existing code); new code
shouldn't add any. Errors (eval, undefined names, parse errors) fail CI.
