# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Phishing Shield is a tiny Manifest V3 browser-extension popup that inspects the active tab's URL
and highlights phishing/spoofing signs: non-HTTPS, raw IP hosts, punycode (`xn--`) homographs (in the
registrable domain or a subdomain) and characters the URL parser lets through, such as `_`, in the
registrable domain. Plain HTML/CSS/JS, no build, no runtime dependencies (ESLint is dev-only).

## Running

`chrome://extensions` → Developer mode → **Load unpacked** → this folder, then pin it and click
the icon on any page. After edits, press **Reload** on the extension card. `npm test` runs
`popup.js` against fake tabs and a minimal fake DOM (verdicts, host splitting, text-only rendering); still check a normal HTTPS site,
an `http://` site, a punycode domain (e.g. `xn--` test domains) and a `co.uk`-style domain by hand.

## Code

- `manifest.json`: MV3, popup action only, permission `activeTab`.
- `popup.js`: gets the URL via `chrome.tabs.query`, parses it with `URL`, splits subdomain from
  main domain in `extractMainDomain` (small list of second-level TLDs like `co.uk`; IPv4 and
  bracketed IPv6 left as-is), runs the checks (HTTPS, raw IP, core-domain characters and punycode,
  punycode in a subdomain; first match wins) and renders a colour-coded breakdown and a status badge
  with `renderUrlParts`.
- `popup.html`, `popup.css`: markup and styles; `icons/icon16.png`.

## Rules

- **Never put URL-derived text in as HTML.** Build nodes with `createElement` and set
  `textContent` (see `renderUrlParts`); no `innerHTML`. The URL is attacker-controlled. Colours
  are CSS classes in `popup.css` (`url-dim`, `url-danger`, `url-main`).
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

Unsafe DOM sinks (no-unsanitized) are lint **errors** and fail CI. Unused variables are still
warnings. Other errors (eval, undefined names, parse errors) fail CI too.
