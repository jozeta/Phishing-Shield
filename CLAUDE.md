# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Phishing Shield is a tiny Manifest V3 browser-extension popup that inspects the active tab's URL
and highlights phishing/spoofing signs: non-HTTPS, punycode (`xn--`) homographs and non-ASCII
characters in the registrable domain. Plain HTML/CSS/JS, no build, no dependencies.

## Running

`chrome://extensions` → Developer mode → **Load unpacked** → this folder, then pin it and click
the icon on any page. After edits, press **Reload** on the extension card. There are no automated
tests: check a normal HTTPS site, an `http://` site, a punycode domain (e.g. `xn--` test domains)
and a `co.uk`-style domain.

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
- The README "Installation" note says `manifest.json` is missing; it now exists, so update that
  note when you next touch the README.
