# 🛡️ Phishing Shield

A lightweight browser extension popup that inspects the URL of the active tab and highlights signs of phishing or domain-spoofing — unencrypted connections, raw IP addresses, punycode homograph attacks, and suspicious characters in the core domain.

## Screenshots

| Valid HTTPS domain | Unencrypted connection | Punycode look-alike |
|---|---|---|
| ![Popup showing a validated HTTPS domain](docs/screenshots/popup-safe.png) | ![Popup warning about a non-HTTPS connection](docs/screenshots/popup-http.png) | ![Popup flagging punycode spoofing on the core domain](docs/screenshots/popup-punycode.png) |

## Description

Phishing Shield is a minimal browser-extension "inspector" that helps users quickly sanity-check the address bar of the page they're currently viewing. Instead of trusting the URL at a glance, it parses the hostname, isolates the **registrable (main) domain** from subdomains, and visually distinguishes the two — making it much harder for a spoofed subdomain (e.g. `paypal.com.security-check.example`) to blend in with the real domain.

## How It Works

When the popup is opened, `popup.js`:

1. **Gets the active tab's URL** via the `chrome.tabs.query` API.
2. **Parses the URL** using the built-in `URL` object to extract the hostname, protocol, path, and query string.
3. **Splits the hostname into subdomain + main domain** (`extractMainDomain`):
   - Handles plain domains (`example.com`) and second-level TLDs (`example.co.uk`, `example.gov.uk`, etc.) using a small list of common SLDs (`co`, `com`, `net`, `org`, `gov`, `edu`, `ac`, `biz`, `info`).
   - Leaves IP addresses (IPv4, and bracketed IPv6 such as `[::1]`) untouched (no subdomain splitting).
4. **Runs security checks** against the parsed URL:
   | Check | What it catches |
   |---|---|
   | **HTTPS enforcement** | Flags any page not served over `https://` as an unencrypted connection. |
   | **Raw IP host** | Flags pages whose host is an IP address instead of a domain name. |
   | **Domain character validation** | Ensures the main domain only contains ASCII letters, digits, dots, and hyphens. The browser's URL parser already turns non-ASCII letters into punycode (`päypal.com` → `xn--pypal-gra.com`), so this catches what the parser lets through, such as underscores (`pay_pal.com`). |
   | **Punycode detection** | Flags a main domain starting with `xn--`, a common sign of an IDN homograph attack (e.g. a Cyrillic look-alike character used to impersonate a trusted domain). Punycode in a **subdomain** label (`xn--pypal-4ve.example.com`) gets its own, separate warning. A punycode top-level domain on its own (e.g. `.xn--p1ai`, Russia's `.рф`) is not flagged. |
5. **Renders a color-coded breakdown of the URL**, dimming the protocol/subdomain/path while bolding and color-coding the main domain (green-safe / red-danger), plus a **status badge** summarizing the verdict:
   - ✅ `VALIDATED STANDARD HTTPS DOMAIN`
   - ⚠️ `UNENCRYPTED CONNECTION (NON-HTTPS)`
   - 🚨 `RAW IP ADDRESS USED AS HOST (NO DOMAIN NAME)`
   - 🚨 `PUNYCODE SPOOFING DETECTED ON CORE DOMAIN`
   - 🚨 `SUSPICIOUS CORE DOMAIN CHARACTERS`
   - ⚠️ `PUNYCODE LOOK-ALIKE IN SUBDOMAIN`
   - `UNKNOWN PROTOCOL / UNPARSABLE CONTEXT` (the URL couldn't be parsed)

The checks run in that order and the first match decides the badge. The URL is built into the popup with `createElement` and `textContent` only, never `innerHTML`, so a malicious page URL cannot inject markup into the popup itself.

## Project Structure

```
Phishing-Shield/
├── manifest.json      # Manifest V3: popup action, activeTab permission
├── icons/
│   └── icon16.png     # Extension toolbar icon
├── popup.html          # Popup markup
├── popup.css           # Popup styling
├── popup.js            # URL parsing & phishing heuristics
├── tests/
│   └── popup.test.mjs  # Runs popup.js against fake tabs (node --test)
├── docs/screenshots/   # README images
├── eslint.config.mjs   # ESLint (dev-only), incl. the no-unsanitized rule
├── package.json        # Dev tooling only: npm test, npm run lint
└── .github/workflows/  # CI: lint + tests
```

## Development

```sh
npm ci          # dev-only tools (ESLint); the extension itself has no dependencies
npm run lint
npm test
```

## Installation

1. Open `chrome://extensions` (or the equivalent page in your Chromium-based browser).
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the project folder.
4. Pin the extension and click its icon on any page to inspect the current URL.

## Limitations & Disclaimer

This tool applies simple, client-side heuristics and is intended as a **quick visual aid**, not a definitive security verdict. It does **not**:

- Check domains against blocklists/reputation services.
- Detect all forms of phishing (e.g. malicious content hosted on a legitimate-looking, otherwise valid domain).
- Replace browser-native phishing/malware protection.

Always exercise caution with unfamiliar links, regardless of what this extension reports.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
