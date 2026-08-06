# 🛡️ Phishing Shield

A lightweight browser extension popup that inspects the URL of the active tab and highlights signs of phishing or domain-spoofing — unencrypted connections, punycode homograph attacks, and suspicious characters in the core domain.

## Description

Phishing Shield is a minimal browser-extension "inspector" that helps users quickly sanity-check the address bar of the page they're currently viewing. Instead of trusting the URL at a glance, it parses the hostname, isolates the **registrable (main) domain** from subdomains, and visually distinguishes the two — making it much harder for a spoofed subdomain (e.g. `paypal.com.security-check.example`) to blend in with the real domain.

## How It Works

When the popup is opened, `popup.js`:

1. **Gets the active tab's URL** via the `chrome.tabs.query` API.
2. **Parses the URL** using the built-in `URL` object to extract the hostname, protocol, path, and query string.
3. **Splits the hostname into subdomain + main domain** (`extractMainDomain`):
   - Handles plain domains (`example.com`) and second-level TLDs (`example.co.uk`, `example.gov.uk`, etc.) using a small list of common SLDs (`co`, `com`, `net`, `org`, `gov`, `edu`, `ac`, `biz`, `info`).
   - Leaves IPv4 addresses untouched (no subdomain splitting).
4. **Runs security checks** against the parsed URL:
   | Check | What it catches |
   |---|---|
   | **HTTPS enforcement** | Flags any page not served over `https://` as an unencrypted connection. |
   | **Domain character validation** | Ensures the main domain only contains standard ASCII letters, digits, dots, and hyphens. |
   | **Punycode detection** | Flags domains starting with `xn--`, a common sign of an IDN homograph attack (e.g. a Cyrillic look-alike character used to impersonate a trusted domain). |
5. **Renders a color-coded breakdown of the URL**, dimming the protocol/subdomain/path while bolding and color-coding the main domain (green-safe / red-danger), plus a **status badge** summarizing the verdict:
   - ✅ `VALIDATED STANDARD HTTPS DOMAIN`
   - ⚠️ `UNENCRYPTED CONNECTION (NON-HTTPS)`
   - 🚨 `PUNYCODE SPOOFING DETECTED ON CORE DOMAIN`
   - 🚨 `SUSPICIOUS CORE DOMAIN CHARACTERS`

All URL content is escaped with a dedicated `escapeHtml` helper before being inserted into the DOM, so a malicious page URL cannot inject markup into the popup itself.

## Project Structure

```
Phishing-Shield/
├── icons/
│   └── icon16.png     # Extension toolbar icon
├── popup.html          # Popup markup
├── popup.css           # Popup styling
└── popup.js            # URL parsing & phishing heuristics
```

## Installation

> **Note:** This repository currently contains only the popup UI/logic — a `manifest.json` is required for the browser to load it as an extension. Add a Manifest V3 file (declaring `popup.html` as the `default_popup` action and `tabs`/`activeTab` permission) alongside these files before loading it as an unpacked extension.

Once a manifest is in place:

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
