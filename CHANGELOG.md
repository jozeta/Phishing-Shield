# Changelog

All notable changes to Phishing-Shield are listed here, newest first.

Releases follow the project's git tags. Entries were reconstructed from the commit history.

## [Unreleased]

- New warning: punycode in a subdomain label (e.g. `xn--pypal-4ve.example.com`) is flagged as a look-alike; a punycode TLD alone is not
- The URL is now rendered with `createElement`/`textContent` instead of `innerHTML` (no visual change); the `escapeHtml` helper is gone and the no-unsanitized lint rule is now an error
- More tests: subdomain punycode, underscore in the core domain, punycode TLD, text-only rendering
- README: documents the raw-IP check, IPv6, what the character check actually catches, check order, project structure and dev commands
- popup.html gets a `<title>`
- `.claude-standards`: design decision recorded (keeps its own look)

- ESLint (flat config, with the no-unsanitized rule) as a dev-only tool; CI runs `npm run lint`
- First automated tests (tests/popup.test.mjs runs popup.js against fake tabs: verdicts, host splitting, escaping) and a CI workflow

## [1.0.0] - 2026-11-02

- Initial commit: Phishing Shield browser extension
- Ignore macOS, Claude Code and secret files
- Add CLAUDE.md with project guidance for Claude Code
- README: add screenshots
- Add security policy
