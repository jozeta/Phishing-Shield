# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report it privately through GitHub instead: go to the **Security** tab of this repository and click
**Report a vulnerability** ([direct link](https://github.com/jozeta/Phishing-Shield/security/advisories/new)).
Include what you found, how to reproduce it, and the impact you expect.

This is a personal project maintained in spare time. You can expect an acknowledgement within a
week. Fixes are released as soon as practical, and you'll be credited in the advisory unless you
prefer otherwise.

## Scope

Of particular interest: URLs that inject markup into the popup, spoofed domains the checks wrongly mark as safe, and anything that makes the extension read or send more than it should (it asks for `activeTab`, plus `tabs` only when the toolbar verdict is switched on).

## Supported versions

Only the latest version on the `main` branch receives security fixes.
