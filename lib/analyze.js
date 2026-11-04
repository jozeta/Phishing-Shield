// URL analysis shared by the popup (popup.js) and the toolbar badge (background.js). Pure: it
// takes a URL string and returns what to show, it never touches the DOM or the network.
//
//   PhishingShield.analyzeUrl(url) -> {
//     level:    'safe' | 'warn' | 'danger' | 'neutral',
//     findings: [{ id, level, message }]   most serious first; findings[0] is the headline
//     parts:    [{ text, role }]           the URL split for display; role is one of
//                                          'dim' | 'danger' | 'warn' | 'main' | 'main-danger' |
//                                          'main-warn'
//   }
(function () {
  const ALLOWED_DOMAIN_REGEX = /^[a-zA-Z0-9.-]+$/;
  const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

  // Public Suffix List (lib/psl-data.js, loaded first): normal rules, "*." wildcards and "!"
  // exceptions, parsed once on first use.
  let psl;
  function loadPsl() {
    if (psl) return psl;
    psl = { rules: new Set(), wildcards: new Set(), exceptions: new Set() };
    for (const rule of (globalThis.PSL_RULES || '').split('\n')) {
      if (rule.startsWith('!')) psl.exceptions.add(rule.slice(1));
      else if (rule.startsWith('*.')) psl.wildcards.add(rule.slice(2));
      else if (rule) psl.rules.add(rule);
    }
    return psl;
  }

  // The longest matching public suffix of a lower-case ASCII hostname, per the PSL algorithm:
  // an exception rule wins, otherwise the longest rule; with no match, the last label ("*").
  function publicSuffix(hostname) {
    const { rules, wildcards, exceptions } = loadPsl();
    const labels = hostname.split('.');
    for (let i = 0; i < labels.length; i++) {
      const candidate = labels.slice(i).join('.');
      if (exceptions.has(candidate)) return labels.slice(i + 1).join('.');
      if (rules.has(candidate)) return candidate;
      if (i + 1 < labels.length && wildcards.has(labels.slice(i + 1).join('.'))) return candidate;
    }
    return labels[labels.length - 1];
  }

  // Most serious first: the first finding becomes the headline badge.
  const SEVERITY_ORDER = [
    'userinfo', 'ip', 'punycode', 'lookalike', 'brand-elsewhere', 'characters', 'punycode-subdomain',
    'http', 'brand-ending', 'port',
  ];

  // Country endings that are mostly rented out as generic domains (and popular for phishing): a
  // brand name on these isn't accepted as the brand's own country site.
  const GENERIC_USE_CCTLDS = new Set(['co', 'io', 'me', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'ws', 'tv', 'ai', 'su', 'to', 'ly']);

  // Characters that pass for others at a glance: paypa1, paypai, micros0ft, arnazon.
  function normalizeLookalike(text) {
    return text.toLowerCase()
      .replace(/rn/g, 'm').replace(/vv/g, 'w')
      .replace(/0/g, 'o').replace(/[1i|]/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a')
      .replace(/5/g, 's').replace(/7/g, 't');
  }

  // Edit distance with adjacent swaps counted as one edit (optimal string alignment).
  function editDistance(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
    return d[a.length][b.length];
  }

  // Words phishing domains pad brand names with: paypal-login, swedbanksecure, apple-id-verify.
  const PHISH_WORDS = ['login', 'logon', 'signin', 'sign', 'secure', 'security', 'verify', 'verification',
    'account', 'accounts', 'support', 'update', 'auth', 'confirm', 'wallet', 'service', 'services', 'help',
    'id', 'online', 'portal', 'web', 'app', 'my', 'track', 'tracking', 'delivery', 'refund', 'billing',
    'payment', 'pay', 'unlock', 'recovery', 'alert', 'notice', 'customer', 'center', 'centre', 'team', 'se', 'us'];
  const PHISH_WORDS_RE = new RegExp(`^(${PHISH_WORDS.join('|')})+$`);

  // A keyword inside a longer word only counts when the rest is phishing padding
  // (paypalsecure, myswedbanklogin), so nordnetwork or postnorden don't match.
  function containsWithPadding(word, keyword) {
    const at = word.indexOf(keyword);
    if (at < 0 || word === keyword) return false;
    const rest = [word.slice(0, at), word.slice(at + keyword.length)].filter(Boolean);
    return rest.every((part) => PHISH_WORDS_RE.test(part));
  }

  // A token looks like a keyword: the same after swapping look-alike characters (any length), one
  // adjacent swap (netfilx), or for long names, where ordinary words rarely come this close, one
  // typo (two from 11 letters). Short names stop at swaps: trader/tradera, revolt/revolut.
  function looksLike(token, keyword) {
    if (token === keyword || token.length < 3) return false;
    if (normalizeLookalike(token) === normalizeLookalike(keyword)) return true;
    if (keyword.length < 5) return false;
    const distance = editDistance(token, keyword);
    if (keyword.length >= 11) return distance <= 2;
    if (keyword.length >= 8) return distance <= 1;
    return distance === 1 && token.length === keyword.length && [...token].sort().join() === [...keyword].sort().join();
  }

  // Brand checks against lib/brands.js. registrable is the lower-case registrable domain without
  // a trailing dot, subdomain the lower-case part in front of it.
  function brandFindings(subdomain, registrable) {
    const brands = globalThis.PHISHING_SHIELD_BRANDS || [];
    if (brands.some((b) => b.domains.includes(registrable))) return [];

    const suffix = publicSuffix(registrable);
    const label = registrable.slice(0, -(suffix.length + 1));
    const tld = suffix.split('.').pop();
    const isCountryEnding = tld.length === 2 && !GENERIC_USE_CCTLDS.has(tld);
    const allKeywords = new Set(brands.flatMap((b) => b.keywords));
    const subTokens = subdomain.split(/[.-]/).filter(Boolean);
    const labelTokens = label.split('-').filter(Boolean);
    const results = [];

    for (const brand of brands) {
      const home = brand.domains[0].toUpperCase();
      for (const keyword of brand.keywords) {
        const KEYWORD = keyword.toUpperCase();
        if (label === keyword) {
          if (!isCountryEnding) {
            results.push({ id: 'brand-ending', level: 'warn', inSubdomain: false,
              message: `⚠️ ${brand.name.toUpperCase()} NAME ON AN ENDING ${brand.name.toUpperCase()} DOESN'T USE (.${suffix.toUpperCase()})` });
          }
          continue;
        }
        // Whole word (paypal-login) or padded with phishing words (paypalsecure). Brand names
        // that are ordinary words (apple, chase) need a phishing word somewhere in the host too.
        const matches = (tokens) => tokens.some((t) => t === keyword || containsWithPadding(t, keyword));
        const inSub = matches(subTokens);
        const inLabel = matches(labelTokens);
        const common = (brand.commonWords || []).includes(keyword);
        const hasPhishWord = [...subTokens, ...labelTokens].some((t) => t !== keyword && PHISH_WORDS_RE.test(t));
        if ((inSub || inLabel) && (!common || hasPhishWord)) {
          results.push({ id: 'brand-elsewhere', level: 'danger', inSubdomain: inSub && !inLabel,
            message: `🚨 "${KEYWORD}" ON A SITE THAT ISN'T ${home}` });
        }
        if (labelTokens.some((t) => !allKeywords.has(t) && looksLike(t, keyword))) {
          results.push({ id: 'lookalike', level: 'danger', inSubdomain: false, message: `🚨 LOOK-ALIKE OF ${home}` });
        }
      }
    }
    return results;
  }

  function isIpLiteral(hostname) {
    if (IPV4_REGEX.test(hostname)) return true;
    return hostname.startsWith('[') && hostname.endsWith(']');
  }

  function extractMainDomain(fullHostname) {
    // A trailing dot (www.example.com.) is a valid fully qualified name. Split without it and
    // give it back to the main domain, or "com." would be highlighted as the whole domain.
    const trailingDot = fullHostname.endsWith('.') ? '.' : '';
    const hostname = trailingDot ? fullHostname.slice(0, -1) : fullHostname;
    const split = splitHost(hostname);
    return { subdomain: split.subdomain, mainDomain: split.mainDomain + trailingDot, checkDomain: split.mainDomain };
  }

  // Registrable domain = public suffix plus one label (paypal-login.github.io, bank.co.uk).
  function splitHost(hostname) {
    if (IPV4_REGEX.test(hostname)) return { subdomain: '', mainDomain: hostname };
    const labels = hostname.split('.');
    const suffixLabels = publicSuffix(hostname.toLowerCase()).split('.').length;
    if (labels.length <= suffixLabels + 1) return { subdomain: '', mainDomain: hostname };
    const cut = labels.length - suffixLabels - 1;
    return { subdomain: labels.slice(0, cut).join('.') + '.', mainDomain: labels.slice(cut).join('.') };
  }

  function analyzeUrl(urlString) {
    let urlObj;
    try {
      urlObj = new URL(urlString);
    } catch {
      return {
        level: 'danger',
        findings: [{ id: 'unparsable', level: 'danger', message: 'UNKNOWN PROTOCOL / UNPARSABLE CONTEXT' }],
        parts: [{ text: urlString, role: 'main-danger' }],
      };
    }

    // Browser pages, local files, extensions, about:blank: no website to judge, so no red alarm.
    if (urlObj.protocol !== 'https:' && urlObj.protocol !== 'http:') {
      const scheme = urlObj.protocol.slice(0, -1).toUpperCase();
      return {
        level: 'neutral',
        findings: [{ id: 'not-web', level: 'neutral', message: `NOT A WEBSITE (${scheme} PAGE): NOTHING TO CHECK` }],
        parts: [{ text: urlString, role: 'dim' }],
      };
    }

    const hostname = urlObj.hostname;
    // mainDomain is what's shown (keeps a trailing dot); checkDomain is what's checked.
    const { subdomain, mainDomain, checkDomain } = extractMainDomain(hostname);

    // Built directly from the parsed URL's components (not string search) so the highlighted host
    // can't be mis-sliced if the hostname text also appears earlier, e.g. in user:pass@host.
    const authPrefix = urlObj.username
      ? `${urlObj.username}${urlObj.password ? ':' + urlObj.password : ''}@`
      : '';
    const port = urlObj.port ? ':' + urlObj.port : '';
    const rest = `${urlObj.pathname}${urlObj.search}${urlObj.hash}`;

    const found = new Map();
    const add = (id, level, message) => found.set(id, { id, level, message });

    // user:pass@ before the host: https://paypal.com@evil.example reads as paypal.com at a glance.
    if (authPrefix) add('userinfo', 'danger', '🚨 TEXT BEFORE "@" DISGUISES THE REAL SITE');
    if (urlObj.protocol !== 'https:') add('http', 'danger', '⚠️ UNENCRYPTED CONNECTION (NON-HTTPS)');
    if (isIpLiteral(hostname)) {
      add('ip', 'danger', '🚨 RAW IP ADDRESS USED AS HOST (NO DOMAIN NAME)');
    } else {
      if (checkDomain.toLowerCase().startsWith('xn--')) {
        add('punycode', 'danger', '🚨 PUNYCODE SPOOFING DETECTED ON CORE DOMAIN');
      } else if (!ALLOWED_DOMAIN_REGEX.test(checkDomain)) {
        add('characters', 'danger', '🚨 SUSPICIOUS CORE DOMAIN CHARACTERS');
      }
      // Punycode in any subdomain label (xn--pypal-4ve.example.com): a look-alike in front of a
      // real registrable domain.
      if (subdomain.split('.').some((label) => label.toLowerCase().startsWith('xn--'))) {
        add('punycode-subdomain', 'danger', '⚠️ PUNYCODE LOOK-ALIKE IN SUBDOMAIN');
      }
    }

    if (!found.has('ip')) {
      const lowerSub = subdomain.toLowerCase();
      for (const f of brandFindings(lowerSub, checkDomain.toLowerCase())) {
        if (!found.has(f.id)) found.set(f.id, f); // first brand per kind is enough
      }
    }

    // URL drops default ports, so any port left is unusual. Real sites rarely use one; phishing
    // kits on rented servers and home routers often do.
    if (port) add('port', 'warn', `⚠️ UNUSUAL PORT ${port}`);

    const findings = SEVERITY_ORDER.filter((id) => found.has(id))
      .map((id) => ({ id, level: found.get(id).level, message: found.get(id).message }));
    const has = (id) => found.has(id);
    const brandInSub = has('brand-elsewhere') && found.get('brand-elsewhere').inSubdomain;
    const coreProblem = has('ip') || has('punycode') || has('characters') || has('lookalike') ||
      (has('brand-elsewhere') && !brandInSub);
    const general = has('http') ? 'danger' : 'dim';

    const parts = [
      { text: `${urlObj.protocol}//`, role: general },
      { text: authPrefix, role: 'danger' },
      { text: subdomain, role: has('http') || has('punycode-subdomain') || brandInSub ? 'danger' : 'dim' },
      { text: mainDomain, role: coreProblem || has('http') ? 'main-danger' : has('brand-ending') ? 'main-warn' : 'main' },
      { text: port, role: has('http') ? 'danger' : 'warn' },
      { text: rest, role: general },
    ].filter((p) => p.text);

    if (!findings.length) {
      findings.push({ id: 'ok', level: 'safe', message: '✅ VALIDATED STANDARD HTTPS DOMAIN' });
    }
    return { level: findings[0].level, findings, parts };
  }

  globalThis.PhishingShield = { analyzeUrl, extractMainDomain, publicSuffix };
})();
