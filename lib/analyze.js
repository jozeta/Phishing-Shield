// URL analysis shared by the popup (popup.js) and the toolbar badge (background.js). Pure: it
// takes a URL string and returns what to show, it never touches the DOM or the network.
//
//   PhishingShield.analyzeUrl(url) -> {
//     level:    'safe' | 'warn' | 'danger' | 'neutral',
//     findings: [{ id, level, message }]   most serious first; findings[0] is the headline
//     parts:    [{ text, role }]           the URL split for display; role is one of
//                                          'dim' | 'danger' | 'warn' | 'main' | 'main-danger'
//   }
(function () {
  const ALLOWED_DOMAIN_REGEX = /^[a-zA-Z0-9.-]+$/;
  const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

  // Shared hosting: anyone can get a subdomain here, so the user's own label belongs to the
  // highlighted domain (paypal-login.github.io, not github.io). A short list of popular ones,
  // not the full Public Suffix List.
  const SHARED_HOSTING_SUFFIXES = [
    'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app',
    'herokuapp.com', 'web.app', 'firebaseapp.com', 'appspot.com', 'blogspot.com',
    'azurewebsites.net', 'cloudfront.net', 'glitch.me', 'ngrok-free.app', 'ngrok.io',
    'onrender.com', 'fly.dev', 'replit.app', 'wixsite.com', 'weebly.com', '000webhostapp.com',
    'r2.dev', 'surge.sh', 'translate.goog',
  ];

  // Most serious first: the first finding becomes the headline badge.
  const SEVERITY_ORDER = ['userinfo', 'ip', 'punycode', 'characters', 'punycode-subdomain', 'http'];

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

  function splitHost(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2 || IPV4_REGEX.test(hostname)) {
      return { subdomain: '', mainDomain: hostname };
    }

    const last = parts[parts.length - 1];
    const secondLast = parts[parts.length - 2];
    const commonSLDs = ['com', 'co', 'net', 'org', 'gov', 'edu', 'ac', 'biz', 'info'];

    let mainDomainPartsCount = 2;
    const sharedSuffix = SHARED_HOSTING_SUFFIXES.find((suffix) => hostname.toLowerCase().endsWith('.' + suffix));
    if (sharedSuffix) {
      mainDomainPartsCount = sharedSuffix.split('.').length + 1;
    } else if (last.length === 2 && commonSLDs.includes(secondLast.toLowerCase())) {
      mainDomainPartsCount = 3;
    }

    if (parts.length <= mainDomainPartsCount) {
      return { subdomain: '', mainDomain: hostname };
    }
    return {
      subdomain: parts.slice(0, parts.length - mainDomainPartsCount).join('.') + '.',
      mainDomain: parts.slice(parts.length - mainDomainPartsCount).join('.'),
    };
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

    const findings = SEVERITY_ORDER.filter((id) => found.has(id)).map((id) => found.get(id));
    const has = (id) => found.has(id);
    const coreProblem = has('ip') || has('punycode') || has('characters');
    const general = has('http') ? 'danger' : 'dim';

    const parts = [
      { text: `${urlObj.protocol}//`, role: general },
      { text: authPrefix, role: 'danger' },
      { text: subdomain, role: has('http') || has('punycode-subdomain') ? 'danger' : 'dim' },
      { text: mainDomain, role: coreProblem || has('http') ? 'main-danger' : 'main' },
      { text: port, role: general },
      { text: rest, role: general },
    ].filter((p) => p.text);

    if (!findings.length) {
      findings.push({ id: 'ok', level: 'safe', message: '✅ VALIDATED STANDARD HTTPS DOMAIN' });
    }
    return { level: findings[0].level, findings, parts };
  }

  globalThis.PhishingShield = { analyzeUrl, extractMainDomain };
})();
