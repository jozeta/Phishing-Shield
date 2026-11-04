document.addEventListener('DOMContentLoaded', async () => {
  const urlDisplay = document.getElementById('urlDisplay');
  const securityStatus = document.getElementById('securityStatus');
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

  function isIpLiteral(hostname) {
    if (IPV4_REGEX.test(hostname)) return true;
    return hostname.startsWith('[') && hostname.endsWith(']');
  }

  // Renders the URL as coloured parts. Text goes in via textContent only (never innerHTML): the
  // URL is attacker-controlled. Parts sit side by side with no spaces, so the popup shows (and
  // copies) the URL exactly as it is.
  function renderUrlParts(parts) {
    const spans = parts.filter(({ text }) => text).map(({ text, className }) => {
      const span = document.createElement('span');
      span.className = className;
      span.textContent = text;
      return span;
    });
    urlDisplay.replaceChildren(...spans);
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
    if (parts.length <= 2) {
      return { subdomain: '', mainDomain: hostname };
    }

    if (IPV4_REGEX.test(hostname)) {
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

    const subdomainParts = parts.slice(0, parts.length - mainDomainPartsCount);
    const mainDomainParts = parts.slice(parts.length - mainDomainPartsCount);

    return {
      subdomain: subdomainParts.join('.') + '.',
      mainDomain: mainDomainParts.join('.')
    };
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (!tab || !tab.url) {
    urlDisplay.textContent = "Unable to inspect current page context.";
    return;
  }

  const urlString = tab.url;

  try {
    const urlObj = new URL(urlString);
    const hostname = urlObj.hostname;

    // Browser pages, local files, extensions, about:blank: no website to judge, so no red alarm.
    if (urlObj.protocol !== 'https:' && urlObj.protocol !== 'http:') {
      renderUrlParts([{ text: urlString, className: 'url-dim' }]);
      securityStatus.className = "status-badge status-neutral";
      securityStatus.textContent = `NOT A WEBSITE (${urlObj.protocol.slice(0, -1).toUpperCase()} PAGE): NOTHING TO CHECK`;
      return;
    }

    // mainDomain is what's shown (keeps a trailing dot); checkDomain is what's checked.
    const { subdomain, mainDomain, checkDomain } = extractMainDomain(hostname);

    // Built directly from the parsed URL's components (not string search) so
    // the highlighted host can't be mis-sliced if the hostname text also
    // happens to appear earlier, e.g. inside userinfo (user:pass@host).
    const authPrefix = urlObj.username
      ? `${urlObj.username}${urlObj.password ? ':' + urlObj.password : ''}@`
      : '';
    const prefix = `${urlObj.protocol}//${authPrefix}`;
    const rest = `${urlObj.port ? ':' + urlObj.port : ''}${urlObj.pathname}${urlObj.search}${urlObj.hash}`;

    const isHttps = urlObj.protocol === 'https:';
    const isIp = isIpLiteral(hostname);
    const isDomainSafe = ALLOWED_DOMAIN_REGEX.test(checkDomain);
    const isPunycode = checkDomain.toLowerCase().startsWith('xn--');

    // Punycode in any subdomain label (e.g. xn--pypal-4ve.example.com): a look-alike that sits in
    // front of a real registrable domain. Checked after the core-domain checks, which matter more.
    const hasPunycodeSubdomain = subdomain.split('.').some((label) => label.toLowerCase().startsWith('xn--'));

    let generalClass = 'url-dim', subdomainClass = 'url-dim', mainDomainClass = 'url-main url-danger';

    if (!isHttps) {
      generalClass = subdomainClass = 'url-danger';

      securityStatus.className = "status-badge status-danger";
      securityStatus.textContent = "⚠️ UNENCRYPTED CONNECTION (NON-HTTPS)";
    } else if (isIp) {
      securityStatus.className = "status-badge status-danger";
      securityStatus.textContent = "🚨 RAW IP ADDRESS USED AS HOST (NO DOMAIN NAME)";
    } else if (!isDomainSafe || isPunycode) {
      securityStatus.className = "status-badge status-danger";
      securityStatus.textContent = isPunycode
        ? "🚨 PUNYCODE SPOOFING DETECTED ON CORE DOMAIN"
        : "🚨 SUSPICIOUS CORE DOMAIN CHARACTERS";
    } else if (hasPunycodeSubdomain) {
      subdomainClass = 'url-danger';
      mainDomainClass = 'url-main';

      securityStatus.className = "status-badge status-danger";
      securityStatus.textContent = "⚠️ PUNYCODE LOOK-ALIKE IN SUBDOMAIN";
    } else {
      mainDomainClass = 'url-main';

      securityStatus.className = "status-badge status-safe";
      securityStatus.textContent = "✅ VALIDATED STANDARD HTTPS DOMAIN";
    }

    renderUrlParts([
      { text: prefix, className: generalClass },
      { text: subdomain, className: subdomainClass },
      { text: mainDomain, className: mainDomainClass },
      { text: rest, className: generalClass },
    ]);

  } catch (err) {
    renderUrlParts([{ text: urlString, className: 'url-main url-danger' }]);
    securityStatus.className = "status-badge status-danger";
    securityStatus.textContent = "UNKNOWN PROTOCOL / UNPARSABLE CONTEXT";
  }
});