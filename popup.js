document.addEventListener('DOMContentLoaded', async () => {
  const urlDisplay = document.getElementById('urlDisplay');
  const securityStatus = document.getElementById('securityStatus');
  const ALLOWED_DOMAIN_REGEX = /^[a-zA-Z0-9.-]+$/;
  const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

  function isIpLiteral(hostname) {
    if (IPV4_REGEX.test(hostname)) return true;
    return hostname.startsWith('[') && hostname.endsWith(']');
  }

  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function extractMainDomain(hostname) {
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
    if (last.length === 2 && commonSLDs.includes(secondLast.toLowerCase())) {
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
    
    const { subdomain, mainDomain } = extractMainDomain(hostname);

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
    const isDomainSafe = ALLOWED_DOMAIN_REGEX.test(mainDomain);
    const isPunycode = mainDomain.toLowerCase().startsWith('xn--');

    let generalStyle = '', mainDomainStyle = '';

    if (!isHttps) {
      generalStyle = 'color: #ff3b30; font-weight: normal;';
      mainDomainStyle = 'color: #ff3b30; font-weight: bold;';
      
      securityStatus.className = "status-badge status-danger";
      securityStatus.textContent = "⚠️ UNENCRYPTED CONNECTION (NON-HTTPS)";
    } else if (isIp) {
      generalStyle = 'color: #8e8e93; font-weight: normal;';
      mainDomainStyle = 'color: #ff3b30; font-weight: bold;';

      securityStatus.className = "status-badge status-danger";
      securityStatus.textContent = "🚨 RAW IP ADDRESS USED AS HOST (NO DOMAIN NAME)";
    } else if (!isDomainSafe || isPunycode) {
      generalStyle = 'color: #8e8e93; font-weight: normal;';
      mainDomainStyle = 'color: #ff3b30; font-weight: bold;';
      
      securityStatus.className = "status-badge status-danger";
      securityStatus.textContent = isPunycode 
        ? "🚨 PUNYCODE SPOOFING DETECTED ON CORE DOMAIN" 
        : "🚨 SUSPICIOUS CORE DOMAIN CHARACTERS";
    } else {
      generalStyle = 'color: #8e8e93; font-weight: normal;';
      mainDomainStyle = 'color: #1c1c1e; font-weight: bold;';
      
      securityStatus.className = "status-badge status-safe";
      securityStatus.textContent = "✅ VALIDATED STANDARD HTTPS DOMAIN";
    }

    urlDisplay.innerHTML = `
      <span style="${generalStyle}">${escapeHtml(prefix)}</span>
      <span style="${generalStyle}">${escapeHtml(subdomain)}</span>
      <span style="${mainDomainStyle}">${escapeHtml(mainDomain)}</span>
      <span style="${generalStyle}">${escapeHtml(rest)}</span>
    `;

  } catch (err) {
    urlDisplay.innerHTML = `<span style="color: #ff3b30; font-weight: bold;">${escapeHtml(urlString)}</span>`;
    securityStatus.className = "status-badge status-danger";
    securityStatus.textContent = "UNKNOWN PROTOCOL / UNPARSABLE CONTEXT";
  }
});