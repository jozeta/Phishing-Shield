/* global PhishingShield */
// The popup: asks lib/analyze.js about the active tab's URL and renders the answer. Everything
// derived from the URL goes in via textContent only (never innerHTML): the URL is attacker-controlled.
document.addEventListener('DOMContentLoaded', async () => {
  const urlDisplay = document.getElementById('urlDisplay');
  const securityStatus = document.getElementById('securityStatus');
  const moreFindings = document.getElementById('moreFindings');

  const ROLE_CLASSES = {
    dim: 'url-dim',
    danger: 'url-danger',
    warn: 'url-warn',
    main: 'url-main',
    'main-danger': 'url-main url-danger',
  };

  function span(text, className) {
    const el = document.createElement('span');
    el.className = className;
    el.textContent = text;
    return el;
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab || !tab.url) {
    urlDisplay.textContent = "Unable to inspect current page context.";
    return;
  }

  const result = PhishingShield.analyzeUrl(tab.url);

  // Parts sit side by side with no spaces, so the popup shows (and copies) the exact URL.
  urlDisplay.replaceChildren(...result.parts.map((p) => span(p.text, ROLE_CLASSES[p.role])));

  const [headline, ...others] = result.findings;
  securityStatus.className = `status-badge status-${headline.level}`;
  securityStatus.textContent = headline.message;

  moreFindings.replaceChildren(...others.map((f) => {
    const li = document.createElement('li');
    li.className = `finding-${f.level}`;
    li.textContent = f.message;
    return li;
  }));
});
