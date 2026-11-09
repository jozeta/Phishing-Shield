/* global PhishingShield */
// Opt-in toolbar verdict: when the user has granted the optional "tabs" permission (toggle in the
// popup), every tab's toolbar icon gets a badge from the same checks the popup runs. Without the
// permission this does nothing: tab URLs aren't visible and every badge is cleared. URLs are only
// checked here, on the device; nothing is stored or sent anywhere.
importScripts('lib/psl-data.js', 'lib/brands.js', 'lib/analyze.js');

const TABS = { permissions: ['tabs'] };

const BADGES = {
  danger: { text: '!', color: '#c62828' },
  warn: { text: '!', color: '#a35200' },
  safe: { text: '✓', color: '#1e7e34' },
};

function enabled() {
  return chrome.permissions.contains(TABS);
}

async function showVerdict(tabId, url) {
  const badge = url ? BADGES[PhishingShield.analyzeUrl(url).level] : undefined;
  try {
    await chrome.action.setBadgeText({ tabId, text: badge ? badge.text : '' });
    if (badge) await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  } catch {
    // The tab closed in the meantime.
  }
}

async function refreshAllTabs() {
  const on = await enabled();
  for (const tab of await chrome.tabs.query({})) {
    await showVerdict(tab.id, on ? tab.url : undefined);
  }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (!changeInfo.url && changeInfo.status !== 'loading') return;
  await showVerdict(tabId, (await enabled()) ? tab.url : undefined);
});

chrome.permissions.onAdded.addListener(refreshAllTabs);
chrome.permissions.onRemoved.addListener(refreshAllTabs);
chrome.runtime.onStartup.addListener(refreshAllTabs);
chrome.runtime.onInstalled.addListener(refreshAllTabs);
