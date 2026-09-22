// Multi-Guard WebShield & Download Protection
// Service Worker (Manifest V3)

const BLOCKED_DOMAINS = [
  "malware-traffic-analysis.net",
  "vxvault.net",
  "clean-mx.de",
  "zeustracker.abuse.ch",
  "ransomwaretracker.abuse.ch",
  "feodotracker.abuse.ch",
  "urlhaus.abuse.ch",
  "phishing-site.example",
  "fake-bank-login.com",
  "secure-login-update.net",
  "bank-weryfikacja.pl",
  "paczka-doplata.com",
  "inpost-sledzenie-faktura.top"
];

const SUSPICIOUS_EXTENSIONS = [
  ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".ps1", ".wsf", ".cpl"
];

// 1. Navigation Blocker
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // Only top-level frames

  try {
    const urlObj = new URL(details.url);
    const host = urlObj.hostname.toLowerCase();

    const isBlocked = BLOCKED_DOMAINS.some(domain => host === domain || host.endsWith("." + domain));
    if (isBlocked) {
      const blockUrl = chrome.runtime.getURL("blocked.html") + 
        "?type=site&url=" + encodeURIComponent(details.url) + 
        "&threat=" + encodeURIComponent("Złośliwa witryna / Phishing");
      
      chrome.tabs.update(details.tabId, { url: blockUrl });
    }
  } catch (e) {
    // Ignore invalid URLs (chrome://, about:blank, etc.)
  }
});

// 2. Real-time Dangerous Download Interceptor
chrome.downloads.onCreated.addListener((downloadItem) => {
  const url = (downloadItem.url || "").toLowerCase();
  const filename = (downloadItem.filename || "").toLowerCase();

  const isSuspiciousExt = SUSPICIOUS_EXTENSIONS.some(ext => filename.endsWith(ext) || url.includes(ext + "?") || url.endsWith(ext));
  const isSuspiciousDomain = BLOCKED_DOMAINS.some(domain => url.includes(domain));

  if (isSuspiciousDomain || (isSuspiciousExt && (url.includes("phish") || url.includes("malware") || url.includes("payload") || url.includes("crack") || url.includes("keygen")))) {
    // Cancel dangerous download immediately
    chrome.downloads.cancel(downloadItem.id, () => {
      chrome.downloads.erase({ id: downloadItem.id }, () => {});
    });

    // Open block alert tab
    const blockUrl = chrome.runtime.getURL("blocked.html") + 
      "?type=file&url=" + encodeURIComponent(downloadItem.url) + 
      "&file=" + encodeURIComponent(downloadItem.filename || "Pobrany plik wykonywalny") +
      "&threat=" + encodeURIComponent("Pobieranie zablokowane: Podejrzany plik wykonywalny");

    chrome.tabs.create({ url: blockUrl });
  }
});
