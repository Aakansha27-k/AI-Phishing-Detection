// background.js
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    // Send a quick check request to the API
    fetch('http://localhost:8000/api/quick-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    })
    .then(res => res.json())
    .then(data => {
      // If it's a high risk, change the badge
      if (data.risk_level === 'Phishing') {
        chrome.action.setBadgeText({ text: '!', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId });
      } else if (data.risk_level === 'Suspicious') {
        chrome.action.setBadgeText({ text: '?', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });
      } else {
        chrome.action.setBadgeText({ text: '✓', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId });
      }
      
      // We can also store the result to show in popup
      chrome.storage.local.set({ [tabId]: data });
    })
    .catch(err => console.error('PhishGuard API Error:', err));
  }
});
