document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (tab && tab.url) {
      
      // Try to get cached result
      chrome.storage.local.get([tab.id.toString()], (result) => {
        const data = result[tab.id];
        
        if (data) {
          renderResult(data);
        } else {
          // If not in cache, fetch it
          fetch('http://localhost:8000/api/quick-check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: tab.url })
          })
          .then(res => res.json())
          .then(data => renderResult(data))
          .catch(err => {
            document.getElementById('loading').innerText = 'Error connecting to PhishGuard API.';
          });
        }
      });
      
      document.getElementById('full-scan-btn').addEventListener('click', () => {
        // Open the dashboard to run a full scan
        chrome.tabs.create({ url: `http://localhost:3000/?url=${encodeURIComponent(tab.url)}` });
      });
    }
  });
});

function renderResult(data) {
  document.getElementById('loading').classList.add('hidden');
  const resultDiv = document.getElementById('result');
  resultDiv.classList.remove('hidden');
  
  const statusBox = document.getElementById('status-box');
  const icon = document.getElementById('icon');
  const riskLevel = document.getElementById('risk-level');
  const score = document.getElementById('score');
  const scoreBar = document.getElementById('score-bar');
  const warningMsg = document.getElementById('warning-message');
  
  riskLevel.innerText = data.risk_level;
  score.innerText = data.risk_score.toFixed(1) + '/100';
  scoreBar.style.width = `${data.risk_score}%`;
  
  if (data.risk_level === 'Phishing') {
    statusBox.className = 'p-4 rounded-xl border bg-red-500/10 border-red-500/30 flex flex-col items-center justify-center gap-2 text-red-500';
    icon.innerText = '🛡️❌';
    scoreBar.className = 'h-full bg-red-500';
    warningMsg.classList.remove('hidden');
  } else if (data.risk_level === 'Suspicious') {
    statusBox.className = 'p-4 rounded-xl border bg-yellow-500/10 border-yellow-500/30 flex flex-col items-center justify-center gap-2 text-yellow-500';
    icon.innerText = '⚠️';
    scoreBar.className = 'h-full bg-yellow-500';
    warningMsg.classList.remove('hidden');
  } else {
    statusBox.className = 'p-4 rounded-xl border bg-green-500/10 border-green-500/30 flex flex-col items-center justify-center gap-2 text-green-500';
    icon.innerText = '✅';
    scoreBar.className = 'h-full bg-green-500';
  }
}
