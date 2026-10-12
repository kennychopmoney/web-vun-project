const form = document.getElementById('scan-form');
const urlInput = document.getElementById('target-url');
const statusBox = document.getElementById('status');
const summaryBox = document.getElementById('summary');
const resultsBox = document.getElementById('results');
const findingsList = document.getElementById('findings-list');

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

function setStatus(message, type = 'success') {
  statusBox.textContent = message;
  statusBox.className = `status ${type}`;
  statusBox.classList.remove('hidden');
}

function renderFindings(findings) {
  findingsList.innerHTML = '';

  const sorted = [...findings].sort((a, b) => {
    return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
  });

  sorted.forEach((item) => {
    const li = document.createElement('li');
    li.classList.add(item.severity);

    li.innerHTML = `
      <div class="finding-header">
        <span>${item.title}</span>
        <span class="badge">${item.severity}</span>
      </div>
      <p>${item.description}</p>
      <small>${item.evidence}</small>
    `;

    findingsList.appendChild(li);
  });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const url = urlInput.value.trim();
  if (!url) {
    setStatus('Please enter a URL.', 'error');
    return;
  }

  setStatus('Scanning...', 'success');
  summaryBox.classList.add('hidden');
  resultsBox.classList.add('hidden');

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || 'Scan request failed.');
    }

    const totalFindings = Object.values(payload.summary || {}).reduce((sum, count) => sum + count, 0);
    document.getElementById('risk-score').textContent = payload.risk_score ?? 0;
    document.getElementById('status-code').textContent = payload.status_code ?? '--';
    document.getElementById('issue-count').textContent = totalFindings;
    document.getElementById('site-title').textContent = payload.title || 'Untitled page';
    document.getElementById('site-server').textContent = payload.server || 'Unknown server';

    renderFindings(payload.findings || []);

    summaryBox.classList.remove('hidden');
    resultsBox.classList.remove('hidden');
    setStatus('Scan completed successfully.', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
});
