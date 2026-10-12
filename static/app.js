const form = document.getElementById('scan-form');
const urlInput = document.getElementById('target-url');
const statusBox = document.getElementById('status');
const summaryBox = document.getElementById('summary');
const resultsBox = document.getElementById('results');
const findingsList = document.getElementById('findings-list');
const downloadButton = document.getElementById('download-report');
const activeCheckInput = document.getElementById('active-check');
const reconCheckInput = document.getElementById('recon-check');
const authorizationInput = document.getElementById('authorization-confirmed');
const reconResults = document.getElementById('recon-results');

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
let latestReport = null;

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

    const header = document.createElement('div');
    header.className = 'finding-header';
    const title = document.createElement('span');
    title.textContent = item.title;
    const severity = document.createElement('span');
    severity.className = 'badge';
    severity.textContent = item.severity;
    header.append(title, severity);

    const description = document.createElement('p');
    description.textContent = item.description;
    const confidence = document.createElement('p');
    confidence.className = 'finding-confidence';
    confidence.textContent = `Detection confidence: ${item.confidence || 'Low'}`;
    const evidence = document.createElement('small');
    evidence.textContent = `Evidence: ${item.evidence || 'No additional evidence.'}`;
    const remediation = document.createElement('div');
    remediation.className = 'remediation';
    const remediationTitle = document.createElement('strong');
    remediationTitle.textContent = 'Recommended remediation';
    const remediationText = document.createElement('p');
    remediationText.textContent = item.remediation || 'Review the evidence and verify the behavior manually.';
    remediation.append(remediationTitle, remediationText);

    li.append(header, description, confidence, evidence, remediation);
    if (item.reference) {
      const reference = document.createElement('a');
      reference.href = item.reference;
      reference.target = '_blank';
      reference.rel = 'noopener noreferrer';
      reference.textContent = 'Technical reference';
      reference.className = 'reference-link';
      li.appendChild(reference);
    }
    findingsList.appendChild(li);
  });
}

function renderRecon(data) {
  reconResults.replaceChildren();
  reconResults.classList.toggle('hidden', !data);
  if (!data) {
    return;
  }

  const heading = document.createElement('h3');
  heading.textContent = 'Active reconnaissance';
  const host = document.createElement('p');
  host.textContent = `Host: ${data.hostname}`;
  const addresses = document.createElement('p');
  addresses.textContent = `Public IP addresses: ${data.addresses.join(', ')}`;
  const ports = document.createElement('p');
  const openPorts = data.port_results.filter((result) => result.status === 'open');
  ports.textContent = `Checked ports: ${data.checked_ports.join(', ')}. Open: ${
    openPorts.length ? openPorts.map((result) => `${result.port} (${result.address})`).join(', ') : 'none detected'
  }.`;
  const tls = document.createElement('p');
  tls.textContent = data.tls
    ? data.tls.error || `TLS: ${data.tls.tls_version}; certificate expires ${data.tls.certificate_expires_at || 'unknown'}`
    : 'TLS certificate details: unavailable (no checked HTTPS port responded).';
  const note = document.createElement('small');
  note.textContent = 'Closed-or-filtered ports are indistinguishable from this limited TCP connect check.';
  reconResults.append(heading, host, addresses, ports, tls, note);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const url = urlInput.value.trim();
  const active = activeCheckInput.checked;
  const reconnaissance = reconCheckInput.checked;
  const authorized = authorizationInput.checked;
  if (!url) {
    setStatus('Please enter a URL.', 'error');
    return;
  }
  if ((active || reconnaissance) && !authorized) {
    setStatus('Confirm explicit authorization before running active checks.', 'error');
    return;
  }

  setStatus('Scanning...', 'success');
  summaryBox.classList.add('hidden');
  resultsBox.classList.add('hidden');
  downloadButton.disabled = true;
  latestReport = null;

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, active, reconnaissance, authorized }),
    });

    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || 'Scan request failed.');
    }

    latestReport = payload;
    const totalFindings = Object.values(payload.summary || {}).reduce((sum, count) => sum + count, 0);
    document.getElementById('risk-score').textContent = payload.risk_score ?? 0;
    document.getElementById('status-code').textContent = payload.status_code ?? '--';
    document.getElementById('issue-count').textContent = totalFindings;
    document.getElementById('site-title').textContent = payload.title || 'Untitled page';
    document.getElementById('site-server').textContent = payload.server || 'Unknown server';
    const activeModes = [];
    if (payload.active_checks?.enabled) {
      activeModes.push(`${payload.active_checks.probes_sent} query probes`);
    }
    if (payload.reconnaissance) {
      activeModes.push('reconnaissance');
    }
    document.getElementById('active-status').textContent = activeModes.length
      ? `Active checks: ${activeModes.join(' + ')}`
      : 'Passive checks only';

    renderFindings(payload.findings || []);
    renderRecon(payload.reconnaissance);

    summaryBox.classList.remove('hidden');
    resultsBox.classList.remove('hidden');
    downloadButton.disabled = false;
    setStatus('Scan completed successfully.', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

downloadButton.addEventListener('click', () => {
  if (!latestReport) {
    return;
  }

  const report = new Blob([JSON.stringify(latestReport, null, 2)], { type: 'application/json' });
  const downloadUrl = URL.createObjectURL(report);
  const link = document.createElement('a');
  const hostname = new URL(latestReport.url).hostname.replace(/[^a-z0-9.-]/gi, '_');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  link.href = downloadUrl;
  link.download = `webvun-${hostname}-${timestamp}.json`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
});
