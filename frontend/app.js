let API_BASE_URL = "http://127.0.0.1:8000";
let trendChartInstance = null;
let riskChartInstance = null;
let categoriesChartInstance = null;

// Initialize Lucide Icons & Page State
document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  setupNavigation();
  checkApiHealth();
  loadDashboardData();
});

// Navigation Setup
function setupNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const targetView = item.getAttribute("data-view");
      switchView(targetView);
    });
  });
}

function switchView(viewName) {
  // Update Nav Active State
  document.querySelectorAll(".nav-item").forEach(item => {
    if (item.getAttribute("data-view") === viewName) {
      item.classList.add("active");
    } else {
      item.classList.remove("active");
    }
  });

  // Update Views
  document.querySelectorAll(".view-container").forEach(container => {
    container.classList.remove("active");
  });

  const activeView = document.getElementById(`view-${viewName}`);
  if (activeView) {
    activeView.classList.add("active");
  }

  // Update Topbar Title
  const titles = {
    'dashboard': 'Overview Dashboard',
    'message-scanner': 'AI Message & Email Scanner',
    'url-scanner': 'Malicious URL Inspector',
    'history': 'Scan History & Case Files',
    'analytics': 'Threat Trends & Analytics',
    'settings': 'API & System Settings',
    'help': 'Safety & Phishing Prevention'
  };
  document.getElementById("pageTitle").innerText = titles[viewName] || 'Overview Dashboard';

  if (viewName === 'dashboard') loadDashboardData();
  if (viewName === 'history') loadHistoryData();
  if (viewName === 'analytics') loadAnalyticsData();

  if (window.lucide) lucide.createIcons();
}

// API Health Check
async function checkApiHealth() {
  const statusDot = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");
  try {
    const res = await fetch(`${API_BASE_URL}/health`);
    if (res.ok) {
      statusDot.classList.remove("offline");
      statusText.innerText = "API Engine Connected";
    } else {
      throw new Error();
    }
  } catch (err) {
    statusDot.classList.add("offline");
    statusText.innerText = "API Offline (Run Backend)";
  }
}

// Load Dashboard Data & Charts
async function loadDashboardData() {
  try {
    const res = await fetch(`${API_BASE_URL}/api/analytics`);
    const data = await res.json();

    document.getElementById("statTotalScans").innerText = data.total_scans || 0;
    document.getElementById("statHighThreats").innerText = data.high_risk_count || 0;

    renderTrendChart(data.recent_trend);
    renderRiskChart(data.risk_distribution);
    loadRecentScans();
  } catch (err) {
    console.warn("Could not fetch live dashboard analytics:", err);
  }
}

function renderTrendChart(trendData) {
  const ctx = document.getElementById("trendChart")?.getContext("2d");
  if (!ctx) return;

  if (trendChartInstance) trendChartInstance.destroy();

  const labels = trendData.map(t => t.day);
  const scans = trendData.map(t => t.scans);
  const threats = trendData.map(t => t.threats);

  trendChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Total Scans',
          data: scans,
          borderColor: '#4cc9f0',
          backgroundColor: 'rgba(76, 201, 240, 0.1)',
          fill: true,
          tension: 0.4
        },
        {
          label: 'High/Critical Threats',
          data: threats,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          fill: true,
          tension: 0.4
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#94a3b8' } } },
      scales: {
        x: { ticks: { color: '#64748b' }, grid: { color: '#2b3a67' } },
        y: { ticks: { color: '#64748b' }, grid: { color: '#2b3a67' } }
      }
    }
  });
}

function renderRiskChart(riskDist) {
  const ctx = document.getElementById("riskDistributionChart")?.getContext("2d");
  if (!ctx) return;

  if (riskChartInstance) riskChartInstance.destroy();

  riskChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [riskDist.CRITICAL || 0, riskDist.HIGH || 0, riskDist.MEDIUM || 0, riskDist.LOW || 0],
        backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#10b981'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
    }
  });
}

async function loadRecentScans() {
  const tbody = document.getElementById("recentScansTbody");
  if (!tbody) return;

  try {
    const res = await fetch(`${API_BASE_URL}/api/history?limit=5`);
    const data = await res.json();

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-secondary)">No scans in database. Perform a scan to view history!</td></tr>`;
      return;
    }

    tbody.innerHTML = data.items.map(item => `
      <tr>
        <td style="font-family:var(--font-mono); font-weight:600">${item.scan_id}</td>
        <td><span class="badge" style="background:rgba(255,255,255,0.05); color:var(--text-primary)">${item.input_type}</span></td>
        <td>${escapeHtml(item.content_preview)}</td>
        <td>${getBadgeHtml(item.risk_level)}</td>
        <td style="font-weight:700; color:${getScoreColor(item.risk_score)}">${item.risk_score} / 100</td>
        <td>
          <button class="btn-secondary" style="padding:0.35rem 0.65rem; font-size:0.75rem" onclick="viewCaseDetail('${item.scan_id}')">Inspect</button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Error loading recent scans:", err);
  }
}

// 2. Run Message Scan
async function runMessageScan() {
  const textInput = document.getElementById("messageTextInput").value;
  if (!textInput.trim()) {
    alert("Please enter or paste message text to analyze.");
    return;
  }

  const btn = document.getElementById("btnScanMessage");
  btn.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Analyzing...`;
  btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: textInput })
    });

    const data = await res.json();
    renderAnalysisResult("messageResultContainer", data);
  } catch (err) {
    alert("API Server offline or error analyzing message. Ensure FastAPI backend is running.");
  } finally {
    btn.innerHTML = `<i data-lucide="shield-search"></i> Run AI Analysis`;
    btn.disabled = false;
    if (window.lucide) lucide.createIcons();
  }
}

// 3. Run URL Scan
async function runUrlScan() {
  const urlInput = document.getElementById("urlInput").value;
  if (!urlInput.trim()) {
    alert("Please enter a URL to analyze.");
    return;
  }

  const btn = document.getElementById("btnScanUrl");
  btn.innerHTML = `Analyzing...`;
  btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE_URL}/api/analyze-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlInput })
    });

    const data = await res.json();
    renderAnalysisResult("urlResultContainer", data);
  } catch (err) {
    alert("API Server error analyzing URL.");
  } finally {
    btn.innerHTML = `<i data-lucide="search"></i> Analyze URL`;
    btn.disabled = false;
    if (window.lucide) lucide.createIcons();
  }
}

// Render Result Container
function renderAnalysisResult(containerId, data) {
  const container = document.getElementById(containerId);
  container.style.display = "block";

  const reasonsList = data.reasons.length > 0 
    ? data.reasons.map(r => `<li style="margin-bottom:0.4rem; color:var(--text-primary)"><i data-lucide="alert-circle" style="width:14px; height:14px; color:var(--status-critical); vertical-align:middle; margin-right:4px"></i> ${r}</li>`).join("")
    : `<li style="color:var(--status-low)">No explicit phishing triggers detected in structure or language.</li>`;

  const urlsList = data.urls_found && data.urls_found.length > 0
    ? data.urls_found.map(u => `<div style="font-family:var(--font-mono); font-size:0.85rem; background:var(--bg-surface); padding:0.5rem; border-radius:6px; margin-bottom:0.4rem; word-break:break-all">${u}</div>`).join("")
    : `<div style="color:var(--text-muted); font-size:0.85rem">No URLs detected in message body.</div>`;

  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:1.5rem; padding-bottom:1rem; border-bottom:1px solid var(--border-color)">
      <div>
        <div style="display:flex; align-items:center; gap:0.75rem; margin-bottom:0.35rem">
          <span style="font-family:var(--font-mono); font-weight:700; color:var(--accent-cyan)">Case #${data.scan_id}</span>
          ${getBadgeHtml(data.risk_level)}
        </div>
        <div style="font-size:0.8rem; color:var(--text-secondary)">Analysis Engine: <strong>${data.analysis_type}</strong></div>
      </div>
      <div style="text-align:right">
        <div style="font-size:2.2rem; font-weight:800; color:${getScoreColor(data.risk_score)}; line-height:1">${data.risk_score}</div>
        <div style="font-size:0.75rem; color:var(--text-secondary)">Risk Index / 100</div>
      </div>
    </div>

    <div style="margin-bottom:1.5rem">
      <h4 style="font-size:0.95rem; margin-bottom:0.5rem; color:var(--accent-cyan)">Safety Recommendation</h4>
      <div style="background:rgba(255,255,255,0.03); border-left:4px solid ${getScoreColor(data.risk_score)}; padding:0.85rem 1rem; border-radius:4px; font-size:0.9rem">
        ${data.recommendation}
      </div>
    </div>

    <div style="display:grid; grid-template-columns:1fr 1fr; gap:1.5rem; margin-bottom:1rem">
      <div>
        <h4 style="font-size:0.95rem; margin-bottom:0.5rem">Evidence & Key Risk Reasons</h4>
        <ul style="list-style:none; font-size:0.9rem">
          ${reasonsList}
        </ul>
      </div>
      <div>
        <h4 style="font-size:0.95rem; margin-bottom:0.5rem">Extracted Destination URLs</h4>
        ${urlsList}
      </div>
    </div>

    <div style="font-size:0.75rem; color:var(--text-muted); padding-top:0.75rem; border-top:1px solid var(--border-color)">
      📌 <em>Analysis Disclaimer: A low risk score is not an absolute guarantee of safety. ThreatGuard AI uses structural heuristics and trained ML patterns; always exercise personal vigilance with unsolicited links.</em>
    </div>
  `;
}

// 4. History Page Search & Filter
async function loadHistoryData() {
  const tbody = document.getElementById("historyTbody");
  const searchVal = document.getElementById("historySearch")?.value || "";
  const riskVal = document.getElementById("historyRiskFilter")?.value || "";

  try {
    const res = await fetch(`${API_BASE_URL}/api/history?search=${encodeURIComponent(searchVal)}&risk_level=${riskVal}`);
    const data = await res.json();

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-secondary)">No matching scan records found.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.items.map(item => `
      <tr>
        <td style="font-family:var(--font-mono); font-weight:600">${item.scan_id}</td>
        <td><span class="badge" style="background:rgba(255,255,255,0.05); color:var(--text-primary)">${item.input_type}</span></td>
        <td>${escapeHtml(item.content_preview)}</td>
        <td>${getBadgeHtml(item.risk_level)}</td>
        <td style="font-weight:700; color:${getScoreColor(item.risk_score)}">${item.risk_score}</td>
        <td style="font-size:0.8rem; color:var(--text-secondary)">${new Date(item.created_at).toLocaleString()}</td>
        <td>
          <button class="btn-secondary" style="padding:0.3rem 0.5rem; font-size:0.75rem" onclick="viewCaseDetail('${item.scan_id}')">View</button>
          <button class="btn-secondary" style="padding:0.3rem 0.5rem; font-size:0.75rem; color:var(--status-critical)" onclick="deleteCase('${item.scan_id}')">Delete</button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Error loading history:", err);
  }
}

// Case Details Modal
async function viewCaseDetail(caseId) {
  try {
    const res = await fetch(`${API_BASE_URL}/api/history/${caseId}`);
    const data = await res.json();

    const modalBody = document.getElementById("modalBody");
    modalBody.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem">
        <h3 style="font-size:1.2rem; font-family:var(--font-mono)">Case File: ${data.scan_id}</h3>
        ${getBadgeHtml(data.risk_level)}
      </div>
      <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem">Scanned on ${new Date(data.created_at).toLocaleString()}</div>

      <div style="margin-bottom:1rem">
        <strong>Content Preview:</strong>
        <div style="background:var(--bg-surface); padding:0.75rem; border-radius:6px; margin-top:0.35rem; font-family:var(--font-mono); font-size:0.85rem">${escapeHtml(data.content_preview)}</div>
      </div>

      <div style="margin-bottom:1rem">
        <strong>Detected Risk Score:</strong> <span style="font-weight:800; color:${getScoreColor(data.risk_score)}">${data.risk_score} / 100</span>
      </div>

      <div style="margin-bottom:1rem">
        <strong>Identified Threat Factors:</strong>
        <ul style="margin-left:1.25rem; margin-top:0.35rem; font-size:0.9rem">
          ${data.reasons.map(r => `<li>${r}</li>`).join("") || '<li>None</li>'}
        </ul>
      </div>

      <div>
        <strong>Recommendation:</strong>
        <p style="margin-top:0.35rem; font-size:0.9rem; color:var(--text-secondary)">${data.recommendation}</p>
      </div>
    `;

    document.getElementById("detailModal").classList.add("active");
  } catch (err) {
    alert("Error fetching case details.");
  }
}

function closeModal() {
  document.getElementById("detailModal").classList.remove("active");
}

async function deleteCase(caseId) {
  if (!confirm(`Are you sure you want to delete case ${caseId}?`)) return;

  try {
    const res = await fetch(`${API_BASE_URL}/api/history/${caseId}`, { method: "DELETE" });
    if (res.ok) {
      loadHistoryData();
      loadDashboardData();
    }
  } catch (err) {
    alert("Could not delete case.");
  }
}

// Samples Pre-loader
function loadSampleMessage(type) {
  const input = document.getElementById("messageTextInput");
  if (type === 'phishing') {
    input.value = "URGENT NOTICE: Your bank account has been flagged for suspicious transactions. Verify your account credentials and enter your OTP immediately to prevent deactivation: http://paypa1-security-update.xyz/login.php";
  } else if (type === 'lottery') {
    input.value = "CONGRATULATIONS! You have been randomly selected to win $50,000 cash prize in our annual lottery draw. Click http://claim-reward.top/win to claim your funds before they expire!";
  } else if (type === 'legit') {
    input.value = "Hi Team, please find attached the meeting notes from today's sprint review session. Let me know if you have any feedback on the design mockups!";
  }
}

// Helpers
function getBadgeHtml(level) {
  const lvl = level ? level.toLowerCase() : 'low';
  return `<span class="badge badge-${lvl}">${level}</span>`;
}

function getScoreColor(score) {
  if (score >= 75) return 'var(--status-critical)';
  if (score >= 50) return 'var(--status-high)';
  if (score >= 25) return 'var(--status-medium)';
  return 'var(--status-low)';
}

function escapeHtml(text) {
  if (!text) return '';
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
