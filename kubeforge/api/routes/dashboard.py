"""Dashboard route — serves the main UI."""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KubeForge — Security Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg:        #EEF6FA;
  --bg2:       #FFFFFF;
  --bg3:       #F0F9FF;
  --bg4:       #E0F2FE;
  --teal:      #0D9488;
  --teal-dim:  rgba(13,148,136,0.1);
  --teal-glow: rgba(13,148,136,0.2);
  --green:     #059669;
  --green-dim: rgba(5,150,105,0.1);
  --sky:       #0284C7;
  --red:       #E11D48;
  --orange:    #EA580C;
  --yellow:    #D97706;
  --blue:      #2563EB;
  --text:      #0D4A3E;
  --text2:     #0F5C4A;
  --muted:     #3D7A6A;
  --border:    rgba(13,148,136,0.15);
  --border2:   rgba(13,148,136,0.25);
  --shadow:    0 4px 20px rgba(13,148,136,0.12);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Inter', sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}

::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--bg4); border-radius: 3px; }

/* ── NAV ── */
nav {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 28px; height: 60px;
  background: rgba(255,255,255,0.85);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 100;
  box-shadow: 0 1px 12px rgba(13,148,136,0.08);
}
.nav-logo { display: flex; align-items: center; gap: 11px; }
.logo-text { font-size: 1em; font-weight: 800; letter-spacing: 3px; color: var(--text); }
.logo-text span { color: var(--teal); }
.nav-right { display: flex; align-items: center; gap: 12px; }
.version-badge {
  font-size: 0.7em; color: var(--muted);
  background: var(--bg3); padding: 4px 11px; border-radius: 20px;
  border: 1px solid var(--border);
}
.status-pill {
  display: flex; align-items: center; gap: 7px;
  background: rgba(45,212,191,0.08);
  border: 1px solid var(--border2);
  color: var(--teal); padding: 5px 15px; border-radius: 20px;
  font-size: 0.74em; font-weight: 600; letter-spacing: 0.5px;
}
.status-dot {
  width: 6px; height: 6px; background: var(--teal);
  border-radius: 50%; animation: pulse 2s ease-in-out infinite;
  box-shadow: 0 0 6px var(--teal);
}
@keyframes pulse { 0%,100%{opacity:1;box-shadow:0 0 6px var(--teal)} 50%{opacity:0.5;box-shadow:0 0 2px var(--teal)} }

/* ── LAYOUT ── */
.layout { display: grid; grid-template-columns: 210px 1fr; min-height: calc(100vh - 60px); }

/* ── SIDEBAR ── */
aside {
  background: linear-gradient(180deg, #FFFFFF 0%, #F0F9FF 100%);
  border-right: 1px solid var(--border);
  padding: 20px 0;
  box-shadow: 2px 0 12px rgba(13,148,136,0.05);
}
.sidebar-section { margin-bottom: 6px; }
.sidebar-label {
  font-size: 0.63em; font-weight: 700; color: var(--muted);
  letter-spacing: 2.5px; text-transform: uppercase;
  padding: 12px 18px 6px;
}
.sidebar-item {
  display: flex; align-items: center;
  padding: 8px 14px; cursor: pointer; font-size: 0.82em;
  color: var(--text2); border: 1px solid transparent;
  transition: all 0.18s; margin: 2px 10px; border-radius: 8px;
  font-weight: 500;
}
.sidebar-item:hover {
  color: var(--teal);
  background: #ECFDF5;
  border-color: #60A5C8;
  box-shadow: 0 2px 8px rgba(96,165,200,0.15);
}
.sidebar-item.active {
  color: var(--teal);
  background: #ECFDF5;
  border-color: #60A5C8;
  font-weight: 700;
  box-shadow: 0 2px 8px rgba(96,165,200,0.2);
}

/* ── MAIN ── */
main { padding: 26px 30px; overflow-y: auto; }
.screen { display: none; }
.screen.active { display: block; }

/* ── STATS GRID ── */
.stats-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 14px; margin-bottom: 18px; }
.stat-card {
  background: linear-gradient(135deg, #F0FDF8 0%, #ECFDF5 100%);
  border: 1.5px solid #60A5C8;
  border-radius: 16px; padding: 20px 22px;
  position: relative; overflow: hidden;
  transition: transform 0.2s, box-shadow 0.2s;
}
.stat-card::after {
  content: ''; position: absolute;
  top: -40px; right: -40px;
  width: 100px; height: 100px; border-radius: 50%;
  opacity: 0.06;
}
.stat-card.critical::after { background: var(--red); }
.stat-card.high::after     { background: var(--orange); }
.stat-card.medium::after   { background: var(--yellow); }
.stat-card.safe::after     { background: var(--teal); }
.stat-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  border-radius: 16px 16px 0 0;
}
.stat-card.critical::before { background: linear-gradient(90deg, var(--red), transparent); }
.stat-card.high::before     { background: linear-gradient(90deg, var(--orange), transparent); }
.stat-card.medium::before   { background: linear-gradient(90deg, var(--yellow), transparent); }
.stat-card.safe::before     { background: linear-gradient(90deg, var(--teal), transparent); }
.stat-card:hover { transform: translateY(-3px); box-shadow: 0 12px 40px rgba(0,0,0,0.4); }
.stat-label {
  font-size: 0.68em; color: var(--muted); font-weight: 600;
  letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 10px;
}
.stat-value { font-size: 2.4em; font-weight: 800; line-height: 1; }
.stat-card.critical .stat-value { color: var(--red); }
.stat-card.high .stat-value     { color: var(--orange); }
.stat-card.medium .stat-value   { color: var(--yellow); }
.stat-card.safe .stat-value     { color: var(--teal); }
.stat-sub { font-size: 0.7em; color: var(--muted); margin-top: 7px; }

/* ── RISK SCORE ── */
#riskScoreBar {
  display: none;
  background: linear-gradient(135deg, #F0FDF8, #ECFDF5);
  border: 1.5px solid #60A5C8; border-radius: 16px;
  padding: 18px 24px; margin-bottom: 18px;
  align-items: center; gap: 24px;
}
.risk-title { font-size: 0.68em; color: var(--muted); font-weight: 700;
  text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 5px; }
.risk-label-text { font-size: 0.82em; color: var(--text2); }
.risk-number { font-size: 2.8em; font-weight: 800; min-width: 78px; text-align: center; }
.risk-track { flex: 1; height: 7px; background: var(--bg4); border-radius: 4px; overflow: hidden; }
.risk-fill { height: 100%; border-radius: 4px; transition: width 1.2s cubic-bezier(.4,0,.2,1); }

/* ── SCAN BAR ── */
.scan-bar {
  background: linear-gradient(135deg, #F0FDF8, #ECFDF5);
  border: 1.5px solid #60A5C8; border-radius: 16px;
  padding: 18px 22px; margin-bottom: 14px;
}
.scan-bar-top {
  display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px;
}
.scan-bar-title { font-size: 0.9em; font-weight: 600; color: var(--text); }
.scan-bar-sub { font-size: 0.74em; color: var(--muted); margin-top: 3px; }
.path-row { display: flex; gap: 8px; }
.path-input {
  flex: 1; background: var(--bg4); border: 1px solid var(--border2);
  border-radius: 10px; padding: 9px 14px;
  color: var(--text2); font-size: 0.81em; font-family: 'Courier New', monospace;
  outline: none; transition: all 0.2s;
}
.path-input:focus { border-color: var(--teal); box-shadow: 0 0 0 3px rgba(45,212,191,0.1); }
.path-input::placeholder { color: var(--muted); }
.paths-list { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 11px; }
.path-tag {
  display: inline-flex; align-items: center; gap: 5px;
  background: rgba(45,212,191,0.08); border: 1px solid var(--border2);
  color: var(--teal); padding: 4px 11px; border-radius: 8px;
  font-size: 0.72em; cursor: pointer; transition: all 0.15s;
}
.path-tag:hover { background: rgba(251,113,133,0.08); border-color: rgba(251,113,133,0.2); color: var(--red); }

/* ── BUTTONS ── */
.btn-scan {
  background: linear-gradient(135deg, #2DD4BF, #34D399);
  color: #0B1623; border: none; padding: 10px 24px; border-radius: 10px;
  font-size: 0.85em; font-weight: 700; cursor: pointer;
  font-family: inherit; display: flex; align-items: center; gap: 8px;
  transition: all 0.25s; white-space: nowrap;
  box-shadow: 0 4px 15px rgba(45,212,191,0.3);
}
.btn-scan:hover {
  background: linear-gradient(135deg, #5EEAD4, #6EE7B7);
  box-shadow: 0 6px 25px rgba(45,212,191,0.45);
  transform: translateY(-1px);
}
.btn-scan:disabled {
  background: var(--bg4); color: var(--muted);
  cursor: not-allowed; box-shadow: none; transform: none;
}
.btn-secondary {
  background: rgba(45,212,191,0.08);
  border: 1px solid var(--border2);
  color: var(--teal); padding: 9px 16px; border-radius: 10px;
  font-size: 0.8em; font-weight: 500; cursor: pointer;
  font-family: inherit; transition: all 0.2s; white-space: nowrap;
}
.btn-secondary:hover {
  background: rgba(45,212,191,0.15);
  border-color: var(--teal);
  box-shadow: 0 4px 12px rgba(45,212,191,0.15);
}
.spinner {
  width: 13px; height: 13px;
  border: 2px solid rgba(11,22,35,0.3); border-top-color: #0B1623;
  border-radius: 50%; animation: spin 0.7s linear infinite; display: none;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ── PROGRESS ── */
.progress-wrap { margin-bottom: 18px; display: none; }
.progress-label { font-size: 0.76em; color: var(--muted); margin-bottom: 8px; }
.progress-bar { height: 3px; background: var(--bg4); border-radius: 2px; overflow: hidden; }
.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--teal), var(--green), var(--sky));
  background-size: 200% 100%;
  border-radius: 2px;
  animation: progressAnim 1.8s ease-in-out infinite;
}
@keyframes progressAnim { 0%{width:5%;background-position:0%} 50%{width:80%;background-position:100%} 100%{width:95%;background-position:0%} }

/* ── EXPORT BAR ── */
#exportBar {
  display: none; gap: 8px; margin-bottom: 16px; align-items: center;
  padding: 10px 16px; background: #F0FDF8; border: 1.5px solid #60A5C8;
  border-radius: 12px;
}
#exportBar span { font-size: 0.76em; color: var(--muted); }

/* ── SECTION HEADER ── */
.section-header {
  display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px;
}
.section-title { font-size: 0.88em; font-weight: 700; display: flex; align-items: center; gap: 7px; color: var(--text2); }
.badge {
  background: var(--bg3); border: 1px solid var(--border2);
  padding: 2px 9px; border-radius: 10px; font-size: 0.72em; color: var(--teal);
}

/* ── THREAT CARDS ── */
.threats-list { display: flex; flex-direction: column; gap: 10px; }
.threat-card {
  background: linear-gradient(135deg, #F0FDF8, #ECFDF5);
  border: 1.5px solid #60A5C8;
  border-radius: 13px; padding: 15px 19px;
  border-left: 3px solid transparent;
  transition: all 0.2s; cursor: pointer;
}
.threat-card:hover {
  transform: translateX(4px);
  border-color: var(--border2);
  box-shadow: 0 6px 24px rgba(0,0,0,0.35);
}
.threat-card.critical { border-left-color: var(--red); }
.threat-card.high     { border-left-color: var(--orange); }
.threat-card.medium   { border-left-color: var(--yellow); }
.threat-card.low      { border-left-color: var(--sky); }
.threat-card.info     { border-left-color: var(--muted); }

.threat-header { display: flex; align-items: center; gap: 9px; margin-bottom: 8px; }
.severity-badge {
  font-size: 0.63em; font-weight: 700; letter-spacing: 1px;
  padding: 3px 9px; border-radius: 6px; text-transform: uppercase;
}
.severity-badge.critical { background: rgba(251,113,133,0.12); color: var(--red); border: 1px solid rgba(251,113,133,0.2); }
.severity-badge.high     { background: rgba(251,146,60,0.12);  color: var(--orange); border: 1px solid rgba(251,146,60,0.2); }
.severity-badge.medium   { background: rgba(252,211,77,0.12);  color: var(--yellow); border: 1px solid rgba(252,211,77,0.2); }
.severity-badge.low      { background: rgba(56,189,248,0.12);  color: var(--sky); border: 1px solid rgba(56,189,248,0.2); }
.severity-badge.info     { background: rgba(94,143,175,0.12);  color: var(--muted); border: 1px solid rgba(94,143,175,0.2); }

.threat-title { font-size: 0.87em; font-weight: 600; color: var(--text); }
.threat-location {
  font-size: 0.71em; color: var(--muted); margin-bottom: 8px;
  font-family: 'Courier New', monospace;
}
.threat-evidence {
  background: #ECFDF5; border: 1px solid rgba(13,148,136,0.15);
  border-radius: 8px; padding: 8px 12px;
  font-family: 'Courier New', monospace; font-size: 0.75em;
  color: var(--muted); word-break: break-all;
}
.threat-ai {
  margin-top: 10px; padding: 11px 15px;
  background: rgba(45,212,191,0.05);
  border: 1px solid rgba(45,212,191,0.12);
  border-radius: 10px; font-size: 0.8em; color: var(--text2); line-height: 1.7;
  display: none;
}
.threat-ai.visible { display: block; }
.threat-ai-label {
  font-size: 0.7em; font-weight: 700; color: var(--teal);
  text-transform: uppercase; letter-spacing: 1.2px; margin-bottom: 7px;
}
.threat-rec { margin-top: 8px; font-size: 0.78em; color: var(--muted); }
.risk-score-badge {
  margin-left: auto;
  background: rgba(45,212,191,0.1); border: 1px solid var(--border2);
  color: var(--teal); font-size: 0.68em; font-weight: 700;
  padding: 3px 9px; border-radius: 6px;
}

/* ── EMPTY STATE ── */
.empty-state { text-align: center; padding: 56px 20px; color: var(--muted); }
.empty-state .icon { font-size: 2.6em; margin-bottom: 14px; opacity: 0.4; }
.empty-state p { font-size: 0.84em; line-height: 1.8; }
.empty-state strong { color: var(--teal); }

/* ── HISTORY TABLE ── */
.history-table { width: 100%; border-collapse: collapse; }
.history-table th {
  text-align: left; font-size: 0.67em; font-weight: 700; color: var(--muted);
  text-transform: uppercase; letter-spacing: 1.5px;
  padding: 10px 14px; border-bottom: 1px solid var(--border);
}
.history-table td {
  padding: 13px 14px; border-bottom: 1px solid var(--border);
  font-size: 0.82em; vertical-align: middle; color: var(--text2);
}
.history-table tr:hover td { background: rgba(45,212,191,0.03); cursor: pointer; }
.history-table tr.selected td { background: rgba(45,212,191,0.06); }
.sev-pills { display: flex; gap: 5px; flex-wrap: wrap; }
.sev-pill {
  font-size: 0.67em; font-weight: 700; padding: 2px 7px; border-radius: 5px;
}
.sev-pill.critical { background: rgba(251,113,133,0.12); color: var(--red); }
.sev-pill.high     { background: rgba(251,146,60,0.12);  color: var(--orange); }
.sev-pill.medium   { background: rgba(252,211,77,0.12);  color: var(--yellow); }
.sev-pill.low      { background: rgba(56,189,248,0.12);  color: var(--sky); }
.scanner-badge {
  font-size: 0.7em; padding: 3px 9px; border-radius: 6px; font-weight: 600;
  background: var(--bg3); border: 1px solid var(--border);
}
.scanner-badge.multi_scanner { border-color: var(--border2); color: var(--teal); }
.scanner-badge.data_scanner  { border-color: rgba(96,165,250,0.2); color: var(--blue); }
.scanner-badge.k8s_scanner   { border-color: rgba(52,211,153,0.2); color: var(--green); }

/* ── TOAST ── */
.toast {
  position: fixed; bottom: 22px; right: 22px; z-index: 999;
  background: #FFFFFF; border: 1px solid var(--border2);
  border-radius: 13px; padding: 13px 18px;
  font-size: 0.81em; max-width: 300px;
  transform: translateY(80px); opacity: 0;
  transition: all 0.3s cubic-bezier(.4,0,.2,1);
  box-shadow: 0 8px 32px rgba(0,0,0,0.5);
}
.toast.show { transform: translateY(0); opacity: 1; }
.toast.success { border-left: 3px solid var(--teal); }
.toast.error   { border-left: 3px solid var(--red); }
</style>
</head>
<body>

<nav>
  <div class="nav-logo">
    <svg width="28" height="28" viewBox="0 0 64 64">
      <polygon points="32,4 52,15 52,37 32,48 12,37 12,15" fill="none" stroke="#2DD4BF" stroke-width="2"/>
      <polygon points="32,10 47,19 47,35 32,44 17,35 17,19" fill="#112033"/>
      <text x="32" y="38" text-anchor="middle" font-family="Inter,sans-serif" font-size="19" font-weight="800" fill="#2DD4BF">K</text>
    </svg>
    <span class="logo-text">KUBE<span>FORGE</span></span>
  </div>
  <div class="nav-right">
    <span class="version-badge" id="versionLabel">v0.1.0</span>
    <div class="status-pill"><div class="status-dot"></div><span id="statusText">System Online</span></div>
  </div>
</nav>

<div class="layout">
  <aside>
    <div class="sidebar-section">
      <div class="sidebar-label">Main</div>
      <div class="sidebar-item active" onclick="showScreen('dashboard',this)">Dashboard</div>
      <div class="sidebar-item" onclick="showScreen('history',this)">Scan History</div>
      <div class="sidebar-item" onclick="showScreen('threats',this)">Threats</div>
    </div>
    <div class="sidebar-section" style="margin-top:8px;">
      <div class="sidebar-label">Scanners</div>
      <div class="sidebar-item">Data & Secrets</div>
      <div class="sidebar-item">Kubernetes</div>
      <div class="sidebar-item">Docker</div>
      <div class="sidebar-item">Dependencies</div>
    </div>
    <div class="sidebar-section" style="margin-top:8px;">
      <div class="sidebar-label">Settings</div>
      <div class="sidebar-item" onclick="showScreen('settings',this);loadSettings()">Config & Alerts</div>
    </div>
  </aside>

  <main>

    <!-- DASHBOARD -->
    <div id="screen-dashboard" class="screen active">

      <div class="stats-grid">
        <div class="stat-card critical">
          <div class="stat-label">Critical</div>
          <div class="stat-value" id="countCritical">—</div>
          <div class="stat-sub">Immediate action</div>
        </div>
        <div class="stat-card high">
          <div class="stat-label">High</div>
          <div class="stat-value" id="countHigh">—</div>
          <div class="stat-sub">Within 24h</div>
        </div>
        <div class="stat-card medium">
          <div class="stat-label">Medium</div>
          <div class="stat-value" id="countMedium">—</div>
          <div class="stat-sub">Review this week</div>
        </div>
        <div class="stat-card safe">
          <div class="stat-label">Files Scanned</div>
          <div class="stat-value" id="countFiles">—</div>
          <div class="stat-sub" id="scanDuration">Run a scan</div>
        </div>
      </div>

      <div id="riskScoreBar">
        <div style="flex:1;">
          <div class="risk-title">Overall Risk Score</div>
          <div class="risk-label-text" id="riskLabel">—</div>
        </div>
        <div class="risk-number" id="riskValue">—</div>
        <div class="risk-track"><div class="risk-fill" id="riskBar"></div></div>
      </div>

      <div class="scan-bar">
        <div class="scan-bar-top">
          <div>
            <div class="scan-bar-title">🔍 Security Scanner</div>
            <div class="scan-bar-sub" id="lastScanText">No scan has been run yet</div>
          </div>
          <button class="btn-scan" id="scanBtn" onclick="triggerScan()">
            <span class="spinner" id="scanSpinner"></span>
            <span id="scanBtnText">▶ Run Scan</span>
          </button>
        </div>
        <div class="path-row">
          <input class="path-input" id="pathInput" type="text" placeholder="Add path to scan, e.g. /Users/me/projects"/>
          <button class="btn-secondary" onclick="addPath()">+ Add</button>
        </div>
        <div class="paths-list" id="pathsList"></div>
      </div>

      <div id="exportBar">
        <span>Export last scan:</span>
        <button class="btn-secondary" onclick="exportCSV()">⬇ CSV</button>
        <button class="btn-secondary" onclick="exportReport()">📄 PDF Report</button>
      </div>

      <div class="progress-wrap" id="progressWrap">
        <div class="progress-label">Scanning files...</div>
        <div class="progress-bar"><div class="progress-fill"></div></div>
      </div>

      <!-- GITHUB SCAN -->
      <div class="scan-bar" style="margin-bottom:14px;">
        <div class="scan-bar-top" style="margin-bottom:0;">
          <div>
            <div class="scan-bar-title">GitHub Repository Scanner</div>
            <div class="scan-bar-sub">Scan any public GitHub repo for secrets and misconfigs</div>
          </div>
        </div>
        <div class="path-row" style="margin-top:12px;">
          <input class="path-input" id="githubUrl" type="text" placeholder="https://github.com/owner/repo"/>
          <button class="btn-scan" onclick="scanGitHub()" style="padding:9px 18px;">Scan Repo</button>
        </div>
      </div>

      <div class="section-header">
        <div class="section-title">⚠️ Detected Threats <span class="badge" id="threatCount">0</span></div>
        <div style="display:flex;gap:8px;align-items:center;">
          <input id="searchInput" oninput="renderThreatsFiltered()" type="text"
            class="path-input" style="width:180px;padding:6px 11px;font-family:inherit;"
            placeholder="Search threats..."/>
          <select id="filterSev" onchange="renderThreatsFiltered()"
            style="background:var(--bg4);border:1.5px solid #60A5C8;border-radius:8px;
            color:var(--text);padding:6px 10px;font-family:inherit;font-size:0.8em;cursor:pointer;">
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>
      <div id="threatsContainer">
        <div class="empty-state">
          <div class="icon">🛡️</div>
          <p>No threats detected yet.<br>Add a path and click <strong>Run Scan</strong>.</p>
        </div>
      </div>
    </div>

    <!-- HISTORY -->
    <div id="screen-history" class="screen">
      <div class="section-header" style="margin-bottom:18px;">
        <div class="section-title">📋 Scan History</div>
        <button class="btn-secondary" onclick="loadHistory()">↻ Refresh</button>
      </div>
      <div id="historyContainer">
        <div class="empty-state"><div class="icon">📋</div><p>Loading...</p></div>
      </div>
      <div id="historyDetail" style="display:none;margin-top:22px;">
        <div class="section-header">
          <div class="section-title">⚠️ Threats — <span id="detailScanId" style="font-family:monospace;font-size:0.85em;color:var(--muted);"></span></div>
        </div>
        <div id="historyThreats"></div>
      </div>
    </div>

    <!-- THREATS -->
    <div id="screen-threats" class="screen">
      <div class="section-header" style="margin-bottom:18px;">
        <div class="section-title">⚠️ All Threats — Latest Scan</div>
      </div>
      <div id="allThreatsContainer">
        <div class="empty-state"><div class="icon">⚠️</div><p>Run a scan first.</p></div>
      </div>
    </div>

    <!-- SETTINGS -->
    <div id="screen-settings" class="screen">
      <div class="section-header" style="margin-bottom:20px;">
        <div class="section-title">⚙️ Settings</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:14px;max-width:560px;">

        <div class="scan-bar">
          <div class="scan-bar-title" style="margin-bottom:12px;">Auto-Scan Interval</div>
          <div class="path-row">
            <select id="settingInterval" class="path-input" style="font-family:inherit;">
              <option value="900">Every 15 minutes</option>
              <option value="1800">Every 30 minutes</option>
              <option value="3600" selected>Every 1 hour</option>
              <option value="21600">Every 6 hours</option>
              <option value="86400">Every 24 hours</option>
            </select>
          </div>
        </div>

        <div class="scan-bar">
          <div class="scan-bar-title" style="margin-bottom:4px;">Slack Webhook URL</div>
          <div class="scan-bar-sub" style="margin-bottom:12px;">Receive alerts when critical threats are found</div>
          <input id="settingSlack" class="path-input" type="text" placeholder="https://hooks.slack.com/services/..."/>
        </div>

        <div class="scan-bar">
          <div class="scan-bar-title" style="margin-bottom:4px;">GitHub Token</div>
          <div class="scan-bar-sub" style="margin-bottom:12px;">For scanning private repositories</div>
          <input id="settingGithubToken" class="path-input" type="password" placeholder="ghp_..."/>
        </div>

        <div class="scan-bar">
          <div class="scan-bar-title" style="margin-bottom:4px;">Network Scan Hosts</div>
          <div class="scan-bar-sub" style="margin-bottom:12px;">Comma-separated hosts to scan for open ports</div>
          <input id="settingHosts" class="path-input" type="text" placeholder="localhost, 10.0.0.1, myserver.com"/>
        </div>

        <button class="btn-scan" onclick="saveSettings()" style="align-self:flex-start;">
          💾 Save Settings
        </button>
      </div>
    </div>

  </main>
</div>

<div class="toast" id="toast"></div>

<script>
const API = '';
let scanPollingInterval = null;
let scanPaths = [];

function showScreen(name, el) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.sidebar-item').forEach(s => s.classList.remove('active'));
  document.getElementById('screen-' + name).classList.add('active');
  if (el) el.classList.add('active');
  if (name === 'history') loadHistory();
  if (name === 'threats') loadAllThreats();
}

function addPath() {
  const input = document.getElementById('pathInput');
  const val = input.value.trim();
  if (!val || scanPaths.includes(val)) return;
  scanPaths.push(val);
  renderPaths();
  input.value = '';
}
document.getElementById('pathInput').addEventListener('keydown', e => { if (e.key==='Enter') addPath(); });
function removePath(path) { scanPaths = scanPaths.filter(p => p !== path); renderPaths(); }
function renderPaths() {
  document.getElementById('pathsList').innerHTML = scanPaths.map(p =>
    `<span class="path-tag" onclick="removePath('${escHtml(p)}')" title="Remove">📁 ${escHtml(p)} ×</span>`
  ).join('');
}

async function init() {
  try {
    const data = await (await fetch(`${API}/health`)).json();
    document.getElementById('versionLabel').textContent = `v${data.version}`;
  } catch(e) { document.getElementById('statusText').textContent = 'Offline'; }
  loadLatestScan();
}

async function triggerScan() {
  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  document.getElementById('scanSpinner').style.display = 'block';
  document.getElementById('scanBtnText').textContent = 'Scanning...';
  document.getElementById('progressWrap').style.display = 'block';
  document.getElementById('lastScanText').textContent = 'Scan in progress...';
  const body = { enrich_with_ai: true };
  if (scanPaths.length) body.paths = scanPaths;
  try {
    await fetch(`${API}/api/v1/scan`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
    showToast('Scan started...', 'success');
    scanPollingInterval = setInterval(pollScanResult, 1500);
  } catch(e) { showToast('Failed to start scan', 'error'); resetScanBtn(); }
}

async function pollScanResult() {
  try {
    const res = await fetch(`${API}/api/v1/scan/latest`);
    if (!res.ok) return;
    const summary = await res.json();
    const age = (Date.now() - new Date(summary.finished_at + 'Z').getTime()) / 1000;
    if (age < 10) { clearInterval(scanPollingInterval); await renderResults(summary); resetScanBtn(); }
  } catch(e) {}
}

async function loadLatestScan() {
  try {
    const res = await fetch(`${API}/api/v1/scan/latest`);
    if (!res.ok) return;
    await renderResults(await res.json());
  } catch(e) {}
}

async function renderResults(summary) {
  const sev = summary.threats_by_severity || {};
  document.getElementById('countCritical').textContent = sev.critical || 0;
  document.getElementById('countHigh').textContent     = sev.high     || 0;
  document.getElementById('countMedium').textContent   = sev.medium   || 0;
  document.getElementById('countFiles').textContent    = summary.total_files_scanned;
  document.getElementById('scanDuration').textContent  = `Took ${summary.duration_seconds}s`;
  document.getElementById('threatCount').textContent   = summary.total_threats_found;
  const dt = new Date(summary.finished_at + 'Z');
  document.getElementById('lastScanText').textContent = `Last scan: ${dt.toLocaleTimeString()} — ${summary.total_threats_found} threats`;
  document.getElementById('scanMeta').textContent = `${summary.scan_id.slice(0,8)}...  ·  ${summary.total_files_scanned} files`;

  const raw = (sev.critical||0)*10 + (sev.high||0)*5 + (sev.medium||0)*2 + (sev.low||0);
  const score = Math.min(100, raw);
  const color = score>=60 ? 'var(--red)' : score>=30 ? 'var(--orange)' : score>=10 ? 'var(--yellow)' : 'var(--teal)';
  const label = score>=60 ? 'High Risk — Immediate attention required'
              : score>=30 ? 'Medium Risk — Review findings soon'
              : score>=10 ? 'Low Risk — Monitor regularly'
              : 'Minimal Risk — Environment looks clean ✓';
  const bar = document.getElementById('riskScoreBar');
  bar.style.display = 'flex';
  document.getElementById('riskValue').textContent = score;
  document.getElementById('riskValue').style.color = color;
  document.getElementById('riskBar').style.width = score + '%';
  document.getElementById('riskBar').style.background = color;
  document.getElementById('riskLabel').textContent = label;

  window._currentScanId = summary.scan_id;
  document.getElementById('exportBar').style.display = 'flex';

  const tData = await (await fetch(`${API}/api/v1/scan/latest/threats`)).json();
  _allThreats = tData.threats || [];
  renderThreats(_allThreats, 'threatsContainer');
  document.getElementById('progressWrap').style.display = 'none';
  showToast(`Scan complete — ${summary.total_threats_found} threats found`, 'success');

  // Browser notification for critical threats
  const critCount = sev.critical || 0;
  if (critCount > 0) {
    sendNotification('KubeForge — Critical Threats Found',
      `${critCount} critical threat${critCount>1?'s':''} detected! Open dashboard to review.`);
  }
}

async function loadHistory() {
  document.getElementById('historyContainer').innerHTML = '<div class="empty-state"><div class="icon">⏳</div><p>Loading...</p></div>';
  document.getElementById('historyDetail').style.display = 'none';
  try {
    const data = await (await fetch(`${API}/api/v1/scans`)).json();
    renderHistory(data.scans || []);
  } catch(e) {
    document.getElementById('historyContainer').innerHTML = '<div class="empty-state"><div class="icon">📋</div><p>No scan history yet.</p></div>';
  }
}

function renderHistory(scans) {
  if (!scans.length) {
    document.getElementById('historyContainer').innerHTML = '<div class="empty-state"><div class="icon">📋</div><p>No scans yet.</p></div>';
    return;
  }
  const rows = scans.map(s => {
    const sev = s.threats_by_severity || {};
    const pills = ['critical','high','medium','low'].filter(k=>sev[k])
      .map(k=>`<span class="sev-pill ${k}">${k[0].toUpperCase()} ${sev[k]}</span>`).join('');
    const dt = new Date(s.finished_at + 'Z').toLocaleString();
    return `<tr onclick="loadHistoryDetail('${s.scan_id}',this)">
      <td style="font-family:monospace;color:var(--muted);font-size:0.77em">${s.scan_id.slice(0,12)}...</td>
      <td>${dt}</td>
      <td><span class="scanner-badge ${s.scanner_name}">${s.scanner_name}</span></td>
      <td>${s.total_files_scanned}</td>
      <td style="font-weight:600;color:var(--text)">${s.total_threats_found}</td>
      <td><div class="sev-pills">${pills||'<span style="color:var(--muted);font-size:0.78em">none</span>'}</div></td>
      <td style="color:var(--muted);font-size:0.78em">${s.duration_seconds}s</td>
    </tr>`;
  }).join('');
  document.getElementById('historyContainer').innerHTML = `
    <table class="history-table">
      <thead><tr><th>Scan ID</th><th>Date</th><th>Scanner</th><th>Files</th><th>Threats</th><th>By Severity</th><th>Duration</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

async function loadHistoryDetail(scanId, row) {
  document.querySelectorAll('.history-table tr').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  document.getElementById('detailScanId').textContent = scanId.slice(0,12) + '...';
  document.getElementById('historyDetail').style.display = 'block';
  const container = document.getElementById('historyThreats');
  container.innerHTML = '<div class="empty-state"><div class="icon">⏳</div><p>Loading...</p></div>';
  try {
    const data = await (await fetch(`${API}/api/v1/scans/${scanId}/threats`)).json();
    renderThreats(data.threats || [], 'historyThreats');
  } catch(e) {
    container.innerHTML = '<div class="empty-state"><div class="icon">❌</div><p>Failed to load.</p></div>';
  }
}

async function loadAllThreats() {
  try {
    const data = await (await fetch(`${API}/api/v1/scan/latest/threats`)).json();
    renderThreats(data.threats || [], 'allThreatsContainer');
  } catch(e) {
    document.getElementById('allThreatsContainer').innerHTML = '<div class="empty-state"><div class="icon">⚠️</div><p>Run a scan first.</p></div>';
  }
}

function renderThreats(threats, containerId) {
  const container = document.getElementById(containerId);
  if (!threats.length) {
    container.innerHTML = '<div class="empty-state"><div class="icon">✅</div><p>No threats detected.</p></div>';
    return;
  }
  const order = {critical:0,high:1,medium:2,low:3,info:4};
  threats.sort((a,b) => (order[a.severity]||9)-(order[b.severity]||9));
  container.innerHTML = '<div class="threats-list">' + threats.map(t => threatCard(t)).join('') + '</div>';
}

function threatCard(t) {
  const ai = t.ai_summary ? `
    <div class="threat-ai visible">
      <div class="threat-ai-label">🤖 AI Analysis</div>
      <div>${escHtml(t.ai_summary)}</div>
      ${t.ai_recommendation ? `<div class="threat-rec">💡 ${escHtml(t.ai_recommendation)}</div>` : ''}
    </div>` : '';
  const risk = t.ai_risk_score ? `<span class="risk-score-badge">Risk ${t.ai_risk_score}/10</span>` : '';
  return `<div class="threat-card ${t.severity}" onclick="toggleAI(this)">
    <div class="threat-header">
      <span class="severity-badge ${t.severity}">${t.severity}</span>
      <span class="threat-title">${escHtml(t.title)}</span>
      ${risk}
    </div>
    <div class="threat-location">📍 ${escHtml(t.location)}</div>
    <div class="threat-evidence">${escHtml(t.raw_evidence)}</div>
    ${ai}
  </div>`;
}

function toggleAI(card) { const ai = card.querySelector('.threat-ai'); if(ai) ai.classList.toggle('visible'); }
function resetScanBtn() {
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('scanSpinner').style.display = 'none';
  document.getElementById('scanBtnText').textContent = '▶ Run Scan';
}
function showToast(msg, type='success') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = `toast ${type} show`;
  setTimeout(() => t.classList.remove('show'), 3500);
}
function escHtml(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function exportCSV() { if(window._currentScanId) window.location.href=`/api/v1/scans/${window._currentScanId}/export/csv`; }
function exportReport() { if(window._currentScanId) window.open(`/api/v1/scans/${window._currentScanId}/export/report`,'_blank'); }

// ── BROWSER NOTIFICATIONS ──
async function requestNotifications() {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'default') {
    await Notification.requestPermission();
  }
}
function sendNotification(title, body) {
  if (Notification.permission === 'granted') {
    new Notification(title, { body, icon: '' });
  }
}

// ── SEARCH & FILTER ──
let _allThreats = [];
function renderThreatsFiltered() {
  const q = (document.getElementById('searchInput')?.value || '').toLowerCase();
  const sev = document.getElementById('filterSev')?.value || 'all';
  const filtered = _allThreats.filter(t => {
    const matchSev = sev === 'all' || t.severity === sev;
    const matchQ   = !q || t.title.toLowerCase().includes(q) || t.location.toLowerCase().includes(q);
    return matchSev && matchQ;
  });
  renderThreats(filtered, 'threatsContainer');
  document.getElementById('threatCount').textContent = filtered.length;
}

// ── SCAN GITHUB ──
async function scanGitHub() {
  const url = document.getElementById('githubUrl')?.value?.trim();
  if (!url) { showToast('Enter a GitHub repo URL', 'error'); return; }
  try {
    await fetch(`${API}/api/v1/scan/github`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ repo_url: url, enrich_with_ai: true }),
    });
    showToast('GitHub scan started — cloning repo...', 'success');
    document.getElementById('progressWrap').style.display = 'block';
    scanPollingInterval = setInterval(pollScanResult, 2000);
  } catch(e) { showToast('Failed to start GitHub scan', 'error'); }
}

// ── SETTINGS ──
function saveSettings() {
  const interval = document.getElementById('settingInterval')?.value;
  const slack    = document.getElementById('settingSlack')?.value;
  localStorage.setItem('kf_interval', interval);
  localStorage.setItem('kf_slack', slack);
  showToast('Settings saved locally', 'success');
}
function loadSettings() {
  const interval = localStorage.getItem('kf_interval') || '3600';
  const slack    = localStorage.getItem('kf_slack') || '';
  if (document.getElementById('settingInterval')) document.getElementById('settingInterval').value = interval;
  if (document.getElementById('settingSlack'))    document.getElementById('settingSlack').value = slack;
}

// ── DIFF ──
let _diffScanA = null;
function selectDiffScan(scanId, label) {
  if (!_diffScanA) {
    _diffScanA = scanId;
    showToast(`Scan A selected: ${scanId.slice(0,8)}... — now select Scan B`, 'success');
    document.querySelectorAll('.history-table tr').forEach(r => r.classList.remove('diff-a'));
    event.currentTarget.closest('tr').classList.add('diff-a');
  } else if (_diffScanA !== scanId) {
    runDiff(_diffScanA, scanId);
    _diffScanA = null;
  }
}

async function runDiff(scanA, scanB) {
  try {
    const data = await (await fetch(`${API}/api/v1/scans/${scanA}/diff/${scanB}`)).json();
    const container = document.getElementById('historyThreats');
    document.getElementById('historyDetail').style.display = 'block';
    document.getElementById('detailScanId').textContent = `Diff: ${scanA.slice(0,8)} → ${scanB.slice(0,8)}`;

    container.innerHTML = `
      <div style="display:flex;gap:12px;margin-bottom:16px;">
        <div style="flex:1;background:#FFF5F5;border:1.5px solid #FB7185;border-radius:12px;padding:14px;">
          <div style="font-size:0.7em;font-weight:700;color:#E11D48;letter-spacing:1px;margin-bottom:8px;">🆕 NEW THREATS (${data.new_count})</div>
          ${data.new.length ? '<div class="threats-list">' + data.new.map(t=>threatCard(t)).join('') + '</div>'
            : '<p style="color:#aaa;font-size:0.82em">No new threats</p>'}
        </div>
        <div style="flex:1;background:#F0FFF4;border:1.5px solid #34D399;border-radius:12px;padding:14px;">
          <div style="font-size:0.7em;font-weight:700;color:#059669;letter-spacing:1px;margin-bottom:8px;">✅ RESOLVED (${data.resolved_count})</div>
          ${data.resolved.length ? '<div class="threats-list">' + data.resolved.map(t=>threatCard(t)).join('') + '</div>'
            : '<p style="color:#aaa;font-size:0.82em">No resolved threats</p>'}
        </div>
      </div>`;
  } catch(e) { showToast('Diff failed', 'error'); }
}

init();
requestNotifications();
</script>
</body>
</html>
"""

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)
