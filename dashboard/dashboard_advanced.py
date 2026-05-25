<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>CyberDefense Hub — OWASP Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Syne:wght@400;500;600;700;800&display=swap" rel="stylesheet"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
  :root {
    --bg:        #0a0c10;
    --bg2:       #0f1117;
    --bg3:       #161922;
    --bg4:       #1c2030;
    --border:    rgba(255,255,255,0.07);
    --border2:   rgba(255,255,255,0.12);
    --text:      #e8eaf0;
    --muted:     #7a8099;
    --dim:       #3d4460;
    --accent:    #00e5a0;
    --accent2:   #0af;
    --critical:  #ff4d6a;
    --high:      #ff8c42;
    --medium:    #ffd166;
    --low:       #06d6a0;
    --info:      #48cae4;
    --font-head: 'Syne', sans-serif;
    --font-mono: 'JetBrains Mono', monospace;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    font-family: var(--font-mono);
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    font-size: 13px;
    line-height: 1.6;
  }

  /* ── Grid noise background ── */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,229,160,0.015) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,229,160,0.015) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  /* ── Glow orb ── */
  body::after {
    content: '';
    position: fixed;
    top: -200px;
    left: 50%;
    transform: translateX(-50%);
    width: 800px;
    height: 500px;
    background: radial-gradient(ellipse, rgba(0,229,160,0.06) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
  }

  * { position: relative; z-index: 1; }

  /* ── Layout ── */
  .shell { max-width: 1400px; margin: 0 auto; padding: 0 24px 60px; }

  /* ── Header ── */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 28px 0 32px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 32px;
  }
  .header-left { display: flex; align-items: center; gap: 14px; }
  .logo-mark {
    width: 36px; height: 36px;
    background: var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
  }
  .logo-mark svg { width: 20px; height: 20px; }
  .brand { font-family: var(--font-head); font-size: 18px; font-weight: 800; letter-spacing: -0.5px; color: var(--text); }
  .brand span { color: var(--accent); }
  .header-meta { font-size: 11px; color: var(--muted); margin-top: 2px; }
  .header-right { display: flex; align-items: center; gap: 16px; }
  .timestamp { font-size: 11px; color: var(--muted); font-family: var(--font-mono); }
  .status-pill {
    display: flex; align-items: center; gap: 6px;
    padding: 5px 12px;
    background: rgba(0,229,160,0.08);
    border: 1px solid rgba(0,229,160,0.2);
    border-radius: 20px;
    font-size: 11px;
    color: var(--accent);
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }
  .pulse {
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--accent);
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.7); }
  }

  /* ── Metric cards row ── */
  .metrics-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 28px;
  }
  .metric-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 20px;
    transition: border-color 0.2s;
  }
  .metric-card:hover { border-color: var(--border2); }
  .metric-label {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 8px;
  }
  .metric-value {
    font-family: var(--font-head);
    font-size: 32px;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 4px;
  }
  .metric-sub { font-size: 11px; color: var(--muted); }
  .metric-card.critical .metric-value { color: var(--critical); }
  .metric-card.high     .metric-value { color: var(--high); }
  .metric-card.medium   .metric-value { color: var(--medium); }
  .metric-card.low      .metric-value { color: var(--low); }
  .metric-card.total    .metric-value { color: var(--accent2); }

  /* ── 2-col main grid ── */
  .main-grid {
    display: grid;
    grid-template-columns: 1fr 340px;
    gap: 16px;
    margin-bottom: 16px;
  }
  @media (max-width: 1000px) { .main-grid { grid-template-columns: 1fr; } }

  /* ── Panel base ── */
  .panel {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow: hidden;
  }
  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
  }
  .panel-title {
    font-family: var(--font-head);
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    color: var(--text);
  }
  .panel-badge {
    font-size: 10px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 20px;
    background: var(--bg4);
    color: var(--muted);
    font-family: var(--font-mono);
  }
  .panel-body { padding: 20px; }

  /* ── Scanner results list ── */
  .scanner-list { display: flex; flex-direction: column; gap: 8px; }
  .scanner-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 10px;
    cursor: pointer;
    transition: border-color 0.15s, background 0.15s;
  }
  .scanner-row:hover { border-color: var(--border2); background: var(--bg4); }
  .scanner-row.expanded { border-color: var(--accent); }
  .scanner-icon {
    width: 32px; height: 32px; border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 15px; flex-shrink: 0;
  }
  .scanner-info { flex: 1; min-width: 0; }
  .scanner-name {
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text);
    margin-bottom: 2px;
  }
  .scanner-summary { font-size: 11px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .scanner-count {
    font-family: var(--font-head);
    font-size: 20px;
    font-weight: 800;
    min-width: 32px;
    text-align: right;
  }
  .scanner-chevron {
    color: var(--muted);
    font-size: 12px;
    transition: transform 0.2s;
    flex-shrink: 0;
  }
  .scanner-row.expanded .scanner-chevron { transform: rotate(180deg); }

  /* ── Details accordion ── */
  .scanner-details {
    display: none;
    background: var(--bg);
    border: 1px solid var(--border);
    border-top: none;
    border-radius: 0 0 10px 10px;
    overflow: hidden;
    margin-top: -8px;
    margin-bottom: 8px;
  }
  .scanner-details.open { display: block; }
  .detail-row {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
  }
  .detail-row:last-child { border-bottom: none; }
  .sev-dot {
    width: 7px; height: 7px; border-radius: 50%;
    flex-shrink: 0; margin-top: 4px;
  }
  .detail-title { color: var(--text); line-height: 1.4; flex: 1; }
  .sev-tag {
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    padding: 2px 6px;
    border-radius: 4px;
    flex-shrink: 0;
  }
  .sev-critical { background: rgba(255,77,106,0.15); color: var(--critical); }
  .sev-high     { background: rgba(255,140,66,0.15); color: var(--high); }
  .sev-medium   { background: rgba(255,209,102,0.12); color: var(--medium); }
  .sev-low      { background: rgba(6,214,160,0.12); color: var(--low); }
  .sev-info     { background: rgba(72,202,228,0.12); color: var(--info); }
  .dot-critical { background: var(--critical); }
  .dot-high     { background: var(--high); }
  .dot-medium   { background: var(--medium); }
  .dot-low      { background: var(--low); }
  .dot-info     { background: var(--info); }
  .empty-state  { padding: 20px; text-align: center; color: var(--muted); font-size: 11px; }

  /* ── Chart panel ── */
  .chart-wrap { position: relative; height: 220px; }

  /* ── Legend ── */
  .chart-legend {
    display: flex; flex-direction: column; gap: 8px;
    padding: 0 20px 20px;
  }
  .legend-row {
    display: flex; align-items: center; justify-content: space-between;
    font-size: 11px;
  }
  .legend-label { display: flex; align-items: center; gap: 8px; color: var(--muted); }
  .legend-swatch { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
  .legend-count { font-weight: 600; color: var(--text); }
  .legend-bar-wrap { flex: 1; margin: 0 12px; height: 3px; background: var(--bg4); border-radius: 2px; overflow: hidden; }
  .legend-bar { height: 100%; border-radius: 2px; transition: width 0.8s cubic-bezier(0.4,0,0.2,1); }

  /* ── Target info ── */
  .target-panel { margin-bottom: 16px; }
  .target-body { padding: 16px 20px; display: flex; flex-wrap: wrap; gap: 20px; }
  .target-item { }
  .target-key { font-size: 10px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); margin-bottom: 4px; }
  .target-val { font-family: var(--font-mono); font-size: 13px; color: var(--accent2); }

  /* ── Bottom grid ── */
  .bottom-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }
  @media (max-width: 800px) { .bottom-grid { grid-template-columns: 1fr; } }

  /* ── Trend chart ── */
  .trend-wrap { position: relative; height: 160px; }

  /* ── OWASP mapping ── */
  .owasp-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 6px;
    padding: 16px 20px;
  }
  .owasp-item {
    display: flex; align-items: center; gap: 8px;
    padding: 8px 10px;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 10px;
  }
  .owasp-num {
    font-family: var(--font-head);
    font-weight: 800;
    font-size: 13px;
    color: var(--accent);
    min-width: 28px;
    line-height: 1;
  }
  .owasp-name { color: var(--muted); line-height: 1.3; }
  .owasp-item.active { border-color: rgba(0,229,160,0.3); background: rgba(0,229,160,0.04); }
  .owasp-item.active .owasp-name { color: var(--text); }

  /* ── Footer ── */
  .footer {
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 10px;
    color: var(--dim);
  }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--dim); border-radius: 2px; }

  /* ── Animations ── */
  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .panel, .metric-card { animation: fadeUp 0.4s ease both; }
  .metric-card:nth-child(1) { animation-delay: 0.05s; }
  .metric-card:nth-child(2) { animation-delay: 0.10s; }
  .metric-card:nth-child(3) { animation-delay: 0.15s; }
  .metric-card:nth-child(4) { animation-delay: 0.20s; }
  .metric-card:nth-child(5) { animation-delay: 0.25s; }
</style>
</head>
<body>
<div class="shell">

  <!-- ── Header ── -->
  <header class="header">
    <div class="header-left">
      <div class="logo-mark">
        <svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M10 2L3 5.5V10c0 4 3.1 7.5 7 8.5 3.9-1 7-4.5 7-8.5V5.5L10 2z" fill="#0a0c10" stroke="#0a0c10" stroke-width="0.5"/>
          <path d="M10 4L5 6.8V10c0 3 2.3 5.6 5 6.4 2.7-.8 5-3.4 5-6.4V6.8L10 4z" fill="rgba(0,229,160,0.2)"/>
          <path d="M8 10l1.5 1.5L12.5 8" stroke="#00e5a0" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div>
        <div class="brand">Cyber<span>Defense</span> Hub</div>
        <div class="header-meta">OWASP Automation Framework · v2.0</div>
      </div>
    </div>
    <div class="header-right">
      <span class="timestamp" id="ts">{{ timestamp }}</span>
      <div class="status-pill">
        <span class="pulse"></span>
        Scan Complete
      </div>
    </div>
  </header>

  <!-- ── Metric Cards ── -->
  <div class="metrics-row" id="metricsRow">
    <div class="metric-card critical">
      <div class="metric-label">Critical</div>
      <div class="metric-value" id="cnt-critical">0</div>
      <div class="metric-sub">Immediate action</div>
    </div>
    <div class="metric-card high">
      <div class="metric-label">High</div>
      <div class="metric-value" id="cnt-high">0</div>
      <div class="metric-sub">Remediate soon</div>
    </div>
    <div class="metric-card medium">
      <div class="metric-label">Medium</div>
      <div class="metric-value" id="cnt-medium">0</div>
      <div class="metric-sub">Plan remediation</div>
    </div>
    <div class="metric-card low">
      <div class="metric-label">Low</div>
      <div class="metric-value" id="cnt-low">0</div>
      <div class="metric-sub">Track & review</div>
    </div>
    <div class="metric-card total">
      <div class="metric-label">Total Findings</div>
      <div class="metric-value" id="cnt-total">0</div>
      <div class="metric-sub">Across all scanners</div>
    </div>
  </div>

  <!-- ── Target info ── -->
  <div class="panel target-panel">
    <div class="panel-header">
      <span class="panel-title">Scan Target</span>
      <span class="panel-badge" id="scannerCount">0 scanners</span>
    </div>
    <div class="target-body" id="targetBody">
      <div class="target-item">
        <div class="target-key">Scan ID</div>
        <div class="target-val" id="scanId">—</div>
      </div>
      <div class="target-item">
        <div class="target-key">Timestamp</div>
        <div class="target-val">{{ timestamp }}</div>
      </div>
      <div class="target-item">
        <div class="target-key">Modules Run</div>
        <div class="target-val" id="modulesRun">—</div>
      </div>
      <div class="target-item">
        <div class="target-key">Report Format</div>
        <div class="target-val">JSON + HTML</div>
      </div>
    </div>
  </div>

  <!-- ── Main Grid ── -->
  <div class="main-grid">

    <!-- Scanner results -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Scanner Results</span>
        <span class="panel-badge" id="totalFindings">0 findings</span>
      </div>
      <div class="panel-body">
        <div class="scanner-list" id="scannerList">
          <div class="empty-state">No scan data loaded.</div>
        </div>
      </div>
    </div>

    <!-- Donut chart -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Severity Distribution</span>
      </div>
      <div class="panel-body" style="padding-bottom:8px;">
        <div class="chart-wrap">
          <canvas id="donutChart" role="img" aria-label="Doughnut chart showing vulnerability severity distribution">No chart data.</canvas>
        </div>
      </div>
      <div class="chart-legend" id="donutLegend"></div>
    </div>

  </div>

  <!-- ── Bottom Grid ── -->
  <div class="bottom-grid">

    <!-- Trend chart -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Findings by Scanner</span>
      </div>
      <div class="panel-body">
        <div class="trend-wrap">
          <canvas id="barChart" role="img" aria-label="Bar chart showing number of findings per scanner">No chart data.</canvas>
        </div>
      </div>
    </div>

    <!-- OWASP mapping -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">OWASP Top 10 Coverage</span>
        <span class="panel-badge">2021</span>
      </div>
      <div class="owasp-grid" id="owaspGrid"></div>
    </div>

  </div>

  <!-- ── Footer ── -->
  <footer class="footer">
    <span>CyberDefense Hub · OWASP Automation Framework</span>
    <span>Generated {{ timestamp }} · MIT License</span>
  </footer>

</div>

<script>
/* ── Data injected by Jinja2 ── */
const RAW_SCANS = {{ scans | safe }};

/* ── Colour helpers ── */
const SEV_COLORS = {
  critical: '#ff4d6a',
  high:     '#ff8c42',
  medium:   '#ffd166',
  low:      '#06d6a0',
  info:     '#48cae4',
};
const SCANNER_COLORS = [
  '#00e5a0','#00aaff','#a78bfa','#fb923c','#f472b6','#34d399','#60a5fa','#fbbf24'
];
const SCANNER_ICONS = {
  sast: '🔍', dast: '🌐', nuclei: '⚡', nmap: '🗺️',
  dependency: '📦', session: '🔐', api_fuzz: '🔧', zap: '🛡️',
};
function sevClass(s) {
  const n = (s||'info').toLowerCase();
  if (n==='critical') return 'critical';
  if (n==='high')     return 'high';
  if (n==='medium')   return 'medium';
  if (n==='low')      return 'low';
  return 'info';
}

/* ── Count severities across all scanners ── */
function countAll() {
  const counts = { critical:0, high:0, medium:0, low:0, info:0 };
  Object.values(RAW_SCANS).forEach(s => {
    (s.details||[]).forEach(d => { const k=sevClass(d.severity); counts[k]=(counts[k]||0)+1; });
  });
  return counts;
}

/* ── Findings per scanner ── */
function perScanner() {
  return Object.entries(RAW_SCANS).map(([name, data]) => ({
    name,
    count: (data.details||[]).length,
    summary: data.summary || '',
    details: data.details || [],
  }));
}

/* ── Update metric cards ── */
function updateMetrics() {
  const c = countAll();
  const total = Object.values(c).reduce((a,b)=>a+b,0);
  document.getElementById('cnt-critical').textContent = c.critical;
  document.getElementById('cnt-high').textContent     = c.high;
  document.getElementById('cnt-medium').textContent   = c.medium;
  document.getElementById('cnt-low').textContent      = c.low;
  document.getElementById('cnt-total').textContent    = total;
  document.getElementById('totalFindings').textContent = total + ' findings';

  const keys = Object.keys(RAW_SCANS);
  document.getElementById('scannerCount').textContent = keys.length + ' scanners';
  document.getElementById('modulesRun').textContent   = keys.join(' · ') || '—';
  document.getElementById('scanId').textContent       = 'SCAN-' + Date.now().toString(36).toUpperCase().slice(-6);
}

/* ── Build scanner list ── */
function buildScannerList() {
  const list = document.getElementById('scannerList');
  const scanners = perScanner();
  if (!scanners.length) return;
  list.innerHTML = '';

  scanners.forEach((sc, i) => {
    const color = SCANNER_COLORS[i % SCANNER_COLORS.length];
    const icon  = SCANNER_ICONS[sc.name] || '🔎';
    const total = sc.count;
    const sevCounts = {};
    sc.details.forEach(d => { const k=sevClass(d.severity); sevCounts[k]=(sevCounts[k]||0)+1; });
    const topSev = ['critical','high','medium','low','info'].find(s=>sevCounts[s]>0) || 'info';

    /* Row */
    const row = document.createElement('div');
    row.className = 'scanner-row';
    row.innerHTML = `
      <div class="scanner-icon" style="background:${color}1a; color:${color};">${icon}</div>
      <div class="scanner-info">
        <div class="scanner-name">${sc.name}</div>
        <div class="scanner-summary">${sc.summary || 'No findings'}</div>
      </div>
      <div class="scanner-count" style="color:${total>0?SEV_COLORS[topSev]:'#3d4460'}">${total}</div>
      <div class="scanner-chevron">▼</div>
    `;

    /* Details panel */
    const details = document.createElement('div');
    details.className = 'scanner-details';
    if (sc.details.length === 0) {
      details.innerHTML = '<div class="empty-state">✓ No findings from this scanner.</div>';
    } else {
      sc.details.forEach(d => {
        const sc2 = sevClass(d.severity);
        const item = document.createElement('div');
        item.className = 'detail-row';
        item.innerHTML = `
          <span class="sev-dot dot-${sc2}"></span>
          <span class="detail-title">${d.title || 'Unnamed finding'}</span>
          <span class="sev-tag sev-${sc2}">${sc2}</span>
        `;
        details.appendChild(item);
      });
    }

    row.addEventListener('click', () => {
      const open = row.classList.toggle('expanded');
      details.classList.toggle('open', open);
    });

    list.appendChild(row);
    list.appendChild(details);
  });
}

/* ── Donut chart ── */
function buildDonut() {
  const c = countAll();
  const labels  = ['Critical','High','Medium','Low','Info'];
  const values  = [c.critical, c.high, c.medium, c.low, c.info];
  const colors  = ['#ff4d6a','#ff8c42','#ffd166','#06d6a0','#48cae4'];
  const total   = values.reduce((a,b)=>a+b,0);

  new Chart(document.getElementById('donutChart'), {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: colors.map(c => c + 'cc'),
        borderColor: '#0a0c10',
        borderWidth: 3,
        hoverBorderWidth: 3,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.raw} (${total ? Math.round(ctx.raw/total*100) : 0}%)`
          }
        }
      }
    }
  });

  /* Custom legend with mini bars */
  const legend = document.getElementById('donutLegend');
  labels.forEach((lbl, i) => {
    const pct = total ? Math.round(values[i]/total*100) : 0;
    const row = document.createElement('div');
    row.className = 'legend-row';
    row.innerHTML = `
      <span class="legend-label">
        <span class="legend-swatch" style="background:${colors[i]}"></span>
        ${lbl}
      </span>
      <div class="legend-bar-wrap">
        <div class="legend-bar" style="width:${pct}%; background:${colors[i]};"></div>
      </div>
      <span class="legend-count">${values[i]}</span>
    `;
    legend.appendChild(row);
  });
}

/* ── Bar chart (findings per scanner) ── */
function buildBar() {
  const scanners = perScanner();
  const labels  = scanners.map(s => s.name.toUpperCase());
  const values  = scanners.map(s => s.count);
  const colors  = scanners.map((_, i) => SCANNER_COLORS[i % SCANNER_COLORS.length] + 'cc');

  new Chart(document.getElementById('barChart'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Findings',
        data: values,
        backgroundColor: colors,
        borderColor: colors.map(c=>c.slice(0,-2)),
        borderWidth: 0,
        borderRadius: 5,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#7a8099', font: { family: "'JetBrains Mono'", size: 10 }, maxRotation: 30 },
          grid: { color: 'rgba(255,255,255,0.04)' },
        },
        y: {
          ticks: { color: '#7a8099', font: { family: "'JetBrains Mono'", size: 10 }, stepSize: 1 },
          grid: { color: 'rgba(255,255,255,0.04)' },
          beginAtZero: true,
        }
      }
    }
  });
}

/* ── OWASP Top 10 grid ── */
function buildOwasp() {
  const OWASP = [
    ['A01', 'Broken Access Control'],
    ['A02', 'Cryptographic Failures'],
    ['A03', 'Injection'],
    ['A04', 'Insecure Design'],
    ['A05', 'Security Misconfiguration'],
    ['A06', 'Vulnerable Components'],
    ['A07', 'Auth & Session Failures'],
    ['A08', 'Software Integrity Failures'],
    ['A09', 'Logging Failures'],
    ['A10', 'SSRF'],
  ];
  /* Heuristic: flag categories based on finding titles */
  const allTitles = Object.values(RAW_SCANS)
    .flatMap(s => (s.details||[]).map(d => (d.title||'').toLowerCase()));
  const KEYWORDS = {
    'A01': ['access','auth','idor','privilege','permission'],
    'A02': ['crypto','ssl','tls','cert','hash','cipher'],
    'A03': ['inject','sql','xss','command','ldap','xpath'],
    'A04': ['design','logic','workflow'],
    'A05': ['config','header','server','expose','version','default'],
    'A06': ['outdated','vulnerable','cve','package','dependency'],
    'A07': ['session','jwt','token','login','cookie','csrf'],
    'A08': ['integrity','supply','unsigned'],
    'A09': ['log','monitor','audit'],
    'A10': ['ssrf','request forgery','internal'],
  };
  const grid = document.getElementById('owaspGrid');
  OWASP.forEach(([code, name]) => {
    const active = allTitles.some(t => (KEYWORDS[code]||[]).some(k => t.includes(k)));
    const el = document.createElement('div');
    el.className = 'owasp-item' + (active ? ' active' : '');
    el.innerHTML = `<span class="owasp-num">${code}</span><span class="owasp-name">${name}</span>`;
    grid.appendChild(el);
  });
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  updateMetrics();
  buildScannerList();
  buildDonut();
  buildBar();
  buildOwasp();
});
</script>
</body>
</html>
