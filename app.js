/**
 * PCAP Flow Analyzer - Frontend Application Controller
 * Handles async API communication, SVG sequence ladder generation,
 * Canvas performance charting, and deep packet header inspection.
 */

// Application State
const state = {
  activeFileName: '',
  conversations: [],
  analysisResult: null,
  selectedStreamIndex: 0,
  filterAnomaliesOnly: false,
  selectedPacketIndex: null,
  packetDetailCache: {},
};

// DOM Element References
const elements = {
  // Navigation & Header
  activeFileName: document.getElementById('activeFileName'),
  activeFileStats: document.getElementById('activeFileStats'),
  sampleSelect: document.getElementById('sampleSelect'),
  btnExportReport: document.getElementById('btnExportReport'),

  // Upload & Form
  dropZone: document.getElementById('dropZone'),
  fileInput: document.getElementById('fileInput'),
  inputClientIp: document.getElementById('inputClientIp'),
  inputClientPort: document.getElementById('inputClientPort'),
  btnSwapIps: document.getElementById('btnSwapIps'),
  inputServerIp: document.getElementById('inputServerIp'),
  inputServerPort: document.getElementById('inputServerPort'),
  btnRunAnalysis: document.getElementById('btnRunAnalysis'),
  conversationPillsContainer: document.getElementById('conversationPillsContainer'),

  // Executive Diagnostics
  overallHealthBadge: document.getElementById('overallHealthBadge'),
  overallHealthStatusText: document.getElementById('overallHealthStatusText'),
  healthScoreNumber: document.getElementById('healthScoreNumber'),
  gaugeProgressCircle: document.getElementById('gaugeProgressCircle'),
  analysisScopeSubtitle: document.getElementById('analysisScopeSubtitle'),

  valRetransmissions: document.getElementById('valRetransmissions'),
  valRetransRate: document.getElementById('valRetransRate'),
  footRetransDetail: document.getElementById('footRetransDetail'),

  valDupAcks: document.getElementById('valDupAcks'),
  footDupAcksDetail: document.getElementById('footDupAcksDetail'),

  valZeroWindows: document.getElementById('valZeroWindows'),
  valZeroWinStall: document.getElementById('valZeroWinStall'),
  footZeroWinDetail: document.getElementById('footZeroWinDetail'),

  valRstCount: document.getElementById('valRstCount'),
  footRstDetail: document.getElementById('footRstDetail'),

  valAvgRtt: document.getElementById('valAvgRtt'),
  footRttDetail: document.getElementById('footRttDetail'),

  recommendationsList: document.getElementById('recommendationsList'),

  // Streams Table
  streamsCountPill: document.getElementById('streamsCountPill'),
  streamsTableBody: document.getElementById('streamsTableBody'),

  // Ladder Diagram
  ladderStreamSubtitle: document.getElementById('ladderStreamSubtitle'),
  btnFilterAllPkts: document.getElementById('btnFilterAllPkts'),
  btnFilterAnomalies: document.getElementById('btnFilterAnomalies'),
  ladderViewport: document.getElementById('ladderViewport'),
  ladderSvg: document.getElementById('ladderSvg'),

  // Charts Canvas
  rttCanvas: document.getElementById('rttChartCanvas'),
  windowCanvas: document.getElementById('windowChartCanvas'),
  throughputCanvas: document.getElementById('throughputChartCanvas'),

  // Modal Inspector
  packetModalBackdrop: document.getElementById('packetModalBackdrop'),
  modalPacketTitle: document.getElementById('modalPacketTitle'),
  modalPacketSubtitle: document.getElementById('modalPacketSubtitle'),
  btnModalClose: document.getElementById('btnModalClose'),
  modalFrameContent: document.getElementById('modalFrameContent'),
  modalEthContent: document.getElementById('modalEthContent'),
  modalIpContent: document.getElementById('modalIpContent'),
  modalTcpContent: document.getElementById('modalTcpContent'),
  modalHexDumpViewer: document.getElementById('modalHexDumpViewer'),
  btnCopyHex: document.getElementById('btnCopyHex'),
};

// =============================================================================
// Initialization
// =============================================================================
document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  // Fetch initial active session / conversations
  await refreshActiveSession();
});

function setupEventListeners() {
  // Sample picker dropdown
  elements.sampleSelect.addEventListener('change', async (e) => {
    const sampleKey = e.target.value;
    if (!sampleKey) return;
    await loadSample(sampleKey);
    e.target.value = '';
  });

  // Export report button
  elements.btnExportReport.addEventListener('click', () => {
    window.open('/api/export-report', '_blank');
  });

  // Drag and drop upload
  elements.dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    elements.dropZone.classList.add('dragover');
  });

  elements.dropZone.addEventListener('dragleave', () => {
    elements.dropZone.classList.remove('dragover');
  });

  elements.dropZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    elements.dropZone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await uploadFile(e.dataTransfer.files[0]);
    }
  });

  elements.fileInput.addEventListener('change', async (e) => {
    if (e.target.files && e.target.files.length > 0) {
      await uploadFile(e.target.files[0]);
    }
  });

  // Swap IPs button
  elements.btnSwapIps.addEventListener('click', () => {
    const cIp = elements.inputClientIp.value;
    const cPort = elements.inputClientPort.value;
    elements.inputClientIp.value = elements.inputServerIp.value;
    elements.inputClientPort.value = elements.inputServerPort.value;
    elements.inputServerIp.value = cIp;
    elements.inputServerPort.value = cPort;
    runAnalysis();
  });

  // Run Analysis button
  elements.btnRunAnalysis.addEventListener('click', () => {
    runAnalysis();
  });

  // Ladder filter toggle buttons
  elements.btnFilterAllPkts.addEventListener('click', () => {
    state.filterAnomaliesOnly = false;
    elements.btnFilterAllPkts.classList.add('active');
    elements.btnFilterAnomalies.classList.remove('active');
    renderLadderDiagram();
  });

  elements.btnFilterAnomalies.addEventListener('click', () => {
    state.filterAnomaliesOnly = true;
    elements.btnFilterAnomalies.classList.add('active');
    elements.btnFilterAllPkts.classList.remove('active');
    renderLadderDiagram();
  });

  // Modal close handlers
  elements.btnModalClose.addEventListener('click', closeModal);
  elements.packetModalBackdrop.addEventListener('click', (e) => {
    if (e.target === elements.packetModalBackdrop) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
  });

  // Copy Hex button
  elements.btnCopyHex.addEventListener('click', () => {
    const text = elements.modalHexDumpViewer.innerText;
    navigator.clipboard.writeText(text).then(() => {
      elements.btnCopyHex.innerText = 'Copied!';
      setTimeout(() => { elements.btnCopyHex.innerText = 'Copy Hex'; }, 2000);
    });
  });
}

// =============================================================================
// API Communication
// =============================================================================
async function refreshActiveSession() {
  try {
    const res = await fetch('/api/conversations');
    const data = await res.json();
    if (data.success && data.conversations && data.conversations.length > 0) {
      state.activeFileName = data.filename;
      state.conversations = data.conversations;
      updateHeaderFileInfo(data.filename, data.total_packets);
      renderConversationPills();

      // Auto-select first conversation
      const topConv = data.conversations[0];
      elements.inputClientIp.value = topConv.ip_a;
      elements.inputServerIp.value = topConv.ip_b;
      await runAnalysis();
    }
  } catch (err) {
    console.error('Error refreshing session:', err);
  }
}

async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  try {
    elements.activeFileName.innerText = 'Uploading...';
    const res = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();
    if (!data.success) {
      alert(`Upload error: ${data.error}`);
      return;
    }

    const meta = data.metadata;
    state.activeFileName = meta.filename;
    state.conversations = meta.conversations;
    updateHeaderFileInfo(meta.filename, meta.total_packets, meta.duration_seconds);
    renderConversationPills();

    if (meta.conversations && meta.conversations.length > 0) {
      const topConv = meta.conversations[0];
      elements.inputClientIp.value = topConv.ip_a;
      elements.inputServerIp.value = topConv.ip_b;
    } else {
      elements.inputClientIp.value = '';
      elements.inputServerIp.value = '';
    }

    await runAnalysis();
  } catch (err) {
    console.error('Upload failed:', err);
    alert('Failed to upload file');
  }
}

async function loadSample(sampleKey) {
  try {
    elements.activeFileName.innerText = `Loading ${sampleKey}...`;
    const res = await fetch('/api/load-sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sample_key: sampleKey }),
    });
    const data = await res.json();
    if (!data.success) {
      alert(`Error loading sample: ${data.error}`);
      return;
    }

    const meta = data.metadata;
    state.activeFileName = meta.filename;
    state.conversations = meta.conversations;
    updateHeaderFileInfo(meta.filename, meta.total_packets, meta.duration_seconds);
    renderConversationPills();

    if (meta.conversations && meta.conversations.length > 0) {
      const topConv = meta.conversations[0];
      elements.inputClientIp.value = topConv.ip_a;
      elements.inputServerIp.value = topConv.ip_b;
    }
    await runAnalysis();
  } catch (err) {
    console.error('Sample load error:', err);
  }
}

async function runAnalysis() {
  const clientIp = elements.inputClientIp.value.trim() || undefined;
  const serverIp = elements.inputServerIp.value.trim() || undefined;
  const clientPort = elements.inputClientPort.value.trim() || undefined;
  const serverPort = elements.inputServerPort.value.trim() || undefined;

  try {
    elements.btnRunAnalysis.disabled = true;
    elements.btnRunAnalysis.innerText = 'Analyzing...';

    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_ip: clientIp,
        server_ip: serverIp,
        client_port: clientPort,
        server_port: serverPort,
      }),
    });

    const data = await res.json();
    if (!data.success) {
      alert(`Analysis error: ${data.error}`);
      return;
    }

    state.analysisResult = data;
    state.selectedStreamIndex = 0;

    renderDiagnosticsDashboard(data.summary);
    renderStreamsTable(data.streams);
    renderActiveStreamDetail();
  } catch (err) {
    console.error('Analysis error:', err);
  } finally {
    elements.btnRunAnalysis.disabled = false;
    elements.btnRunAnalysis.innerHTML = `
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
        <polygon points="5 3 19 12 5 21 5 3"/>
      </svg>
      <span>Analyze Flow</span>
    `;
  }
}

// =============================================================================
// UI Rendering Functions
// =============================================================================
function updateHeaderFileInfo(name, packetsCount, durationSec) {
  elements.activeFileName.innerText = name || 'None';
  let stats = `${packetsCount.toLocaleString()} pkts`;
  if (durationSec !== undefined && durationSec > 0) {
    stats += ` • ${durationSec}s`;
  }
  elements.activeFileStats.innerText = stats;
}

function renderConversationPills() {
  const container = elements.conversationPillsContainer;
  container.innerHTML = '';

  if (!state.conversations || state.conversations.length === 0) {
    container.innerHTML = '<span class="loading-shimmer">No conversations detected.</span>';
    return;
  }

  state.conversations.forEach((conv, idx) => {
    const pill = document.createElement('button');
    pill.className = `conv-pill ${idx === 0 ? 'active' : ''}`;
    pill.innerHTML = `<strong>${conv.ip_a}</strong> ↔ <strong>${conv.ip_b}</strong> (${conv.total_packets} pkts)`;
    pill.addEventListener('click', () => {
      document.querySelectorAll('.conv-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      elements.inputClientIp.value = conv.ip_a;
      elements.inputServerIp.value = conv.ip_b;
      runAnalysis();
    });
    container.appendChild(pill);
  });
}

function renderDiagnosticsDashboard(summary) {
  const score = summary.health_score ?? 100;
  const status = summary.health_status || 'HEALTHY';

  elements.healthScoreNumber.innerText = score;
  elements.overallHealthStatusText.innerText = status;

  // Gauge SVG dashoffset animation (circumference = 2 * PI * 42 ~= 263.89)
  const maxDash = 263.89;
  const offset = maxDash - (score / 100) * maxDash;
  elements.gaugeProgressCircle.style.strokeDashoffset = offset;

  // Color coordination
  elements.overallHealthBadge.className = 'overall-health-badge';
  let strokeColor = 'var(--color-success)';
  if (status === 'DEGRADED') {
    elements.overallHealthBadge.classList.add('status-degraded');
    strokeColor = 'var(--color-warning)';
  } else if (status === 'CRITICAL') {
    elements.overallHealthBadge.classList.add('status-critical');
    strokeColor = 'var(--color-danger)';
  }
  elements.gaugeProgressCircle.style.stroke = strokeColor;

  // Summary Metrics
  elements.valRetransmissions.innerText = summary.retransmissions_total;
  elements.valRetransRate.innerText = `(${summary.retransmission_rate_pct}%)`;
  elements.footRetransDetail.innerText = summary.retransmissions_total > 0
    ? `${summary.retransmissions_total} packets required retransmit`
    : 'No packet loss detected';

  elements.valDupAcks.innerText = summary.duplicate_acks_total;
  elements.footDupAcksDetail.innerText = summary.duplicate_acks_total > 0
    ? `${summary.duplicate_acks_total} duplicate ACKs signaled`
    : 'Smooth sequence progression';

  elements.valZeroWindows.innerText = summary.zero_window_events_total;
  elements.valZeroWinStall.innerText = `(${summary.zero_window_total_stall_ms}ms)`;
  elements.footZeroWinDetail.innerText = summary.zero_window_events_total > 0
    ? `${summary.zero_window_total_stall_ms}ms total receiver stall`
    : 'Healthy receiver buffer';

  elements.valRstCount.innerText = summary.rst_aborts_total;
  elements.footRstDetail.innerText = summary.rst_aborts_total > 0
    ? `${summary.rst_aborts_total} abrupt RST terminations`
    : 'Clean graceful closures';

  elements.valAvgRtt.innerText = summary.avg_rtt_ms !== null ? summary.avg_rtt_ms : '--';
  elements.footRttDetail.innerText = summary.max_rtt_ms !== null ? `Max RTT: ${summary.max_rtt_ms} ms` : 'Handshake RTT';

  // Subtitle scope
  elements.analysisScopeSubtitle.innerText = `${summary.total_streams} streams • ${summary.total_packets} packets • ${(summary.total_bytes / 1024).toFixed(1)} KB`;

  // Recommendations
  const recList = elements.recommendationsList;
  recList.innerHTML = '';

  const issues = [...(summary.critical_issues || []), ...(summary.warnings || [])];
  if (issues.length > 0) {
    issues.forEach(iss => {
      const li = document.createElement('li');
      li.innerHTML = `<strong>${iss.title}:</strong> ${iss.detail}`;
      recList.appendChild(li);
    });
  }

  if (summary.recommendations && summary.recommendations.length > 0) {
    summary.recommendations.forEach(rec => {
      const li = document.createElement('li');
      li.innerText = rec;
      recList.appendChild(li);
    });
  }
}

function renderStreamsTable(streams) {
  const tbody = elements.streamsTableBody;
  tbody.innerHTML = '';

  elements.streamsCountPill.innerText = `${streams.length} Stream${streams.length === 1 ? '' : 's'}`;

  if (!streams || streams.length === 0) {
    tbody.innerHTML = '<tr><td colspan="12" class="text-center py-4">No matching TCP streams found in capture.</td></tr>';
    return;
  }

  streams.forEach((s, idx) => {
    const tr = document.createElement('tr');
    if (idx === state.selectedStreamIndex) tr.classList.add('selected');

    let badgeClass = 'badge-healthy';
    if (s.health_status === 'DEGRADED') badgeClass = 'badge-degraded';
    if (s.health_status === 'CRITICAL') badgeClass = 'badge-critical';

    tr.innerHTML = `
      <td class="font-mono"><strong>#${s.stream_id}</strong></td>
      <td class="font-mono">${s.client_ip}:${s.client_port}</td>
      <td class="text-center" style="color: var(--text-dim);">↔</td>
      <td class="font-mono">${s.server_ip}:${s.server_port}</td>
      <td><strong>${s.total_packets}</strong></td>
      <td>${(s.total_bytes / 1024).toFixed(1)} KB</td>
      <td>${s.duration_ms} ms</td>
      <td>${s.handshake_irtt_ms !== null ? s.handshake_irtt_ms + ' ms' : '--'}</td>
      <td style="${s.retransmission_count > 0 ? 'color: var(--color-danger); font-weight: 700;' : ''}">${s.retransmission_count}</td>
      <td style="${s.zero_window_count > 0 ? 'color: var(--color-warning); font-weight: 700;' : ''}">${s.zero_window_count > 0 ? s.zero_window_stall_ms + 'ms' : '0'}</td>
      <td><span class="status-badge ${badgeClass}">${s.health_status} (${s.health_score})</span></td>
      <td><button class="btn btn-xs btn-outline">Inspect Flow</button></td>
    `;

    tr.addEventListener('click', () => {
      document.querySelectorAll('#streamsTableBody tr').forEach(r => r.classList.remove('selected'));
      tr.classList.add('selected');
      state.selectedStreamIndex = idx;
      renderActiveStreamDetail();
    });

    tbody.appendChild(tr);
  });
}

function renderActiveStreamDetail() {
  if (!state.analysisResult || !state.analysisResult.streams || state.analysisResult.streams.length === 0) {
    return;
  }

  const stream = state.analysisResult.streams[state.selectedStreamIndex] || state.analysisResult.streams[0];
  elements.ladderStreamSubtitle.innerText = `Stream #${stream.stream_id} • ${stream.client_ip}:${stream.client_port} ↔ ${stream.server_ip}:${stream.server_port} (${stream.total_packets} packets)`;

  renderLadderDiagram();
  renderPerformanceCharts(stream);
}

// =============================================================================
// Interactive SVG Sequence Ladder Diagram
// =============================================================================
function renderLadderDiagram() {
  if (!state.analysisResult || !state.analysisResult.streams) return;
  const stream = state.analysisResult.streams[state.selectedStreamIndex];
  if (!stream) return;

  const svg = elements.ladderSvg;
  svg.innerHTML = '';

  let packets = stream.packets || [];
  if (state.filterAnomaliesOnly) {
    packets = packets.filter(p => p.anomalies && p.anomalies.length > 0);
  }

  if (packets.length === 0) {
    svg.setAttribute('height', '120');
    svg.innerHTML = `<text x="50%" y="60" fill="var(--text-dim)" text-anchor="middle" font-size="13">No packets to display for this filter.</text>`;
    return;
  }

  const rowHeight = 46;
  const topMargin = 70;
  const totalHeight = topMargin + packets.length * rowHeight + 40;
  svg.setAttribute('height', totalHeight);

  // Measure width
  const svgWidth = elements.ladderViewport.clientWidth || 800;
  const clientX = 140;
  const serverX = Math.max(400, svgWidth - 140);

  // 1. Draw Lifelines
  let svgContent = `
    <!-- Defs / Arrowheads -->
    <defs>
      <marker id="arrow-green" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981" />
      </marker>
      <marker id="arrow-blue" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#0ea5e9" />
      </marker>
      <marker id="arrow-amber" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#f59e0b" />
      </marker>
      <marker id="arrow-red" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444" />
      </marker>
    </defs>

    <!-- Client Lifeline -->
    <line x1="${clientX}" y1="40" x2="${clientX}" y2="${totalHeight - 20}" stroke="rgba(255,255,255,0.15)" stroke-width="2" stroke-dasharray="4 4" />
    <rect x="${clientX - 65}" y="10" width="130" height="30" rx="6" fill="#1e293b" stroke="rgba(255,255,255,0.2)" />
    <text x="${clientX}" y="30" fill="#ffffff" text-anchor="middle" font-size="11" font-weight="700" font-family="JetBrains Mono">Client :${stream.client_port}</text>

    <!-- Server Lifeline -->
    <line x1="${serverX}" y1="40" x2="${serverX}" y2="${totalHeight - 20}" stroke="rgba(255,255,255,0.15)" stroke-width="2" stroke-dasharray="4 4" />
    <rect x="${serverX - 65}" y="10" width="130" height="30" rx="6" fill="#1e293b" stroke="rgba(255,255,255,0.2)" />
    <text x="${serverX}" y="30" fill="#ffffff" text-anchor="middle" font-size="11" font-weight="700" font-family="JetBrains Mono">Server :${stream.server_port}</text>
  `;

  // 2. Draw Packet Flow Rows
  packets.forEach((p, idx) => {
    const y = topMargin + idx * rowHeight;
    const isCtoS = p.direction === 'C->S';
    const x1 = isCtoS ? clientX : serverX;
    const x2 = isCtoS ? serverX : clientX;

    // Determine category color & marker
    let strokeColor = '#0ea5e9'; // Blue default
    let markerName = 'arrow-blue';

    if (p.flags.SYN || p.flags.FIN) {
      strokeColor = '#10b981'; // Green
      markerName = 'arrow-green';
    }

    const hasAnomaly = p.anomalies && p.anomalies.length > 0;
    if (hasAnomaly) {
      const topAnom = p.anomalies[0].anomaly_type;
      if (topAnom.includes('RETRANSMISSION') || topAnom.includes('RST')) {
        strokeColor = '#ef4444'; // Red
        markerName = 'arrow-red';
      } else {
        strokeColor = '#f59e0b'; // Amber
        markerName = 'arrow-amber';
      }
    }

    // Packet Label info
    const flagsPill = `[${p.flags_str}]`;
    const labelMain = `Pkt #${p.packet_index} • ${flagsPill} Seq=${p.rel_seq} Ack=${p.rel_ack} Len=${p.payload_len}`;
    const labelSub = `+${p.relative_time_ms.toFixed(1)}ms • Win=${p.effective_window}`;

    const midX = (clientX + serverX) / 2;
    const textAnchor = 'middle';

    let anomalyBadgeSvg = '';
    if (hasAnomaly) {
      const anomTitle = p.anomalies[0].title;
      anomalyBadgeSvg = `
        <rect x="${midX - 110}" y="${y + 12}" width="220" height="18" rx="4" fill="rgba(239, 68, 68, 0.2)" stroke="${strokeColor}" stroke-width="1"/>
        <text x="${midX}" y="${y + 24}" fill="${strokeColor}" text-anchor="middle" font-size="10" font-weight="700">⚠️ ${anomTitle}</text>
      `;
    }

    svgContent += `
      <g class="packet-row-group" style="cursor: pointer;" onclick="inspectPacket(${p.packet_index})">
        <!-- Row hover background -->
        <rect x="20" y="${y - 18}" width="${svgWidth - 40}" height="${rowHeight}" rx="6" fill="transparent" class="pkt-hover-bg" />
        
        <!-- Packet Arrow Line -->
        <line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="${strokeColor}" stroke-width="2" marker-end="url(#${markerName})" />
        
        <!-- Packet Label -->
        <text x="${midX}" y="${y - 6}" fill="#ffffff" text-anchor="${textAnchor}" font-size="11" font-family="JetBrains Mono" font-weight="600">${labelMain}</text>
        <text x="${isCtoS ? clientX - 8 : serverX + 8}" y="${y + 4}" fill="var(--text-dim)" text-anchor="${isCtoS ? 'end' : 'start'}" font-size="10" font-family="JetBrains Mono">${labelSub}</text>
        
        ${anomalyBadgeSvg}
      </g>
    `;
  });

  svg.innerHTML = svgContent;
}

// Global hook for SVG onclick
window.inspectPacket = async function(packetIndex) {
  openPacketModal(packetIndex);
};

// =============================================================================
// Performance Metrics Canvas Charts
// =============================================================================
function renderPerformanceCharts(stream) {
  drawTimelineChart(elements.rttCanvas, stream.rtt_timeline, 'time_ms', 'rtt_ms', '#10b981', 'ms');
  drawTimelineChart(elements.windowCanvas, stream.window_timeline, 'time_ms', 'window_size', '#6366f1', 'bytes');
  drawTimelineChart(elements.throughputCanvas, stream.throughput_timeline, 'time_sec', 'kbps', '#0ea5e9', 'KB/s');
}

function drawTimelineChart(canvas, data, xKey, yKey, color, unit) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;

  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = rect.height;
  const padLeft = 40;
  const padRight = 20;
  const padTop = 15;
  const padBottom = 25;

  ctx.clearRect(0, 0, w, h);

  if (!data || data.length === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No sample data points', w / 2, h / 2);
    return;
  }

  // Find min/max
  const xVals = data.map(d => d[xKey]);
  const yVals = data.map(d => d[yKey]);

  const minX = Math.min(...xVals);
  const maxX = Math.max(...xVals) || 1;
  const minY = 0;
  const maxY = (Math.max(...yVals) * 1.15) || 10;

  // Helper scale functions
  const scaleX = (val) => padLeft + ((val - minX) / (maxX - minX || 1)) * (w - padLeft - padRight);
  const scaleY = (val) => h - padBottom - ((val - minY) / (maxY - minY || 1)) * (h - padTop - padBottom);

  // Draw Gridlines
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const yVal = minY + (maxY - minY) * (i / 3);
    const yPos = scaleY(yVal);
    ctx.beginPath();
    ctx.moveTo(padLeft, yPos);
    ctx.lineTo(w - padRight, yPos);
    ctx.stroke();

    ctx.fillStyle = '#64748b';
    ctx.font = '9px JetBrains Mono';
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(yVal), padLeft - 6, yPos + 3);
  }

  // Draw Line
  ctx.beginPath();
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;

  data.forEach((d, idx) => {
    const px = scaleX(d[xKey]);
    const py = scaleY(d[yKey]);
    if (idx === 0) ctx.moveTo(px, py);
    else ctx.lineTo(px, py);
  });
  ctx.stroke();

  // Draw Area fill gradient
  const grad = ctx.createLinearGradient(0, padTop, 0, h - padBottom);
  grad.addColorStop(0, color.replace(')', ', 0.35)').replace('rgb', 'rgba').replace('#', 'rgba('));
  grad.addColorStop(1, 'rgba(0,0,0,0)');

  ctx.lineTo(scaleX(xVals[xVals.length - 1]), h - padBottom);
  ctx.lineTo(scaleX(xVals[0]), h - padBottom);
  ctx.closePath();
  ctx.fillStyle = 'rgba(99, 102, 241, 0.1)';
  ctx.fill();

  // Draw Dots
  ctx.fillStyle = color;
  data.forEach((d) => {
    const px = scaleX(d[xKey]);
    const py = scaleY(d[yKey]);
    ctx.beginPath();
    ctx.arc(px, py, 3, 0, Math.PI * 2);
    ctx.fill();
  });
}

// =============================================================================
// Deep Packet Inspector Modal
// =============================================================================
async function openPacketModal(packetIndex) {
  state.selectedPacketIndex = packetIndex;
  elements.modalPacketTitle.innerText = `Packet #${packetIndex} Inspector`;
  elements.modalPacketSubtitle.innerText = 'Fetching decoded protocol headers & payload...';
  elements.packetModalBackdrop.classList.add('open');

  try {
    let detail = state.packetDetailCache[packetIndex];
    if (!detail) {
      const res = await fetch(`/api/packet-detail?packet_index=${packetIndex}`);
      detail = await res.json();
      if (detail.success) {
        state.packetDetailCache[packetIndex] = detail;
      }
    }

    if (detail && detail.success) {
      renderPacketModalDetail(detail);
    }
  } catch (err) {
    console.error('Failed to load packet detail:', err);
  }
}

function renderPacketModalDetail(d) {
  elements.modalPacketSubtitle.innerText = `Captured: ${d.captured_len} bytes • Link Type: ${d.link_type}`;

  // Frame
  elements.modalFrameContent.innerHTML = `
    <div class="proto-field-row"><span class="proto-field-key">Frame Number:</span><span class="proto-field-val">#${d.packet_index}</span></div>
    <div class="proto-field-row"><span class="proto-field-key">Timestamp:</span><span class="proto-field-val">${d.timestamp.toFixed(6)}</span></div>
    <div class="proto-field-row"><span class="proto-field-key">Captured Length:</span><span class="proto-field-val">${d.captured_len} bytes (${d.original_len} bytes on wire)</span></div>
  `;

  // Ethernet
  if (d.ethernet) {
    elements.modalEthContent.innerHTML = `
      <div class="proto-field-row"><span class="proto-field-key">Source MAC:</span><span class="proto-field-val">${d.ethernet.src_mac}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Destination MAC:</span><span class="proto-field-val">${d.ethernet.dst_mac}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">EtherType:</span><span class="proto-field-val">0x${d.ethernet.ethertype ? d.ethernet.ethertype.toString(16).padStart(4, '0') : '0800'}</span></div>
      ${d.ethernet.vlan_id ? `<div class="proto-field-row"><span class="proto-field-key">802.1Q VLAN ID:</span><span class="proto-field-val">${d.ethernet.vlan_id}</span></div>` : ''}
    `;
  } else {
    elements.modalEthContent.innerHTML = '<span class="text-dim">No Ethernet Header (Raw IP / SLL)</span>';
  }

  // IP
  if (d.ip) {
    elements.modalIpContent.innerHTML = `
      <div class="proto-field-row"><span class="proto-field-key">IP Version:</span><span class="proto-field-val">IPv${d.ip.version}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Source IP:</span><span class="proto-field-val">${d.ip.src_ip}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Destination IP:</span><span class="proto-field-val">${d.ip.dst_ip}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Protocol:</span><span class="proto-field-val">${d.ip.proto_name} (${d.ip.proto})</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Time to Live (TTL):</span><span class="proto-field-val">${d.ip.ttl}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Total Length:</span><span class="proto-field-val">${d.ip.total_length} bytes</span></div>
    `;
  }

  // TCP
  if (d.tcp) {
    let optsHtml = '';
    if (d.tcp.options && d.tcp.options.length > 0) {
      optsHtml = '<div style="margin-top: 8px; border-top: 1px solid var(--border-subtle); padding-top: 6px;"><strong>TCP Options:</strong>';
      d.tcp.options.forEach(opt => {
        optsHtml += `<div class="proto-field-row" style="font-size: 11px;"><span class="proto-field-key">• ${opt.name} (${opt.length}B):</span><span class="proto-field-val">${JSON.stringify(opt.decoded) || 'Present'}</span></div>`;
      });
      optsHtml += '</div>';
    }

    elements.modalTcpContent.innerHTML = `
      <div class="proto-field-row"><span class="proto-field-key">Source Port:</span><span class="proto-field-val">${d.tcp.src_port}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Destination Port:</span><span class="proto-field-val">${d.tcp.dst_port}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Sequence Number:</span><span class="proto-field-val">${d.tcp.seq_num}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Acknowledgment Number:</span><span class="proto-field-val">${d.tcp.ack_num}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">TCP Flags:</span><span class="proto-field-val" style="color: var(--color-primary);">${d.tcp.flags_str}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Window Size:</span><span class="proto-field-val">${d.tcp.window_size}</span></div>
      <div class="proto-field-row"><span class="proto-field-key">Payload Length:</span><span class="proto-field-val">${d.tcp.payload_len} bytes</span></div>
      ${optsHtml}
    `;
  }

  // Hex Dump
  elements.modalHexDumpViewer.innerText = d.hex_dump || 'No payload bytes';
}

function closeModal() {
  elements.packetModalBackdrop.classList.remove('open');
}
