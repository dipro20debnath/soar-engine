/**
 * SOAR Engine — SOC Dashboard JavaScript
 *
 * Fetches live data from the SOAR API and updates the dashboard:
 *   - Stats overview (total alerts, critical, blocked IPs, etc.)
 *   - Charts (severity distribution, alert types, pipeline status)
 *   - Recent alerts table with filtering
 *   - Containment status (firewall, isolator, notifications)
 *   - Blocked IPs list with unblock actions
 *   - Pending approvals with approve/reject buttons
 *   - Playbook execution history
 *   - Alert detail modal
 *   - Toast notifications
 *   - Auto-refresh every 10 seconds
 */

const API_BASE = window.location.origin;
const REFRESH_INTERVAL = 10000; // 10 seconds

// ── Chart instances ────────────────────────────────
let chartSeverity = null;
let chartType = null;
let chartStatus = null;

// ── Chart.js Global Config ─────────────────────────
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.plugins.legend.labels.padding = 12;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.legend.labels.pointStyleWidth = 8;

// ── Severity color map ─────────────────────────────
const SEVERITY_COLORS = {
    critical: { bg: 'rgba(239, 68, 68, 0.8)', border: '#ef4444' },
    high:     { bg: 'rgba(249, 115, 22, 0.8)', border: '#f97316' },
    medium:   { bg: 'rgba(234, 179, 8, 0.8)',  border: '#eab308' },
    low:      { bg: 'rgba(34, 197, 94, 0.8)',   border: '#22c55e' },
    info:     { bg: 'rgba(59, 130, 246, 0.8)',   border: '#3b82f6' },
};

const TYPE_COLORS = {
    brute_force:       { bg: 'rgba(239, 68, 68, 0.7)',  border: '#ef4444' },
    malware_detected:  { bg: 'rgba(168, 85, 247, 0.7)', border: '#a855f7' },
    suspicious_login:  { bg: 'rgba(249, 115, 22, 0.7)', border: '#f97316' },
    port_scan:         { bg: 'rgba(6, 182, 212, 0.7)',   border: '#06b6d4' },
    data_exfiltration: { bg: 'rgba(236, 72, 153, 0.7)', border: '#ec4899' },
    phishing:          { bg: 'rgba(234, 179, 8, 0.7)',   border: '#eab308' },
    unknown:           { bg: 'rgba(100, 116, 139, 0.7)', border: '#64748b' },
};

const STATUS_COLORS = {
    new:              { bg: 'rgba(99, 102, 241, 0.7)',  border: '#6366f1' },
    normalized:       { bg: 'rgba(148, 163, 184, 0.7)', border: '#94a3b8' },
    enriched:         { bg: 'rgba(6, 182, 212, 0.7)',   border: '#06b6d4' },
    responded:        { bg: 'rgba(16, 185, 129, 0.7)',  border: '#10b981' },
    pending_approval: { bg: 'rgba(245, 158, 11, 0.7)',  border: '#f59e0b' },
    closed:           { bg: 'rgba(100, 116, 139, 0.7)', border: '#64748b' },
};


// ═══════════════════════════════════════════════════
// API Fetch Helpers
// ═══════════════════════════════════════════════════

async function fetchJSON(endpoint) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`[API] Failed to fetch ${endpoint}:`, error);
        return null;
    }
}

async function postJSON(endpoint) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        });
        return await response.json();
    } catch (error) {
        console.error(`[API] Failed to POST ${endpoint}:`, error);
        return null;
    }
}


// ═══════════════════════════════════════════════════
// Stats Overview
// ═══════════════════════════════════════════════════

async function updateStats() {
    const [stats, containment, pending] = await Promise.all([
        fetchJSON('/api/stats'),
        fetchJSON('/api/containment/summary'),
        fetchJSON('/api/playbooks/pending'),
    ]);

    if (stats) {
        animateValue('statTotalAlerts', stats.total_alerts || 0);
        animateValue('statCritical', (stats.by_severity?.critical || 0) + (stats.by_severity?.high || 0));
        animateValue('statAvgRisk', stats.avg_risk_score != null ? stats.avg_risk_score.toFixed(1) : '—');
    }

    if (containment) {
        animateValue('statBlockedIPs', containment.firewall?.blocked_ips || 0);
        animateValue('statIsolated', containment.isolation?.isolated_instances || 0);
        animateValue('fwBlockedCount', `${containment.firewall?.blocked_ips || 0} IPs`);
        animateValue('isoCount', `${containment.isolation?.isolated_instances || 0} hosts`);
        animateValue('notifCount', containment.notifications?.total_sent || 0);
        animateValue('playbookExecCount', containment.playbooks?.total_executions || 0);
    }

    if (pending) {
        animateValue('statPending', pending.total || 0);
        document.getElementById('pendingBadge').textContent = pending.total || 0;
    }
}

function animateValue(elementId, value) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = value;
    el.style.animation = 'none';
    el.offsetHeight; // Trigger reflow
    el.style.animation = 'countUp 0.3s ease';
}


// ═══════════════════════════════════════════════════
// Charts
// ═══════════════════════════════════════════════════

async function updateCharts() {
    const stats = await fetchJSON('/api/stats');
    if (!stats) return;

    updateSeverityChart(stats.by_severity || {});
    updateTypeChart(stats.by_type || {});
    updateStatusChart(stats.by_status || {});
}

function updateSeverityChart(data) {
    const labels = Object.keys(data);
    const values = Object.values(data);
    const bgColors = labels.map(l => (SEVERITY_COLORS[l]?.bg || 'rgba(100,116,139,0.7)'));
    const borderColors = labels.map(l => (SEVERITY_COLORS[l]?.border || '#64748b'));

    const chartData = {
        labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
        datasets: [{
            data: values,
            backgroundColor: bgColors,
            borderColor: borderColors,
            borderWidth: 2,
            hoverBorderWidth: 3,
        }],
    };

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: 'bottom', labels: { padding: 10, font: { size: 11 } } },
        },
        cutout: '60%',
    };

    if (chartSeverity) {
        chartSeverity.data = chartData;
        chartSeverity.update('none');
    } else {
        chartSeverity = new Chart(
            document.getElementById('chartSeverity'),
            { type: 'doughnut', data: chartData, options }
        );
    }
}

function updateTypeChart(data) {
    const labels = Object.keys(data);
    const values = Object.values(data);
    const bgColors = labels.map(l => (TYPE_COLORS[l]?.bg || 'rgba(100,116,139,0.7)'));
    const borderColors = labels.map(l => (TYPE_COLORS[l]?.border || '#64748b'));

    const displayLabels = labels.map(l =>
        l.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
    );

    const chartData = {
        labels: displayLabels,
        datasets: [{
            data: values,
            backgroundColor: bgColors,
            borderColor: 'transparent',
            borderWidth: 0,
            borderRadius: 4,
            barThickness: 24,
        }],
    };

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
            x: {
                grid: { color: 'rgba(99,102,241,0.06)' },
                ticks: { stepSize: 1 },
            },
            y: {
                grid: { display: false },
                ticks: { font: { size: 11 } },
            },
        },
    };

    if (chartType) {
        chartType.data = chartData;
        chartType.update('none');
    } else {
        chartType = new Chart(
            document.getElementById('chartType'),
            { type: 'bar', data: chartData, options }
        );
    }
}

function updateStatusChart(data) {
    const labels = Object.keys(data);
    const values = Object.values(data);
    const bgColors = labels.map(l => (STATUS_COLORS[l]?.bg || 'rgba(100,116,139,0.7)'));
    const borderColors = labels.map(l => (STATUS_COLORS[l]?.border || '#64748b'));

    const displayLabels = labels.map(l =>
        l.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
    );

    const chartData = {
        labels: displayLabels,
        datasets: [{
            data: values,
            backgroundColor: bgColors,
            borderColor: borderColors,
            borderWidth: 2,
        }],
    };

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: 'bottom', labels: { padding: 10, font: { size: 11 } } },
        },
        cutout: '55%',
    };

    if (chartStatus) {
        chartStatus.data = chartData;
        chartStatus.update('none');
    } else {
        chartStatus = new Chart(
            document.getElementById('chartStatus'),
            { type: 'doughnut', data: chartData, options }
        );
    }
}


// ═══════════════════════════════════════════════════
// Alerts Table
// ═══════════════════════════════════════════════════

async function updateAlertsTable() {
    const severityFilter = document.getElementById('filterSeverity').value;
    const typeFilter = document.getElementById('filterType').value;

    let endpoint = '/api/alerts?limit=20';
    if (severityFilter) endpoint += `&severity=${severityFilter}`;
    if (typeFilter) endpoint += `&alert_type=${typeFilter}`;

    const alerts = await fetchJSON(endpoint);
    if (!alerts) return;

    const tbody = document.getElementById('alertsTableBody');

    if (alerts.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="7">
                    <div class="empty-state">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        <p>No alerts match the current filters</p>
                    </div>
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(alert => {
        const time = new Date(alert.timestamp).toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
        });
        const date = new Date(alert.timestamp).toLocaleDateString('en-US', {
            month: 'short', day: 'numeric'
        });
        const risk = alert.risk_score;
        const riskColor = risk > 80 ? '#ef4444' : risk > 60 ? '#f97316' : risk > 30 ? '#eab308' : '#22c55e';
        const riskWidth = risk != null ? Math.min(risk, 100) : 0;

        return `
            <tr>
                <td>
                    <div style="line-height:1.3">
                        <div style="font-weight:500;color:var(--text-primary)">${time}</div>
                        <div style="font-size:0.7rem;color:var(--text-muted)">${date}</div>
                    </div>
                </td>
                <td><span class="type-label">${alert.alert_type}</span></td>
                <td><span class="badge badge-${alert.severity}">${alert.severity}</span></td>
                <td><span class="ip-address">${alert.source_ip || '—'}</span></td>
                <td>
                    ${risk != null ? `
                        <div class="risk-bar">
                            <div class="risk-bar-track">
                                <div class="risk-bar-fill" style="width:${riskWidth}%;background:${riskColor}"></div>
                            </div>
                            <span class="risk-bar-value" style="color:${riskColor}">${risk.toFixed(0)}</span>
                        </div>
                    ` : '<span style="color:var(--text-muted)">—</span>'}
                </td>
                <td><span class="badge badge-${alert.status}">${alert.status.replace('_', ' ')}</span></td>
                <td><button class="btn-action" onclick="viewAlert('${alert.alert_id}')">View</button></td>
            </tr>`;
    }).join('');
}


// ═══════════════════════════════════════════════════
// Blocked IPs List
// ═══════════════════════════════════════════════════

async function updateBlockedIPs() {
    const data = await fetchJSON('/api/containment/blocklist');
    if (!data) return;

    const container = document.getElementById('blockedIPsList');
    const badge = document.getElementById('blockedBadge');
    badge.textContent = data.blocked_count;

    if (data.blocked_count === 0) {
        container.innerHTML = '<div class="empty-state small"><p>No IPs blocked</p></div>';
        return;
    }

    container.innerHTML = Object.entries(data.blocklist).map(([ip, info]) =>
        `<div class="blocked-ip-item">
            <span>${ip}</span>
            <button class="btn-action unblock" onclick="unblockIP('${ip}')">Unblock</button>
        </div>`
    ).join('');
}


// ═══════════════════════════════════════════════════
// Pending Approvals
// ═══════════════════════════════════════════════════

async function updatePendingApprovals() {
    const data = await fetchJSON('/api/playbooks/pending');
    if (!data) return;

    const container = document.getElementById('pendingList');

    if (data.total === 0) {
        container.innerHTML = '<div class="empty-state small"><p>No pending approvals</p></div>';
        return;
    }

    container.innerHTML = data.pending.map(item => {
        const shortId = item.alert_id.substring(0, 8);
        const actions = item.pending_actions.join(', ');
        return `
            <div class="pending-item">
                <div class="pending-item-header">
                    <span class="pending-item-id">${shortId}...</span>
                    <span class="pending-item-risk">Risk: ${item.risk_score.toFixed(0)}</span>
                </div>
                <div class="pending-item-actions">${actions}</div>
                <div class="pending-item-buttons">
                    <button class="btn-action approve" onclick="approveAlert('${item.alert_id}')">✓ Approve</button>
                    <button class="btn-action reject" onclick="rejectAlert('${item.alert_id}')">✗ Reject</button>
                </div>
            </div>`;
    }).join('');
}


// ═══════════════════════════════════════════════════
// Playbook History
// ═══════════════════════════════════════════════════

async function updatePlaybookHistory() {
    const data = await fetchJSON('/api/playbooks/history?limit=15');
    if (!data) return;

    const tbody = document.getElementById('historyTableBody');

    if (data.total === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="6"><div class="empty-state"><p>No playbook executions yet</p></div></td>
            </tr>`;
        return;
    }

    tbody.innerHTML = data.history.map(exec => {
        const time = new Date(exec.executed_at).toLocaleString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false
        });
        const shortId = exec.alert_id.substring(0, 8);
        const actionStr = exec.actions.slice(0, 3).join(', ');
        const more = exec.actions.length > 3 ? ` +${exec.actions.length - 3}` : '';
        const riskColor = exec.risk_score > 80 ? '#ef4444' : exec.risk_score > 60 ? '#f97316' : exec.risk_score > 30 ? '#eab308' : '#22c55e';

        return `
            <tr>
                <td>${time}</td>
                <td><span class="ip-address" style="cursor:pointer" onclick="viewAlert('${exec.alert_id}')">${shortId}...</span></td>
                <td><span class="type-label">${exec.playbook_name}</span></td>
                <td><span style="font-family:var(--font-mono);color:${riskColor};font-weight:600">${exec.risk_score.toFixed(0)}</span></td>
                <td><span class="badge badge-${exec.status}">${exec.status}</span></td>
                <td class="actions-cell">${actionStr}${more}</td>
            </tr>`;
    }).join('');
}


// ═══════════════════════════════════════════════════
// Alert Detail Modal
// ═══════════════════════════════════════════════════

async function viewAlert(alertId) {
    const alert = await fetchJSON(`/api/alerts/${alertId}`);
    if (!alert) {
        showToast('Alert not found', 'error');
        return;
    }

    const modal = document.getElementById('alertModal');
    const body = document.getElementById('modalBody');

    const risk = alert.risk_score;
    const riskColor = risk > 80 ? '#ef4444' : risk > 60 ? '#f97316' : risk > 30 ? '#eab308' : '#22c55e';

    body.innerHTML = `
        <div class="modal-field">
            <div class="modal-field-label">Alert ID</div>
            <div class="modal-field-value mono">${alert.alert_id}</div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
            <div class="modal-field">
                <div class="modal-field-label">Type</div>
                <div class="modal-field-value"><span class="type-label">${alert.alert_type}</span></div>
            </div>
            <div class="modal-field">
                <div class="modal-field-label">Severity</div>
                <div class="modal-field-value"><span class="badge badge-${alert.severity}">${alert.severity}</span></div>
            </div>
            <div class="modal-field">
                <div class="modal-field-label">Status</div>
                <div class="modal-field-value"><span class="badge badge-${alert.status}">${alert.status}</span></div>
            </div>
            <div class="modal-field">
                <div class="modal-field-label">Risk Score</div>
                <div class="modal-field-value" style="color:${riskColor};font-weight:700;font-family:var(--font-mono)">
                    ${risk != null ? risk.toFixed(1) : '—'}
                </div>
            </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
            <div class="modal-field">
                <div class="modal-field-label">Source IP</div>
                <div class="modal-field-value mono">${alert.source_ip || '—'}</div>
            </div>
            <div class="modal-field">
                <div class="modal-field-label">Target Host</div>
                <div class="modal-field-value mono">${alert.target_host || '—'}</div>
            </div>
        </div>
        <div class="modal-field">
            <div class="modal-field-label">Description</div>
            <div class="modal-field-value">${alert.description || 'No description'}</div>
        </div>
        <div class="modal-field">
            <div class="modal-field-label">SIEM Source</div>
            <div class="modal-field-value">${alert.siem_source}</div>
        </div>
        ${alert.playbook_name ? `
            <div class="modal-field">
                <div class="modal-field-label">Playbook</div>
                <div class="modal-field-value"><span class="type-label">${alert.playbook_name}</span></div>
            </div>
        ` : ''}
        ${alert.response_actions && alert.response_actions.length > 0 ? `
            <div class="modal-field">
                <div class="modal-field-label">Response Actions</div>
                <ul class="modal-actions-list">
                    ${alert.response_actions.map(a => `<li>${a}</li>`).join('')}
                </ul>
            </div>
        ` : ''}
        ${alert.iocs && alert.iocs.length > 0 ? `
            <div class="modal-field">
                <div class="modal-field-label">Indicators of Compromise (${alert.iocs.length})</div>
                <ul class="modal-actions-list">
                    ${alert.iocs.map(ioc => `<li><strong>${ioc.ioc_type}:</strong> ${ioc.value}</li>`).join('')}
                </ul>
            </div>
        ` : ''}
        ${alert.tags && alert.tags.length > 0 ? `
            <div class="modal-field">
                <div class="modal-field-label">Tags</div>
                <div style="display:flex;gap:0.3rem;flex-wrap:wrap">
                    ${alert.tags.map(t => `<span class="badge badge-info">${t}</span>`).join('')}
                </div>
            </div>
        ` : ''}
    `;

    modal.classList.add('active');
}


// ═══════════════════════════════════════════════════
// Actions
// ═══════════════════════════════════════════════════

async function approveAlert(alertId) {
    const result = await postJSON(`/api/playbooks/approve/${alertId}`);
    if (result && result.success) {
        showToast(`Alert ${alertId.substring(0, 8)}... APPROVED`, 'success');
        refreshAll();
    } else {
        showToast('Failed to approve alert', 'error');
    }
}

async function rejectAlert(alertId) {
    const result = await postJSON(`/api/playbooks/reject/${alertId}`);
    if (result && result.success) {
        showToast(`Alert ${alertId.substring(0, 8)}... REJECTED`, 'warning');
        refreshAll();
    } else {
        showToast('Failed to reject alert', 'error');
    }
}

async function unblockIP(ip) {
    const result = await postJSON(`/api/containment/unblock/${ip}`);
    if (result && result.success) {
        showToast(`IP ${ip} unblocked`, 'success');
        refreshAll();
    } else {
        showToast(`Failed to unblock ${ip}`, 'error');
    }
}

async function sendTestAlert() {
    const types = ['brute_force', 'malware_detected', 'suspicious_login', 'port_scan', 'data_exfiltration'];
    const severities = ['low', 'medium', 'high', 'critical'];
    const ips = ['103.24.55.12', '185.220.101.45', '45.33.32.156', '91.198.174.192', '77.88.55.66'];

    const payload = {
        source: 'generic',
        payload: {
            alert_type: types[Math.floor(Math.random() * types.length)],
            severity: severities[Math.floor(Math.random() * severities.length)],
            source_ip: ips[Math.floor(Math.random() * ips.length)],
            target_host: `web-server-${String(Math.floor(Math.random() * 5) + 1).padStart(2, '0')}`,
            description: `Simulated alert from SOC Dashboard at ${new Date().toISOString()}`,
        },
    };

    try {
        const response = await fetch(`${API_BASE}/api/alerts`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (data.success) {
            showToast(`Test alert sent: ${data.alert_type} (${data.severity})`, 'success');
            refreshAll();
        }
    } catch (error) {
        showToast('Failed to send test alert', 'error');
    }
}


// ═══════════════════════════════════════════════════
// Toast Notifications
// ═══════════════════════════════════════════════════

function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    const icons = { success: '✓', error: '✗', warning: '⚠' };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ'}</span>
        <span>${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('hiding');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}


// ═══════════════════════════════════════════════════
// Clock
// ═══════════════════════════════════════════════════

function updateClock() {
    const el = document.getElementById('liveClock');
    if (el) {
        el.textContent = new Date().toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
        });
    }
}


// ═══════════════════════════════════════════════════
// Refresh All
// ═══════════════════════════════════════════════════

async function refreshAll() {
    await Promise.all([
        updateStats(),
        updateCharts(),
        updateAlertsTable(),
        updateBlockedIPs(),
        updatePendingApprovals(),
        updatePlaybookHistory(),
    ]);
}


// ═══════════════════════════════════════════════════
// Event Listeners & Initialization
// ═══════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    // Initial load
    refreshAll();
    updateClock();

    // Auto-refresh
    setInterval(refreshAll, REFRESH_INTERVAL);
    setInterval(updateClock, 1000);

    // Button handlers
    document.getElementById('btnRefresh').addEventListener('click', () => {
        showToast('Dashboard refreshed', 'success');
        refreshAll();
    });

    document.getElementById('btnSimulate').addEventListener('click', sendTestAlert);

    // Filter change handlers
    document.getElementById('filterSeverity').addEventListener('change', updateAlertsTable);
    document.getElementById('filterType').addEventListener('change', updateAlertsTable);

    // Modal close
    document.getElementById('modalClose').addEventListener('click', () => {
        document.getElementById('alertModal').classList.remove('active');
    });
    document.getElementById('alertModal').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) {
            e.currentTarget.classList.remove('active');
        }
    });

    // Keyboard shortcut
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.getElementById('alertModal').classList.remove('active');
        }
    });
});
