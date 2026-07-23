/**
 * CyberSOC Dashboard - Live Auto-Sync Chart.js & Statistics Handler
 */

const chartInstances = {};
let autoRefreshTimer = null;

document.addEventListener('DOMContentLoaded', function() {
    refreshDashboardData();
    // Poll SQLite database stats & charts every 3 seconds
    autoRefreshTimer = setInterval(refreshDashboardData, 3000);
});

async function refreshDashboardData() {
    await Promise.all([
        fetchStatsData(),
        fetchChartData(),
        fetchRecentAlertsData()
    ]);
}

/**
 * Fetches and updates top stat counters dynamically
 */
async function fetchStatsData() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) return;
        const stats = await response.json();

        updateStatElement('stat-total-logs', stats.total_logs);
        updateStatElement('stat-critical-alerts', stats.critical_alerts);
        updateStatElement('stat-high-alerts', stats.high_alerts);
        updateStatElement('stat-medium-alerts', stats.medium_alerts);
        updateStatElement('stat-low-alerts', stats.low_alerts);
    } catch (err) {
        console.error('Error fetching live stats:', err);
    }
}

function updateStatElement(elementId, newValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const currentVal = el.innerText.trim();
    if (currentVal !== String(newValue)) {
        el.innerText = newValue;
        // Subtle highlight pulse when value changes
        el.style.transition = 'color 0.3s ease, transform 0.3s ease';
        el.style.transform = 'scale(1.1)';
        setTimeout(() => {
            el.style.transform = 'scale(1)';
        }, 300);
    }
}

/**
 * Fetches and updates Chart.js charts dynamically
 */
async function fetchChartData() {
    try {
        const response = await fetch('/api/chart-data');
        if (!response.ok) return;
        const data = await response.json();
        
        renderOrUpdateSeverityChart(data.severity);
        renderOrUpdateTimelineChart(data.timeline);
        renderOrUpdateAttackTypesChart(data.attack_types);
        renderOrUpdateTopIpsChart(data.top_ips);
    } catch (err) {
        console.error('Error fetching CyberSOC chart analytics:', err);
    }
}

function renderOrUpdateSeverityChart(sevData) {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;

    const datasetValues = [
        sevData.Critical || 0,
        sevData.High || 0,
        sevData.Medium || 0,
        sevData.Low || 0
    ];

    if (chartInstances.severity) {
        chartInstances.severity.data.datasets[0].data = datasetValues;
        chartInstances.severity.update();
        return;
    }

    chartInstances.severity = new Chart(ctx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: datasetValues,
                backgroundColor: [
                    '#f43f5e',
                    '#f97316',
                    '#f59e0b',
                    '#10b981'
                ],
                borderWidth: 2,
                borderColor: '#111827'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                }
            },
            cutout: '70%'
        }
    });
}

function renderOrUpdateTimelineChart(timeline) {
    const ctx = document.getElementById('activityTimelineChart');
    if (!ctx) return;

    const labels = timeline.labels.length ? timeline.labels : ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];

    if (chartInstances.timeline) {
        chartInstances.timeline.data.labels = labels;
        chartInstances.timeline.data.datasets[0].data = timeline.total_logs;
        chartInstances.timeline.data.datasets[1].data = timeline.threats;
        chartInstances.timeline.update();
        return;
    }

    chartInstances.timeline = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Logs',
                    data: timeline.total_logs,
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Threat Alerts',
                    data: timeline.threats,
                    borderColor: '#f43f5e',
                    backgroundColor: 'rgba(244, 63, 94, 0.15)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: { color: '#94a3b8' }
                }
            }
        }
    });
}

function renderOrUpdateAttackTypesChart(attackData) {
    const ctx = document.getElementById('attackTypesChart');
    if (!ctx) return;

    const labels = attackData.labels.length ? attackData.labels : ['SQLi', 'Brute Force', 'XSS', 'Port Scan', 'Suspicious IP'];

    if (chartInstances.attackTypes) {
        chartInstances.attackTypes.data.labels = labels;
        chartInstances.attackTypes.data.datasets[0].data = attackData.counts;
        chartInstances.attackTypes.update();
        return;
    }

    chartInstances.attackTypes = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Count',
                data: attackData.counts,
                backgroundColor: 'rgba(2, 132, 199, 0.7)',
                borderColor: '#0284c7',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8', font: { size: 10 } }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function renderOrUpdateTopIpsChart(ipData) {
    const ctx = document.getElementById('topIpsChart');
    if (!ctx) return;

    if (chartInstances.topIps) {
        chartInstances.topIps.data.labels = ipData.labels;
        chartInstances.topIps.data.datasets[0].data = ipData.counts;
        chartInstances.topIps.update();
        return;
    }

    chartInstances.topIps = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ipData.labels,
            datasets: [{
                label: 'Alerts Triggered',
                data: ipData.counts,
                backgroundColor: 'rgba(249, 115, 22, 0.7)',
                borderColor: '#f97316',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' },
                    beginAtZero: true
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#00f2fe', font: { family: 'JetBrains Mono, monospace', size: 11 } }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

/**
 * Fetches and updates the recent threats table dynamically
 */
async function fetchRecentAlertsData() {
    try {
        const response = await fetch('/api/recent-alerts');
        if (!response.ok) return;
        const alerts = await response.json();

        const tbody = document.getElementById('recent-alerts-tbody');
        if (!tbody) return;

        if (!alerts || alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No security threats detected.</td></tr>`;
            return;
        }

        let html = '';
        alerts.forEach(alert => {
            const timeStr = alert.timestamp ? alert.timestamp.substring(0, 19) : '';
            const sevLower = (alert.severity || 'low').toLowerCase();
            const statusLower = (alert.status || 'new').toLowerCase();

            html += `
                <tr>
                    <td style="font-family: var(--font-mono); color: var(--cyber-cyan);">#${alert.id}</td>
                    <td style="font-size: 0.8rem; color: var(--text-secondary);">${timeStr}</td>
                    <td>
                        <strong style="color: var(--text-primary);">${escapeHtml(alert.alert_type)}</strong>
                        <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(alert.category || 'Security')}</div>
                    </td>
                    <td>
                        <span class="badge badge-${sevLower}">
                            ${escapeHtml(alert.severity)}
                        </span>
                    </td>
                    <td><span class="ip-badge">${escapeHtml(alert.source_ip)}</span></td>
                    <td>
                        <span class="badge-status status-${statusLower}">
                            ${escapeHtml(alert.status)}
                        </span>
                    </td>
                    <td>
                        <a href="/alerts/${alert.id}" class="btn btn-secondary btn-sm">
                            <i class="fa-solid fa-eye"></i> Investigate
                        </a>
                    </td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    } catch (err) {
        console.error('Error updating recent alerts table:', err);
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
