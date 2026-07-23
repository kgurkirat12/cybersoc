import re
from datetime import datetime

class ThreatDetector:
    """
    Rule-based Security Operations Center (SOC) Threat Detection Engine.
    Analyzes incoming log lines for malicious activity signatures, attack vectors,
    and suspicious behavioral patterns.
    """

    SQLI_PATTERNS = [
        r"('|\")\s*(or|and)\s*('|\")?1('|\")?\s*=\s*('|\")?1",
        r"union\s+select",
        r"drop\s+table",
        r"insert\s+into",
        r"update\s+.*\s+set",
        r"exec\s*\(",
        r"information_schema",
        r"benchmark\s*\(",
        r"sleep\s*\(",
        r"--;",
        r"'\s*or\s*''='",
        r"select\s+.*\s+from"
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript\s*:",
        r"onload\s*=",
        r"onerror\s*=",
        r"document\.cookie",
        r"alert\s*\(",
        r"eval\s*\(",
        r"<iframe[^>]*>",
        r"window\.location",
        r"<img[^>]+src\s*=\s*[\"']?javascript:"
    ]

    BRUTE_FORCE_KEYWORDS = [
        "failed password",
        "authentication failure",
        "invalid user",
        "login failed",
        "failed login",
        "incorrect password",
        "auth_fail",
        "access denied for user"
    ]

    PORT_SCAN_KEYWORDS = [
        "nmap",
        "port scan",
        "syn flood",
        "sequential connection",
        "masscan",
        "tcp syn probe",
        "probe detected on port"
    ]

    SUSPICIOUS_LOGIN_KEYWORDS = [
        "root login",
        "admin login from external",
        "unauthorized sudo",
        "login outside working hours",
        "privilege escalation attempt",
        "unrecognized location login",
        "concurrent session detected"
    ]

    MALICIOUS_IP_PREFIXES = [
        "185.220.",  # TOR Exit Nodes
        "45.154.",   # Known C2 subnets
        "198.51.100.",
        "194.26.",
        "185.246.",
        "103.152.",
        "45.146."
    ]

    LOW_RISK_KEYWORDS = [
        "ftp connection",
        "telnet connection",
        "deprecated protocol",
        "policy warning",
        "ping sweep",
        "cleartext password",
        "unencrypted traffic"
    ]

    @classmethod
    def analyze_log(cls, raw_log, source_ip="", username="", category=""):
        """
        Scans a raw log string or metadata and returns threat details if detected.
        Accurately assigns severity ratings: Critical, High, Medium, or Low.
        """
        log_lower = raw_log.lower()
        ip_str = str(source_ip or "")
        
        # 1. SQL Injection Check (Critical)
        for pattern in cls.SQLI_PATTERNS:
            if re.search(pattern, log_lower, re.IGNORECASE):
                return {
                    "is_threat": True,
                    "alert_type": "SQL Injection Pattern",
                    "severity": "Critical",
                    "title": f"SQL Injection Attempt from {ip_str or 'Unknown IP'}",
                    "description": f"Potential SQL Injection attack detected in log payload. Signature pattern matched.",
                    "recommended_action": "Block source IP at WAF/Firewall immediately. Sanitize database queries using parameterized statements and inspect web application logs.",
                    "category": "Web Security"
                }

        # 2. Malicious IP / C2 Check (Critical or High)
        is_malicious_ip = any(ip_str.startswith(prefix) for prefix in cls.MALICIOUS_IP_PREFIXES) or "tor exit node" in log_lower or "c2 server" in log_lower
        if is_malicious_ip:
            is_critical = "c2" in log_lower or "reverse shell" in log_lower
            return {
                "is_threat": True,
                "alert_type": "Suspicious IP Activity",
                "severity": "Critical" if is_critical else "High",
                "title": f"Malicious IP Activity ({ip_str})",
                "description": f"Traffic detected originating from known malicious IP subnet or TOR Exit Node ({ip_str}).",
                "recommended_action": "Immediately add IP to border firewall drop list. Check active network connections on internal hosts for outbound C2 beacons.",
                "category": "Network Security"
            }

        # 3. XSS Check (High)
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, log_lower, re.IGNORECASE):
                return {
                    "is_threat": True,
                    "alert_type": "XSS Pattern",
                    "severity": "High",
                    "title": f"Cross-Site Scripting (XSS) Payload Detected",
                    "description": f"Executable client-side script payload identified in web traffic log.",
                    "recommended_action": "Enable Content Security Policy (CSP) headers, sanitize user inputs using HTML encoding, and inspect frontend form endpoints.",
                    "category": "Web Security"
                }

        # 4. Brute Force Check (High or Medium)
        is_brute_force = any(kw in log_lower for kw in cls.BRUTE_FORCE_KEYWORDS) or "multiple failed logins" in log_lower
        if is_brute_force:
            severity = "High" if ("root" in log_lower or "admin" in log_lower) else "Medium"
            return {
                "is_threat": True,
                "alert_type": "Brute Force Attack",
                "severity": severity,
                "title": f"Authentication Brute Force from {ip_str or 'Unknown IP'}",
                "description": f"Repeated failed authentication attempts detected targeting user '{username or 'unknown'}'. Possible automated credential stuffing or dictionary attack.",
                "recommended_action": "Enforce account lockouts after 5 failed attempts, enable Multi-Factor Authentication (MFA), and block IP rate limits in Fail2ban.",
                "category": "Authentication"
            }

        # 5. Suspicious Login Attempt Check (High or Medium)
        is_suspicious_login = any(kw in log_lower for kw in cls.SUSPICIOUS_LOGIN_KEYWORDS)
        if is_suspicious_login:
            severity = "High" if "root" in log_lower else "Medium"
            return {
                "is_threat": True,
                "alert_type": "Suspicious Login Attempt",
                "severity": severity,
                "title": f"Suspicious Privileged Access ({username or 'User'})",
                "description": f"Anomalous access pattern or administrative login detected: {raw_log}",
                "recommended_action": "Verify session legitimacy with account owner. Audit PAM authentication logs and revoke active session tokens if unconfirmed.",
                "category": "Authentication"
            }

        # 6. Port Scanning Activity Check (Medium)
        is_port_scan = any(kw in log_lower for kw in cls.PORT_SCAN_KEYWORDS)
        if is_port_scan:
            return {
                "is_threat": True,
                "alert_type": "Port Scanning Activity",
                "severity": "Medium",
                "title": f"Reconnaissance Port Scan Detected from {ip_str or 'Remote Host'}",
                "description": f"Sequential TCP/UDP connection probes observed across multiple network ports. Indicates reconnaissance activity prior to exploitation.",
                "recommended_action": "Verify firewall rules, hide unnecessary open ports behind VPN, and temporarily throttle connections from source IP.",
                "category": "Network Security"
            }

        # 7. Low Risk / Policy Warning Check (Low)
        is_low_risk = any(kw in log_lower for kw in cls.LOW_RISK_KEYWORDS)
        if is_low_risk:
            return {
                "is_threat": True,
                "alert_type": "Policy Warning",
                "severity": "Low",
                "title": f"Security Policy Warning ({ip_str or 'Internal Host'})",
                "description": f"Use of unencrypted or deprecated communication protocol identified: {raw_log}",
                "recommended_action": "Migrate traffic to encrypted protocols (SSH/HTTPS). Audit network compliance policies.",
                "category": category or "System"
            }

        # Default: Normal / Clean Log
        return {
            "is_threat": False,
            "alert_type": "None",
            "severity": "Info",
            "title": "Normal Log Event",
            "description": "Log payload verified clean; no known attack signatures or threat indicators detected.",
            "recommended_action": "No immediate SOC response required. Maintain routine monitoring.",
            "category": category or "System"
        }
