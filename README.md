# CyberSOC - Security Operations Center Dashboard 🛡️

**CyberSOC** is a professional, full-featured Security Operations Center (SOC) dashboard web application built with **Python**, **Flask**, **SQLite**, **Chart.js**, and **ReportLab**. 

Designed specifically for cybersecurity interns, SOC analysts, and security enthusiasts, CyberSOC provides real-time log ingestion, automated rule-based threat detection, incident triage, forensic payload inspection, SOC playbook response guidelines, and downloadable executive PDF security audit reports.

---

## 🌟 Key Features

1. **Dark CyberSOC Dashboard**:
   - High-impact dark theme UI with glowing status indicators and live SOC monitoring feed.
   - 5 Key Security Metric Counters: Total Ingested Logs, Critical Alerts, High Risk Alerts, Medium Risk Alerts, and Low Risk Alerts.
   - Dynamic Chart.js Analytics:
     - **Alert Severity Breakdown** (Doughnut Chart)
     - **Security Telemetry Activity Timeline** (Line Chart)
     - **Top Attack Vectors Category Distribution** (Bar Chart)
     - **Top Suspicious Source IPs** (Horizontal Bar Chart)

2. **Automated Rule-Based Threat Detection Engine (`detector.py`)**:
   - **SQL Injection (SQLi)**: Identifies patterns like `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`, `BENCHMARK()`, `SLEEP()`.
   - **Cross-Site Scripting (XSS)**: Identifies `<script>` tags, `document.cookie`, `onload=`, `onerror=`, `javascript:` payloads.
   - **Brute Force Authentication Attacks**: Detects repeated SSH/web login failures and credential stuffing patterns.
   - **Port Scanning Reconnaissance**: Identifies Nmap SYN scans, sequential TCP port probes, and masscan sweeps.
   - **Suspicious Login Attempts**: Detects root logins outside business hours, unverified external admin access, and privilege escalation.
   - **Suspicious IP / Malicious Activity**: Flags TOR Exit Node connections, known C2 server subnets, and reverse shell beacons.

3. **Log Telemetry Management & Interactive Payload Analyzer**:
   - Ingests raw syslog, web access logs, and security events into SQLite.
   - Interactive Live Log Analyzer with 6 Preset Attack Simulations:
     - *SQL Injection Attack*
     - *XSS Script Payload*
     - *SSH Brute Force*
     - *Nmap Port Scan*
     - *C2 IP Beacon*
     - *Clean System Log*

4. **Security Threat Alerts Matrix & Investigation**:
   - Comprehensive alerts list with severity filters (*Critical, High, Medium, Low*) and status triage (*New, Investigating, Resolved*).
   - Dedicated Alert Investigation Page (`/alerts/<id>`) detailing:
     - Alert Type & Severity Badge
     - Attacker Source IP & Target Host IP
     - Detection Timestamp & Category
     - Intercepted Raw Payload Code Box
     - **Recommended SOC Playbook Response Actions & Analyst Checklist**

5. **Executive PDF Report Generator**:
   - Standalone PDF report module built using **ReportLab**.
   - Generates downloadable Executive Security Audit Reports featuring telemetry metrics, top incident tables, and mitigation recommendations.

6. **Auto-Seeding Realistic Sample Security Telemetry**:
   - On first run, CyberSOC automatically initializes the SQLite database (`cybersoc.db`) and populates 20+ realistic security events spanning web attacks, SSH brute-force attempts, and clean traffic.

---

## 📂 Project Architecture

```
CyberSOC/
│── app.py                  # Main Flask Web Application & Routing Endpoints
│── database.py             # SQLite DB Handler, Queries, & Sample Data Seeder
│── detector.py             # Rule-Based Threat Detection Engine
│── report_generator.py     # ReportLab Executive PDF Report Generator
│── requirements.txt        # Python Dependencies (Flask, ReportLab)
│── README.md               # Documentation & Setup Guide
├── templates/
│   ├── base.html           # Master HTML Layout with Navbar & Footer
│   ├── dashboard.html      # Main SOC Dashboard (Stats, Chart.js, Alerts Table)
│   ├── logs.html           # Log Telemetry Feed & Live Threat Analyzer
│   ├── alerts.html         # Threat Alerts Matrix & Status Triage
│   ├── alert_detail.html   # Detailed Alert Investigation & Playbook View
│   └── reports.html        # Executive PDF Reports & Audit Summary
└── static/
    ├── css/
    │   └── style.css       # Custom Dark Cybersecurity SOC CSS System
    └── js/
        ├── dashboard.js    # Chart.js Renderers & REST API Fetcher
        └── main.js         # Log Analyzer Presets & Interactive UI Logic
```

---

## 🛠️ Installation & Setup Guide

### 1. Prerequisites
Ensure you have **Python 3.8+** installed on your system.

### 2. Navigate to Project Directory
```bash
cd CyberSOC
```

### 3. (Optional) Create & Activate Virtual Environment
- **Windows**:
  ```bash
  python -m venv venv
  venv\Scripts\activate
  ```
- **macOS / Linux**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Running the CyberSOC Application

To launch the CyberSOC web server, execute:

```bash
python app.py
```

Output:
```
==========================================================
 CyberSOC - Cybersecurity Operations Center Dashboard 
 Listening on http://127.0.0.1:5000
==========================================================
```

Open your web browser and navigate to:
👉 **`http://127.0.0.1:5000`**

---

## 💻 Tech Stack Summary

| Layer | Technology |
|---|---|
| **Backend Framework** | Python 3, Flask 3.0 |
| **Database** | SQLite 3 (`cybersoc.db`) |
| **Detection Engine** | Custom Regular Expression & Heuristic Engine (`detector.py`) |
| **PDF Generation** | ReportLab 4.2 |
| **Frontend UI** | HTML5, Modern CSS3 (Dark Theme), Vanilla JavaScript (ES6) |
| **Data Visualization** | Chart.js (CDN) |
| **Icons & Typography** | FontAwesome 6.5, Google Fonts (*Inter, JetBrains Mono*) |

---

## 📜 License & Usage Notice
This project is built for educational, portfolio, and Cybersecurity Internship demonstration purposes.
