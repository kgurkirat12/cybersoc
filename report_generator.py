import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from database import get_dashboard_stats, get_all_alerts

def generate_pdf_report():
    """
    Generates a professional SOC Security Summary PDF report using ReportLab
    and returns it as an in-memory BytesIO buffer.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Report Colors
    PRIMARY_COLOR = colors.HexColor('#0f172a')   # Dark Slate
    ACCENT_CYAN = colors.HexColor('#0284c7')     # Cyan / Sky
    CRITICAL_RED = colors.HexColor('#dc2626')    # Red
    HIGH_ORANGE = colors.HexColor('#ea580c')     # Orange
    MEDIUM_YELLOW = colors.HexColor('#d97706')   # Yellow
    TEXT_DARK = colors.HexColor('#1e293b')

    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=PRIMARY_COLOR,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=12
    )

    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=ACCENT_CYAN,
        spaceBefore=14,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=TEXT_DARK,
        spaceAfter=8
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        textColor=colors.white
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=TEXT_DARK
    )

    elements = []

    # 1. Header Banner & Title
    elements.append(Paragraph("CYBERSOC EXECUTIVE SECURITY INCIDENT REPORT", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Prepared by: CyberSOC Operations Team", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=ACCENT_CYAN, spaceAfter=14))

    # 2. Executive Summary
    elements.append(Paragraph("1. Executive Threat Summary", heading_style))
    summary_text = (
        "This security report provides an overview of log telemetry, intrusion detection events, "
        "and threat analytics captured by the CyberSOC Operations Dashboard. "
        "During the evaluated period, automated threat detectors actively scanned network, endpoint, "
        "and web application logs for signatures matching SQL Injection, Cross-Site Scripting (XSS), "
        "Brute Force attacks, Reconnaissance Port Scans, and malicious IP activity."
    )
    elements.append(Paragraph(summary_text, body_style))

    # 3. Security Metrics Table
    stats = get_dashboard_stats()
    metrics_data = [
        [
            Paragraph("<b>Total Telemetry Logs</b>", table_cell_style),
            Paragraph(str(stats['total_logs']), table_cell_style),
            Paragraph("<b>Total Security Alerts</b>", table_cell_style),
            Paragraph(str(stats['total_alerts']), table_cell_style)
        ],
        [
            Paragraph("<b>Critical Risk Alerts</b>", table_cell_style),
            Paragraph(f"<font color='#dc2626'><b>{stats['critical_alerts']}</b></font>", table_cell_style),
            Paragraph("<b>High Risk Alerts</b>", table_cell_style),
            Paragraph(f"<font color='#ea580c'><b>{stats['high_alerts']}</b></font>", table_cell_style)
        ],
        [
            Paragraph("<b>Medium Risk Alerts</b>", table_cell_style),
            Paragraph(f"<font color='#d97706'><b>{stats['medium_alerts']}</b></font>", table_cell_style),
            Paragraph("<b>Low Risk Alerts</b>", table_cell_style),
            Paragraph(f"<font color='#16a34a'><b>{stats['low_alerts']}</b></font>", table_cell_style)
        ]
    ]

    metrics_table = Table(metrics_data, colWidths=[130, 110, 130, 170])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))

    elements.append(metrics_table)
    elements.append(Spacer(1, 14))

    # 4. Detected Alerts Incident Log Table
    elements.append(Paragraph("2. Top Detected Incidents & Severity Matrix", heading_style))
    
    alerts = get_all_alerts()
    alert_table_data = [
        [
            Paragraph("ID", table_header_style),
            Paragraph("Timestamp", table_header_style),
            Paragraph("Alert Type", table_header_style),
            Paragraph("Severity", table_header_style),
            Paragraph("Source IP", table_header_style),
            Paragraph("Status", table_header_style)
        ]
    ]

    for a in alerts[:12]:  # Limit top 12 for PDF sizing
        sev_color = "#dc2626" if a['severity'] == "Critical" else ("#ea580c" if a['severity'] == "High" else "#d97706")
        alert_table_data.append([
            Paragraph(f"#{a['id']}", table_cell_style),
            Paragraph(str(a['timestamp'])[:16], table_cell_style),
            Paragraph(a['alert_type'], table_cell_style),
            Paragraph(f"<font color='{sev_color}'><b>{a['severity']}</b></font>", table_cell_style),
            Paragraph(a['source_ip'], table_cell_style),
            Paragraph(a['status'], table_cell_style)
        ])

    alert_table = Table(alert_table_data, colWidths=[30, 95, 135, 60, 110, 110])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PRIMARY_COLOR),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))

    elements.append(alert_table)
    elements.append(Spacer(1, 14))

    # 5. Playbook & Incident Mitigation Recommendations
    elements.append(Paragraph("3. Recommended Remediation & Incident Response Playbook", heading_style))
    recs = [
        "<b>Web Attack Vector Mitigation:</b> Enforce Web Application Firewall (WAF) blocking rules for detected SQL Injection and XSS signatures. Ensure all user inputs undergo strict parameterization.",
        "<b>Brute Force Defense:</b> Implement rate-limiting, IP-based Fail2ban blocking, and require Multi-Factor Authentication (MFA) across all administrative portals.",
        "<b>Network Reconnaissance Containment:</b> Block port scanning source IPs at perimeter routers and hide management services behind secure WireGuard/IPsec VPNs.",
        "<b>Malicious IP Blacklisting:</b> Update threat intelligence feeds to automatically reject inbound connections from known TOR Exit Nodes and Command & Control subnets."
    ]

    for rec in recs:
        elements.append(Paragraph(f"• {rec}", body_style))

    # Footer notice
    elements.append(Spacer(1, 12))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cbd5e1'), spaceAfter=8))
    elements.append(Paragraph("CONFIDENTIAL - CyberSOC Internal Security Document. For SOC Internship Project Demonstration.", subtitle_style))

    # Build Document
    doc.build(elements)
    buffer.seek(0)
    return buffer
