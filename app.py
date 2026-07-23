import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, flash
from database import (
    init_db,
    get_dashboard_stats,
    get_recent_logs,
    get_all_alerts,
    get_alert_by_id,
    update_alert_status,
    insert_new_log_and_analyze,
    get_chart_analytics
)
from report_generator import generate_pdf_report

app = Flask(__name__)
app.secret_key = 'cybersoc_secret_key_internship_demo'

# Initialize database schema and sample data on startup
with app.app_context():
    init_db()

@app.route('/')
def dashboard():
    """Renders main CyberSOC Dashboard page."""
    stats = get_dashboard_stats()
    recent_alerts = get_all_alerts()[:6]
    recent_logs = get_recent_logs(limit=8)
    return render_template('dashboard.html', stats=stats, alerts=recent_alerts, logs=recent_logs)

@app.route('/logs')
def logs():
    """Renders Security Logs page with interactive log analyzer."""
    category = request.args.get('category', '')
    threat_only = request.args.get('threat_only', '0') == '1'
    logs_list = get_recent_logs(limit=100, category_filter=category if category else None, threat_only=threat_only)
    return render_template('logs.html', logs=logs_list, selected_category=category, threat_only=threat_only)

@app.route('/logs/analyze', methods=['POST'])
def analyze_log_endpoint():
    """API endpoint to analyze user-submitted or preset security log lines."""
    data = request.get_json() if request.is_json else request.form
    
    raw_log = data.get('raw_log', '').strip()
    source_ip = data.get('source_ip', '').strip()
    username = data.get('username', '').strip()
    category = data.get('category', 'System').strip()
    destination_ip = data.get('destination_ip', '10.0.0.1').strip()
    log_level = data.get('log_level', 'INFO').strip()

    if not raw_log:
        if request.is_json:
            return jsonify({'error': 'Raw log string is required'}), 400
        flash('Please enter a valid log message to analyze.', 'danger')
        return redirect(url_for('logs'))

    result = insert_new_log_and_analyze(
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        log_level=log_level,
        category=category,
        message=raw_log,
        raw_log=raw_log
    )

    if request.is_json:
        return jsonify(result)
    
    if result['is_threat']:
        flash(f"Threat Detected: {result['analysis']['alert_type']} ({result['analysis']['severity']} Severity)", 'warning')
    else:
        flash("Log Analyzed: Clean payload - No security threats detected.", 'success')

    return redirect(url_for('logs'))

@app.route('/alerts')
def alerts():
    """Renders Security Alerts page with severity and status filters."""
    severity = request.args.get('severity', 'All')
    status = request.args.get('status', 'All')
    alerts_list = get_all_alerts(severity_filter=severity, status_filter=status)
    stats = get_dashboard_stats()
    return render_template('alerts.html', alerts=alerts_list, selected_severity=severity, selected_status=status, stats=stats)

@app.route('/alerts/<int:alert_id>')
def alert_detail(alert_id):
    """Renders detailed view for a single security alert."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        flash('Alert not found.', 'danger')
        return redirect(url_for('alerts'))
    return render_template('alert_detail.html', alert=alert)

@app.route('/alerts/<int:alert_id>/status', methods=['POST'])
def change_alert_status(alert_id):
    """Updates the status of a specific security alert (New, Investigating, Resolved)."""
    new_status = request.form.get('status') or (request.json.get('status') if request.is_json else None)
    if new_status in ['New', 'Investigating', 'Resolved']:
        update_alert_status(alert_id, new_status)
        if request.is_json:
            return jsonify({'success': True, 'alert_id': alert_id, 'new_status': new_status})
        flash(f"Alert #{alert_id} status updated to {new_status}.", 'success')
    return redirect(request.referrer or url_for('alerts'))

@app.route('/reports')
def reports():
    """Renders Security Reports page with PDF download option."""
    stats = get_dashboard_stats()
    alerts_list = get_all_alerts()
    return render_template('reports.html', stats=stats, alerts=alerts_list[:10])

@app.route('/reports/download')
def download_report():
    """Generates and streams executive PDF security report."""
    pdf_buffer = generate_pdf_report()
    filename = f"CyberSOC_Security_Report_{os.urandom(3).hex()}.pdf"
    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )

@app.route('/api/stats')
def api_stats():
    """REST API endpoint for real-time dashboard stats."""
    return jsonify(get_dashboard_stats())

@app.route('/api/chart-data')
def api_chart_data():
    """REST API endpoint returning datasets for Chart.js dashboard widgets."""
    return jsonify(get_chart_analytics())

@app.route('/api/recent-alerts')
def api_recent_alerts():
    """REST API returning latest security alerts for live dashboard table sync."""
    alerts_list = get_all_alerts()[:6]
    return jsonify(alerts_list)

if __name__ == '__main__':
    print("==========================================================")
    print(" CyberSOC - Cybersecurity Operations Center Dashboard ")
    print(" Listening on http://127.0.0.1:5000")
    print("==========================================================")
    app.run(debug=True, host='127.0.0.1', port=5000)
