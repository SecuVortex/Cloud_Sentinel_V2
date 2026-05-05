from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from scanner import run_scan
from rules import RULES
from ai_analyzer import analyze_log_with_ai, analyze_all_instances, get_sample_logs
from live_scanner import run_live_scan, get_connection, get_instance_logs
import os

app = Flask(__name__)
app.secret_key = 'cloud-sentinel-secret-key'

# Mock user database
USERS = {
    "admin": "password123"
}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and USERS[username] == password:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    results = run_scan()

    total = len(results)
    passed = sum(1 for r in results if r['status'] == 'PASS')
    failed = sum(1 for r in results if r['status'] == 'FAIL')
    not_found = sum(1 for r in results if r['status'] in ['NOT FOUND', 'ERROR'])

    high = sum(1 for r in results if r['severity'] == 'High' and r['status'] == 'FAIL')
    medium = sum(1 for r in results if r['severity'] == 'Medium' and r['status'] == 'FAIL')
    low = sum(1 for r in results if r['severity'] == 'Low' and r['status'] == 'FAIL')

    service_filter = request.args.get('service', 'All')
    severity_filter = request.args.get('severity', 'All')

    filtered = results
    if service_filter != 'All':
        filtered = [r for r in filtered if r['service'] == service_filter]
    if severity_filter != 'All':
        filtered = [r for r in filtered if r['severity'] == severity_filter]

    services = ['All'] + sorted(list(set(r['service'] for r in RULES)))
    severities = ['All', 'High', 'Medium', 'Low']

    return render_template('dashboard.html',
                           results=filtered,
                           total=total,
                           passed=passed,
                           failed=failed,
                           not_found=not_found,
                           high=high,
                           medium=medium,
                           low=low,
                           services=services,
                           severities=severities,
                           service_filter=service_filter,
                           severity_filter=severity_filter)

@app.route('/api/scan')
def api_scan():
    """Primary JSON endpoint for scan results."""
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        results = run_scan()
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/live-scan')
def api_live_scan():
    """Return JSON for live scan."""
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        results = run_live_scan()
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/live-instances')
def live_instances():
    """Show live instances table."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    try:
        results = run_live_scan()
        if "error" in results:
            flash(results["error"], "danger")
            # Create a mock result to allow rendering
            results = {
                "instances": [], "logs": {}, "security_groups": [],
                "networks": [], "volumes": [], "images": [], "users": []
            }
        return render_template('live_instances.html', data=results)
    except Exception as e:
        flash(f"Error connecting to OpenStack: {e}", "danger")
        return render_template('live_instances.html', data={})

@app.route('/ai-analysis')
def ai_analysis():
    """AI Dashboard."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    mode = "DEMO MODE"
    logs = {}
    
    # Try to get live logs first
    try:
        conn = get_connection()
        if conn:
            logs = get_instance_logs(conn)
            if logs:
                mode = "LIVE MODE"
    except Exception as e:
        print(f"Failed to get live logs: {e}")
        
    # Fallback to sample logs
    if not logs:
        logs = get_sample_logs()
        
    results = analyze_all_instances(logs)
    
    return render_template('ai_dashboard.html', results=results, mode=mode)

@app.route('/analyze-log', methods=['POST'])
def analyze_log():
    """POST endpoint to analyze a specific log."""
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    if not data or 'log' not in data or 'instance' not in data:
        return jsonify({"error": "Missing 'log' or 'instance' in request body"}), 400
        
    try:
        result = analyze_log_with_ai(data['log'], data['instance'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
