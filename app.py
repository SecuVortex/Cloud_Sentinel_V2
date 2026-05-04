from flask import Flask, render_template, request, redirect, url_for, session, flash
from scanner import run_scan
from rules import RULES
import os

app = Flask(__name__)
app.secret_key = 'cloud-sentinel-secret-key' # In production, use a secure key

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

    # Stats
    total = len(results)
    passed = sum(1 for r in results if r['status'] == 'PASS')
    failed = sum(1 for r in results if r['status'] == 'FAIL')
    not_found = sum(1 for r in results if r['status'] in ['NOT FOUND', 'ERROR'])

    # Severity counts
    high = sum(1 for r in results if r['severity'] == 'High')
    medium = sum(1 for r in results if r['severity'] == 'Medium')
    low = sum(1 for r in results if r['severity'] == 'Low')

    # Filters
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
        return {"error": "Unauthorized"}, 401
    results = run_scan()
    return {"results": results}

@app.route('/api/results')
def api_results():
    """Alias for /api/scan kept for backwards compatibility."""
    if not session.get('logged_in'):
        return {"error": "Unauthorized"}, 401
    results = run_scan()
    return {"results": results}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
