import os
import re
import json
from datetime import datetime
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
from utils.analyzer import ForensicAnalyzer

app = Flask(__name__)
CORS(app)

FRONTEND_PATH = os.path.join(os.path.dirname(__file__), '..', 'index.html')
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/', methods=['GET'])
def serve_frontend():
    return send_file(os.path.abspath(FRONTEND_PATH))

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({"status": "online", "version": "1.0.0", "message": "ForensAI Backend is running"})

@app.route('/api/analyze/text', methods=['POST'])
def analyze_text():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    if not text:
        return jsonify({"error": "No text provided"}), 400
    critical_terms = re.findall(r'critical|emergency|alert|panic', text.lower())
    warning_terms  = re.findall(r'fail|error|unauthorized|denied|attack', text.lower())
    risk_score = min(10.0, (len(critical_terms) * 3.0) + (len(warning_terms) * 1.5))
    return jsonify({
        "risk_score": round(risk_score, 1),
        "analysis": "Text analysis complete",
        "tokens": len(text.split()),
        "matches": {"critical": len(critical_terms), "warnings": len(warning_terms)}
    })

@app.route('/api/analyze/logs', methods=['POST'])
def analyze_logs():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    try:
        content = file.read().decode('utf-8', errors='ignore')
        lines = content.splitlines()
        parsed_logs = []
        for line in lines:
            if not line.strip():
                continue
            parsed = ForensicAnalyzer.parse_log_line(line)
            if parsed:
                parsed_logs.append(parsed)
        anomalies = ForensicAnalyzer.detect_anomalies(parsed_logs)
        return jsonify({
            "total_lines": len(lines),
            "parsed_count": len(parsed_logs),
            "anomalies": anomalies,
            "summary": {
                "critical": len([a for a in anomalies if a['severity'] == 'Critical']),
                "high":     len([a for a in anomalies if a['severity'] == 'High']),
                "medium":   len([a for a in anomalies if a['severity'] == 'Medium'])
            }
        })
    except Exception as e:
        return jsonify({"error": f"Process error: {str(e)}"}), 500

# ── Export Endpoints ──────────────────────────────────────────────────────────

@app.route('/api/export/txt', methods=['POST'])
def export_txt():
    data        = request.get_json(silent=True) or {}
    anomalies   = data.get('anomalies', [])
    summary     = data.get('summary', {})
    parsed_count = data.get('parsed_count', 0)
    filename    = data.get('filename', 'logfile')
    risk = min(10.0, (summary.get('critical',0)*2.5) + (summary.get('high',0)*1.5) + (len(anomalies)*0.2))
    sep = '=' * 60
    lines = [
        sep, 'FORENSAI INCIDENT REPORT', sep,
        f"Source File : {filename}",
        f"Generated   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Parsed Lines: {parsed_count}",
        f"Anomalies   : {len(anomalies)}",
        f"Risk Score  : {risk:.1f} / 10",
        f"Critical: {summary.get('critical',0)}  High: {summary.get('high',0)}  Medium: {summary.get('medium',0)}",
        '', '-' * 60, 'ANOMALIES DETECTED', '-' * 60,
    ]
    for i, a in enumerate(anomalies, 1):
        lines += [f"\n[{i}] {a['type']} ({a['severity']})",
                  f"    Timestamp  : {a['timestamp']}",
                  f"    Description: {a['description']}"]
    lines += ['', sep, 'END OF REPORT — ForensAI v3.2.1', sep]
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return Response('\n'.join(lines), mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename=forensai_report_{ts}.txt'})

@app.route('/api/export/json', methods=['POST'])
def export_json():
    data = request.get_json(silent=True) or {}
    payload = {
        "meta": {"tool": "ForensAI v3.2.1", "file": data.get('filename',''), "generated": datetime.utcnow().isoformat()},
        "summary":      data.get('summary', {}),
        "parsed_count": data.get('parsed_count', 0),
        "iocs":         data.get('anomalies', [])
    }
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return Response(json.dumps(payload, indent=2), mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=forensai_iocs_{ts}.json'})

@app.route('/api/export/csv', methods=['POST'])
def export_csv():
    data      = request.get_json(silent=True) or {}
    anomalies = data.get('anomalies', [])
    rows = ['Timestamp,Type,Severity,Description']
    for a in anomalies:
        desc = a['description'].replace('"', '""')
        rows.append(f'"{a["timestamp"]}","{a["type"]}","{a["severity"]}","{desc}"')
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return Response('\n'.join(rows), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=forensai_iocs_{ts}.csv'})

if __name__ == '__main__':
    print('ForensAI starting at http://127.0.0.1:5000')
    app.run(debug=True, host='127.0.0.1', port=5000)
