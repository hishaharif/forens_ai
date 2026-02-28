import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode() if content_length else "{}"
            data = json.loads(body)
            anomalies = data.get("anomalies", [])
            summary = data.get("summary", {})
            parsed_count = data.get("parsed_count", 0)
            filename = data.get("filename", "logfile")
            risk = min(10.0, (summary.get("critical", 0) * 2.5) + (summary.get("high", 0) * 1.5) + (len(anomalies) * 0.2))
            sep = "=" * 60
            lines = [sep, "FORENSAI INCIDENT REPORT", sep, f"Source File : {filename}", f"Generated   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", f"Parsed Lines: {parsed_count}", f"Anomalies   : {len(anomalies)}", f"Risk Score  : {risk:.1f} / 10", f"Critical: {summary.get('critical',0)}  High: {summary.get('high',0)}  Medium: {summary.get('medium',0)}", "", "-" * 60, "ANOMALIES DETECTED", "-" * 60]
            for i, a in enumerate(anomalies, 1):
                lines += [f"\n[{i}] {a['type']} ({a['severity']})", f"    Timestamp  : {a['timestamp']}", f"    Description: {a['description']}"]
            lines += ["", sep, "END OF REPORT — ForensAI v3.2.1", sep]
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            out = "\n".join(lines)
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Disposition", f"attachment; filename=forensai_report_{ts}.txt")
            self.end_headers()
            self.wfile.write(out.encode())
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
