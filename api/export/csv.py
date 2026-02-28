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
            rows = ["Timestamp,Type,Severity,Description"]
            for a in anomalies:
                desc = a["description"].replace('"', '""')
                rows.append(f'"{a["timestamp"]}","{a["type"]}","{a["severity"]}","{desc}"')
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            out = "\n".join(rows)
            self.send_response(200)
            self.send_header("Content-type", "text/csv")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Disposition", f"attachment; filename=forensai_iocs_{ts}.csv")
            self.end_headers()
            self.wfile.write(out.encode())
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
