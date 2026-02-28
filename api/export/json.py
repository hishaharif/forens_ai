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
            payload = {"meta": {"tool": "ForensAI v3.2.1", "file": data.get("filename", ""), "generated": datetime.utcnow().isoformat()}, "summary": data.get("summary", {}), "parsed_count": data.get("parsed_count", 0), "iocs": data.get("anomalies", [])}
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            out = json.dumps(payload, indent=2)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Disposition", f"attachment; filename=forensai_iocs_{ts}.json")
            self.end_headers()
            self.wfile.write(out.encode())
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
