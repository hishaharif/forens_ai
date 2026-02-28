import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from lib.analyzer import parse_log_line, detect_anomalies

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
            raw = self.rfile.read(content_length) if content_length else b""
            content_type = self.headers.get("Content-Type", "")

            if "multipart/form-data" not in content_type:
                self._json_response(400, {"error": "No file uploaded"})
                return

            boundary = None
            for part in content_type.split(";"):
                part = part.strip()
                if part.startswith("boundary="):
                    boundary = part[9:].strip().strip('"')
                    break
            if not boundary:
                self._json_response(400, {"error": "Invalid multipart"})
                return

            file_content = None
            boundary_bytes = boundary.encode()
            for part in raw.split(b"--" + boundary_bytes):
                if b"Content-Disposition" not in part or b"filename=" not in part:
                    continue
                header, _, content = part.partition(b"\r\n\r\n")
                if content:
                    file_content = content.rstrip(b"\r\n")
                    break

            if not file_content:
                self._json_response(400, {"error": "No file selected"})
                return

            content_str = file_content.decode("utf-8", errors="ignore")
            lines = content_str.splitlines()
            parsed_logs = []
            for line in lines:
                if not line.strip():
                    continue
                p = parse_log_line(line)
                if p:
                    parsed_logs.append(p)

            anomalies = detect_anomalies(parsed_logs)
            result = {
                "total_lines": len(lines),
                "parsed_count": len(parsed_logs),
                "anomalies": anomalies,
                "summary": {
                    "critical": len([a for a in anomalies if a["severity"] == "Critical"]),
                    "high": len([a for a in anomalies if a["severity"] == "High"]),
                    "medium": len([a for a in anomalies if a["severity"] == "Medium"]),
                },
            }
            self._json_response(200, result)
        except Exception as e:
            self._json_response(500, {"error": f"Process error: {str(e)}"})

    def _json_response(self, code, data):
        self.send_response(code)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
