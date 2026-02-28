# ForensAI — Intelligent Digital Evidence Analysis

A professional forensic log analysis platform with a premium cyberpunk-inspired UI. Upload web access logs (Common Log Format) to detect anomalies, visualize attack timelines, and export reports.

## Quick Start

1. **Install dependencies:**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

2. **Run the application:**
   - **Windows:** Double-click `run.bat` or run `.\run.ps1`
   - **Manual:** `cd backend && python app.py`

3. **Open in browser:** [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Features

- **Evidence ingestion** — Drag & drop or click to upload `.log` files (Common Log Format)
- **Real-time analysis** — Parses logs, detects brute force, SQLi, XSS, path traversal, directory scanning, data exfiltration
- **Dashboard stats** — Evidence count, anomaly count, risk score, severity level
- **Filterable event table** — Filter by Critical / High / Medium severity
- **Timeline reconstruction** — Chronological view of detected events
- **AI-generated narrative** — Incident summary
- **Export** — TXT report, JSON IOCs, CSV table

## Sample Data

- `backend/sample_access.log` — Basic sample
- `backend/test_attack.log` — Rich attack simulation (60 lines → 26 anomalies)

## Tech Stack

- **Frontend:** HTML5, CSS3, Vanilla JS
- **Backend:** Python Flask, CORS enabled
- **Analysis:** Pattern matching, heuristic anomaly detection
