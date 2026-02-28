@echo off
echo Starting ForensAI at http://127.0.0.1:5000
cd /d "%~dp0\backend"
set FLASK_APP=app.py
python app.py
pause
