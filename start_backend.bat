@echo off
echo Starting CATO Backend...
cd /d "%~dp0backend\app"
python -m uvicorn main:app --reload --port 8000
