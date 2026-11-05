@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist config.ini copy config.example.ini config.ini
py -m pip install -r requirements.txt
py jsn_notifier.py serve
pause
