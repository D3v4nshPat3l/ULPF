@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0demo-switch.ps1" -ToWazuh
pause
