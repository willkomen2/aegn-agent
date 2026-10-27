@echo off
rem Desinstala o AEGN Security (pede a senha).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0instalar.ps1" -Desinstalar %*
