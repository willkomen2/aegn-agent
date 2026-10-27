@echo off
rem Instala ou atualiza o AEGN Security (pede administrador e a senha).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0instalar.ps1" %*
