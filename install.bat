@echo off
REM Dwuklik = instalacja (online): sanityzacja danych, Node.js, Tor, FFmpeg/FFprobe, cjxl i acme-client.
REM Pobiera TYLKO to, czego brakuje. Parametry (opcjonalne) trafiaja do install.ps1, np.:
REM   install.bat -Mode system -Tor no     |     install.bat -Clean     |     install.bat -CheckOnly
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
pause
