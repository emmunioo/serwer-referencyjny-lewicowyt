@echo off
setlocal
cd /d "%~dp0"
title Serwer spolecznosci lewicowYT

REM --- znajdz silnik: 1) zapisana sciezka  2) lokalny .\engine  3) systemowy node w PATH ---
set "ENGINE="
if exist "%~dp0.enginepath" (for /f "usebackq delims=" %%p in ("%~dp0.enginepath") do set "ENGINE=%%p")
if not defined ENGINE if exist "%~dp0engine\node.exe" set "ENGINE=%~dp0engine\node.exe"
if not defined ENGINE for /f "delims=" %%p in ('where node 2^>nul') do if not defined ENGINE set "ENGINE=%%p"
if not defined ENGINE goto :install
goto :run

:install
echo.
echo Silnik (Node.js) nie jest jeszcze zainstalowany - uruchamiam instalator...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "ENGINE="
if exist "%~dp0.enginepath" (for /f "usebackq delims=" %%p in ("%~dp0.enginepath") do set "ENGINE=%%p")
if not defined ENGINE if exist "%~dp0engine\node.exe" set "ENGINE=%~dp0engine\node.exe"
if not defined ENGINE for /f "delims=" %%p in ('where node 2^>nul') do if not defined ENGINE set "ENGINE=%%p"
if not defined ENGINE (
  echo.
  echo Nie udalo sie przygotowac silnika. Sprawdz polaczenie z internetem i sprobuj ponownie.
  pause
  exit /b 1
)

:run
"%ENGINE%" -e "const v=process.versions.node.split('.').map(Number);process.exit(v[0]>22||(v[0]===22&&v[1]>=15)?0:1)"
if errorlevel 1 (
  echo.
  echo Ten silnik Node.js jest za stary - serwer wymaga wersji 22.15 lub nowszej.
  echo Silnik: %ENGINE%
  echo Usun plik .enginepath i folder engine albo zainstaluj nowszego Node.js i uruchom start.bat ponownie.
  pause
  exit /b 1
)
REM lokalny Tor, jesli pobrany przez instalator
if exist "%~dp0engine-tor\tor\tor.exe" set "TOR_BINARY=%~dp0engine-tor\tor\tor.exe"
echo.
echo Silnik: %ENGINE%
echo Panel administratora otworzy sie pod: http://127.0.0.1:2138/admin
echo (haslo przy pierwszym starcie pojawi sie ponizej)
echo ------------------------------------------------------------
set "LEWICOWYT_SUPERVISED=1"
:loop
"%ENGINE%" "%~dp0server.js" %*
REM kod 75 = serwer poprosil o restart (po aktualizacji z panelu)
if errorlevel 75 if not errorlevel 76 (
  echo.
  echo Restart serwera po aktualizacji...
  goto :loop
)
echo ------------------------------------------------------------
echo Serwer zakonczyl dzialanie.
echo Jesli to bylo zaraz po aktualizacji z panelu, cofnij ja poleceniem:  start.bat --rollback
pause
