@echo off
rem Captures all UDP traffic (including DNS) with the Windows built-in pktmon.
rem Needs administrator rights: the script asks for them by itself.
rem Loopback traffic (127.0.0.1) is NOT captured here; PacketProbe logs that.

net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "OUT=%~dp0capture"
if not exist "%OUT%" mkdir "%OUT%"
cd /d "%OUT%"

pktmon stop >nul 2>&1
pktmon filter remove >nul
pktmon filter add UDP -t UDP >nul
pktmon start --capture --pkt-size 0 --file-name "%OUT%\capture.etl"
if errorlevel 1 (
  echo pktmon failed to start.
  pause
  exit /b 1
)

echo.
echo ================================================================
echo  Capture running. Now start Turok and open
echo  MULTIPLAYER ^> PUBLIC MATCH ^> QUICK MATCH.
echo  When the game shows the error, come back here and press a key.
echo ================================================================
pause >nul

pktmon stop
pktmon etl2txt "%OUT%\capture.etl" --out "%OUT%\capture.txt"
pktmon etl2pcap "%OUT%\capture.etl" --out "%OUT%\capture.pcapng"
pktmon filter remove >nul
echo.
echo Done. Files saved in %OUT%
pause
