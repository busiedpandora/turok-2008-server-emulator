@echo off
rem Allows inbound UDP traffic for Turok online play in the Windows firewall.
rem   9103        Quazal peer-to-peer port of the game (RendezvousWellKnownPort)
rem   7777        Unreal Engine 3 game traffic
rem   6666, 7666  ports listed in the Turok readme
rem   30720-30721 emulator servers (only needed on the PC running TurokServer)
rem   AllowTurokFirewall.bat remove   -> deletes the rule again
rem Needs administrator rights: the script asks for them by itself.

net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)

netsh advfirewall firewall delete rule name="Turok 2008 online (UDP)" >nul 2>&1
if /i "%~1"=="remove" (
  echo Rule removed.
  pause
  exit /b
)
netsh advfirewall firewall add rule name="Turok 2008 online (UDP)" dir=in action=allow protocol=UDP localport=6666,7666,7777,9103,30720-30721 profile=any
echo.
echo Done. Inbound UDP 6666, 7666, 7777, 9103, 30720-30721 allowed.
pause
