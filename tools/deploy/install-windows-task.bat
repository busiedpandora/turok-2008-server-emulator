@echo off
rem Installs TurokServer on a Windows VPS:
rem   - opens UDP 30720-30721 in the Windows firewall
rem   - registers a scheduled task that starts the server at boot (as SYSTEM) and restarts it on failure
rem Copy this file into the folder that contains TurokServer.exe and server.ini, then run it.
rem   install-windows-task.bat remove   -> removes the task and the firewall rule
rem Needs administrator rights: the script asks for them by itself.

net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)

set "EXE=%~dp0TurokServer.exe"

if /i "%~1"=="remove" (
  schtasks /End /TN "TurokServer" >nul 2>&1
  schtasks /Delete /TN "TurokServer" /F
  netsh advfirewall firewall delete rule name="TurokServer (UDP)"
  pause
  exit /b
)

if not exist "%EXE%" (
  echo TurokServer.exe not found next to this script: %EXE%
  pause
  exit /b 1
)

netsh advfirewall firewall delete rule name="TurokServer (UDP)" >nul 2>&1
netsh advfirewall firewall add rule name="TurokServer (UDP)" dir=in action=allow protocol=UDP localport=30720-30721 profile=any

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$a = New-ScheduledTaskAction -Execute '%EXE%' -WorkingDirectory '%~dp0';" ^
  "$t = New-ScheduledTaskTrigger -AtStartup;" ^
  "$s = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable;" ^
  "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;" ^
  "Register-ScheduledTask -TaskName 'TurokServer' -Action $a -Trigger $t -Settings $s -Principal $p -Force | Out-Null;" ^
  "Start-ScheduledTask -TaskName 'TurokServer';" ^
  "Write-Host 'Task TurokServer registered and started.'"

echo.
echo Logs: %~dp0logs
pause
