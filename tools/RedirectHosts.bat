@echo off
rem Redirects turokpclive.quazal.net to a local or custom emulator via the Windows hosts file.
rem   RedirectHosts.bat              -> adds   "127.0.0.1 turokpclive.quazal.net"
rem   RedirectHosts.bat 1.2.3.4      -> adds   "1.2.3.4 turokpclive.quazal.net"
rem   RedirectHosts.bat remove       -> removes the line again
rem Needs administrator rights: the script asks for them by itself.

net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)

set "ARG=%~1"
if "%ARG%"=="" set "ARG=127.0.0.1"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$h = Join-Path $env:WINDIR 'System32\drivers\etc\hosts';" ^
  "$name = 'turokpclive.quazal.net';" ^
  "if (-not (Test-Path ($h + '.turok.bak'))) { Copy-Item $h ($h + '.turok.bak') };" ^
  "$lines = @(Get-Content $h | Where-Object { $_ -notmatch ('\s' + [regex]::Escape($name) + '\s*$') });" ^
  "if ('%ARG%' -ne 'remove') { $lines += ('%ARG% ' + $name) };" ^
  "Set-Content -Path $h -Value $lines -Encoding ASCII;" ^
  "Write-Host 'Current Turok entries in hosts:';" ^
  "Get-Content $h | Where-Object { $_ -match [regex]::Escape($name) } | ForEach-Object { Write-Host ('  ' + $_) }"

ipconfig /flushdns >nul
echo.
echo Done. DNS cache flushed.
pause
