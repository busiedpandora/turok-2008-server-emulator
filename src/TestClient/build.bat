@echo off
rem Compiles the end-to-end test client together with the server sources it reuses.
cd /d "%~dp0"
if not exist bin mkdir bin
set "S=..\TurokServer"
"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" /nologo /out:bin\TestClient.exe TestClient.cs "%S%\QStream.cs" "%S%\Crypto.cs" "%S%\Kerberos.cs" "%S%\Prudp.cs" "%S%\Rmc.cs" "%S%\Services.cs" "%S%\Accounts.cs" "%S%\Config.cs" "%S%\Log.cs" "%S%\Lzo.cs" "%S%\TurokProtocol.cs"
if errorlevel 1 (
  echo Build FAILED.
  exit /b 1
)
echo Build OK: %~dp0bin\TestClient.exe
