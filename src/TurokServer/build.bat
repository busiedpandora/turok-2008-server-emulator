@echo off
rem Compiles TurokServer with the C# compiler bundled with Windows (.NET Framework 4.x).
cd /d "%~dp0"
if not exist bin mkdir bin
"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" /nologo /optimize /out:bin\TurokServer.exe *.cs
if errorlevel 1 (
  echo Build FAILED.
  exit /b 1
)
echo Build OK: %~dp0bin\TurokServer.exe
