@echo off
rem Compiles PacketProbe with the C# compiler bundled with Windows (.NET Framework 4.x).
cd /d "%~dp0"
"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" /nologo /optimize /out:PacketProbe.exe PacketProbe.cs
if errorlevel 1 (
  echo Build FAILED.
  exit /b 1
)
echo Build OK: %~dp0PacketProbe.exe
