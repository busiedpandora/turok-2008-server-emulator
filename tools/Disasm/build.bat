@echo off
rem Builds the Disasm helper. Needs Iced.dll (net45) from the Iced NuGet package 1.21.0
rem (https://www.nuget.org/packages/Iced), placed next to this file. Iced.dll is not committed.
cd /d "%~dp0"
if not exist Iced.dll (
  echo Iced.dll missing: download the Iced package from nuget.org and copy lib\net45\Iced.dll here.
  exit /b 1
)
"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" /nologo /out:Disasm.exe /r:Iced.dll Disasm.cs
