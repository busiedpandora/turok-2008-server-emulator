@echo off
rem Starts Turok with Unreal Engine 3 logging enabled.
rem The log is written to Turok\TurokGame\Logs\TurokDebug.log
set "TUROK_BIN=%~dp0..\..\Turok\Binaries"
cd /d "%TUROK_BIN%"
start "" TurokGame.exe -log -forcelogflush LOG=TurokDebug.log
