@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_mcp_shield.ps1"
if errorlevel 1 echo MCP Shield did not start. Review the message above and mcp-shield.stderr.log.
pause
