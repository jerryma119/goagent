@echo off

set HTTPS_PROXY=http://127.0.0.1:8087
set PYTHONSCRIPT=appcfg.zip
"%~dp0..\local\proxy.exe" rollback . && "%~dp0..\local\proxy.exe" update . && ping -n 5 127.1 >NUL || pause

@echo on