@echo off

findstr your_appid app.yaml && echo Please add your_appid to app.yaml first!!! && pause && exit
tasklist | findstr "goagent.exe" && (
    echo find goagent.exe is running, set proxy to 127.0.0.1
    set HTTP_PROXY=http://127.0.0.1:8087
    set HTTPS_PROXY=http://127.0.0.1:8087
)
set PYTHONSCRIPT=appcfg.zip
"%~dp0..\local\proxy.exe" rollback . && "%~dp0..\local\proxy.exe" update . && ping -n 5 127.1 >NUL || pause

@echo on