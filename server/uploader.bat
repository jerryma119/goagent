@echo off

cd /d "%~dp0"

cmd.exe /c tasklist | findstr "goagent.exe" >NUL && (
    rem echo find goagent.exe is running, set proxy to 127.0.0.1
    set HTTP_PROXY=http://127.0.0.1:8087
    set HTTPS_PROXY=http://127.0.0.1:8087
)

(
    cmd.exe /c "set PYTHONSCRIPT=appid=raw_input('APPID:').strip();yaml=__import__('re').sub(r'application:\s*\w*', 'application: '+appid, open('app.yaml', 'rb').read());open('app.yaml', 'wb').write(yaml);print yaml && ..\local\proxy.exe"
) && (
    set PYTHONSCRIPT=appcfg.zip && "..\local\proxy.exe" rollback . && "..\local\proxy.exe" update . && ping -n 5 0.0.0.0 >NUL 
) || (
    pause
)

@echo on