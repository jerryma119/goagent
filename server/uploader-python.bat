@echo off

cd /d "%~dp0"

cd python

if not exist "../../local/proxy.exe" (
    echo Cannot found "../local/proxy.exe", may be you need extract it.
    pause && exit /b 1
)

cmd.exe /c tasklist | findstr "goagent.exe" >NUL && (
    rem echo find goagent.exe is running, set proxy to 127.0.0.1
    set HTTP_PROXY=http://127.0.0.1:8087
    set HTTPS_PROXY=http://127.0.0.1:8087
)

(
    cmd.exe /c "set PYTHONSCRIPT=import sys,re;appid=raw_input('APPID:').strip();appid=appid if appid else (sys.stderr.write('APPID is not vaild!!!\n'), sys.exit(-1));yaml=re.sub(r'application:\s*\S+', 'application: '+appid, open('app.yaml', 'rb').read());open('app.yaml', 'wb').write(yaml);print yaml && ..\..\local\proxy.exe"
) && (
    set PYTHONSCRIPT=appcfg.zip && "..\..\local\proxy.exe" rollback . && "..\..\local\proxy.exe" update . && ping -n 5 0.0.0.0 >NUL 
) || (
    pause
)

@echo on