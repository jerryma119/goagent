@echo off

set uploaddir=python

( 
    echo ===============================================================
    echo  GoAgent服务端部署程序, 开始上传%uploaddir%服务端
    echo ===============================================================
    echo.
    echo 请输入您的appid, 多个appid请用^|号隔开
) && (
    @cd /d "%~dp0" 
) && (
    if exist ".appcfg_cookies" (@del /f /q .appcfg_cookies)
) && (
    set PYTHONSCRIPT="import sys;sys.path.insert(0, 'uploader.zip');import appcfg;appcfg.main()"
) && (
    "..\local\proxy.exe"
) && (
    echo.
    echo 上传成功，请忽略Exception KeyError错误, 编辑proxy.ini把你的appid填进去，谢谢。请按任意键退出程序。
)

@pause>NUL

  
  
@echo off