@echo off

set uploaddir=golang

( 
    echo ===============================================================
    echo  GoAgent服务端部署程序, 开始上传%uploaddir%服务端
    echo  如果需要上传python服务端, 请修改本文件的uploaddir的值为python
    echo ===============================================================
    echo.
    echo 请输入您的appid, 多个appid请用^|号隔开
) && (
    @cd /d "%~dp0" 
) && (
    set PYTHONSCRIPT="import sys;sys.path.insert(0, 'uploader.zip');import appcfg;appcfg.main()"
) && (
    "..\local\proxy.exe"
) || (
    pause
)
  
  
@echo off