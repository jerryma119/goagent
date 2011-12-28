@echo off

set uploaddir=golang

( 
    echo ===============================================================
    echo 开始上传GoAgent %uploaddir% Server
    echo 如果需要上传python server, 请修改本文件的uploaddir的值为python
    echo ===============================================================
    echo.
    echo 请输入您的appid, 多个appid请用^|号隔开
) && (
    @cd /d "%~dp0" 
) && (
    set PYTHONSCRIPT=uploader.py
) && (
    "..\local\proxy.exe"
) || (
    pause
)
  
  
@echo off