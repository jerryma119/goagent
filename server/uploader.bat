@echo off

set PYTHONSCRIPT="import sys;sys.path.insert(0,'appcfg.zip');import appcfg;appcfg.main([sys.argv[0], 'rollback', '.'])"
"%~dp0..\local\proxy.exe"
set PYTHONSCRIPT=import sys;sys.path.insert(0,'appcfg.zip');import appcfg;appcfg.main([sys.argv[0], 'update', '.'])
"%~dp0..\local\proxy.exe"
pause
@echo on