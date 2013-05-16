@start "GoAgent" "python.exe" -B -x "%~dpnx0" && exit /b 0 || pause
import sys
import os
import traceback
import ctypes

def main():
    global __file__
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        __file__ = 'proxy.py'
        __import__('proxy').main()
    except:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 1);
        traceback.print_exc(file=sys.stderr);
        os.system('pause')

if __name__ == '__main__':
    main()
