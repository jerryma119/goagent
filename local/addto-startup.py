#!/usr/bin/env python
# coding:utf-8

from __future__ import with_statement

__version__ = '1.0'

import sys
import os
import re
import time

def main_macos():
    PLIST = '''\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>GroupName</key>
	<string>wheel</string>
	<key>Label</key>
	<string>org.goagent.macos</string>
	<key>OnDemand</key>
	<false/>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/bin/python</string>
		<string>%(dirname)s/proxy.py</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ServiceIPC</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>%(dirname)s/proxy.log</string>
	<key>StandardOutPath</key>
	<string>%(dirname)s/proxy.log</string>
	<key>UserName</key>
	<string>root</string>
	<key>WorkingDirectory</key>
	<string>%(dirname)s</string>
</dict>
</plist>''' % dict(dirname=os.path.dirname(__file__))
    filename = '/System/Library/LaunchDaemons/org.goagent.macos.plist'
    print 'write plist to %s' % filename
    with open(filename, 'wb') as fp:
        fp.write(PLIST)
    print 'write plist to %s done' % filename

def main_linux():
    pass

def main_windows():
    pass

def main():
    main_macos()


if __name__ == '__main__':
   try:
       main()
   except KeyboardInterrupt:
       pass
