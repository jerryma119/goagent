#!/usr/bin/env python
# coding:utf-8

from __future__ import with_statement

__version__ = '1.0'

import sys
import os
import re
import time

def main_macos():
    if os.getuid() != 0:
        print 'please use sudo run this script'
        sys.exit()
    PLIST = '''\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>GroupName</key>
	<string>wheel</string>
	<key>Label</key>
	<string>org.goagent.macos</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/bin/python</string>
		<string>%(dirname)s/proxy.py</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>UserName</key>
	<string>root</string>
	<key>WorkingDirectory</key>
	<string>%(dirname)s</string>
    <key>StandardOutPath</key>
    <string>/var/log/goagent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/goagent.log</string>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
</dict>
</plist>''' % dict(dirname=os.path.abspath(os.path.dirname(__file__)))
    filename = '/Library/LaunchDaemons/org.goagent.macos.plist'
    print 'write plist to %s' % filename
    with open(filename, 'wb') as fp:
        fp.write(PLIST)
    print 'write plist to %s done' % filename
    print 'Adding CA.crt to system keychain, You may need to input your password...'
    cmd = 'sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s/CA.crt"' % os.path.abspath(os.path.dirname(__file__))
    if os.system(cmd) != 0:
        print 'Adding CA.crt to system keychain Failed!'
        sys.exit(0)
    print 'Adding CA.crt to system keychain Done'
    print 'To start goagent right now, try this command: sudo launchctl load /Library/LaunchDaemons/org.goagent.macos.plist'
    print 'To checkout log file: using Console.app to locate /var/log/goagent.log' 

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
