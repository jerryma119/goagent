(/usr/bin/env python2.6 -x "$0" 2>&1 >/dev/null &);exit
# coding:utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '1.6'

GOAGENT_TITLE = "GoAgent OS X"
GOAGENT_ICON_DATA = """\
iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAACXBIWXMAAC4jAAAuIwF4pT92AAAC
+UlEQVR4nJ3TO0hbURgHcF3apUNbSpAuFkVop9JNcJGmj8lHHRxE8BlNTYKJDhFBfJDEYMFBpYjQ
qWOppIEghUJoWh/xnbcGDFIao1Hy0CW5N/ec/r+QBLSFVA98nOn87v/7zrklJcVX6ZW62dLr9beG
h4efjY6OtqJ0IyMj2qGhoVaDwfD02jBhAwMDH7BHu7q6Up2dnWmqjo6OdHd3tzA1NaW/Fjo4OFiB
WikvL7/d399v7OnpYYA4cA6UoVbGxsYe/jeI1qpUKpVPp9P9BPart7eX0jGAhBHs7+vrqywKYU6y
8fHxxzhUgwPvgM4DXEC6eaVSKeXBlpYW/8TERE00Gn3i8XgeYf+7/bm5uTq0912tVv/G4QjqGMmO
FQoF7ZF8QsySNzQ0+NbX1z9ubW2FnU6n++joSHEJm5mZkaG9NBJJSMaAZQsQA5iFkLIANjY2+ux2
+yJAYXV1VcKeicfjsgJoMpleA0sjHaciKAdm0LIIVAQoAhTb29tFuVxu3dnZ+YaUGYAcKcVIJCLP
e6Vms1mFZCnCABNE8xKbm5udTU1NFiqk+oJWLbW1tSaHw6ECGAMoEbi8vCycnZ0pCyDe1VusLAhY
amtrOzEajcpwOLwUDAYDe7kVCAT2vV5vEhchbWxsSEjGCUSlT09P1YWWJycnnwMTUAwtZtDiEm7u
Kw4Ku7u7GaTJbG9vZwvzkjY3NxlARuDa2hpDUgEtvyiA09PTD7RarUDt0szwqD+FQqE9SuJyuThQ
DpQD5AA5AA6Q5xISmMKl3Ll007Ozs280Go0doAc3/v7g4GAfGHO73Yx2YG6gHuweAF4qgFSORCJR
98+Hjd9JhhlWWK3WaoxsHwmzGObGgC2iVQvAz6gFgNUYS2UsFisr+sckk8kqYMF8QmBUNL8Qdgt2
1+HhYfFfL78uLi7KcKM/CKT55Yr5/X6zzWa77/P5bGizeLIraD0AEUlFtChQARXxkRQ6qL8Wll+4
ubuoV+fn5xogajzel0h270bYTdcf/MZuVGTw45kAAAAASUVORK5CYII="""

import sys
import subprocess
import pty
import os
import base64
import ctypes
import ctypes.util

from PyObjCTools import AppHelper
from AppKit import *

class GoAgentOSX(NSObject):

    def applicationDidFinishLaunching_(self, notification):
        self.setupUI()
        self.startGoAgent()
        self.registerObserver()

    def windowWillClose_(self, notification):
        self.stopGoAgent()
        NSApp.terminate_(self)

    def setupUI(self):
        self.statusbar = NSStatusBar.systemStatusBar()
        # Create the statusbar item
        self.statusitem = self.statusbar.statusItemWithLength_(NSVariableStatusItemLength)
        # Set initial image
        raw_data = base64.b64decode(''.join(GOAGENT_ICON_DATA.strip().splitlines()))
        self.image_data = NSData.dataWithBytes_length_(raw_data, len(raw_data))
        self.image = NSImage.alloc().initWithData_(self.image_data)
        self.statusitem.setImage_(self.image)
        # Let it highlight upon clicking
        self.statusitem.setHighlightMode_(1)
        # Set a tooltip
        self.statusitem.setToolTip_(GOAGENT_TITLE)

        # Build a very simple menu
        self.menu = NSMenu.alloc().init()
        # Show Menu Item
        menuitem = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_('Show', 'show:', '')
        self.menu.addItem_(menuitem)
        # Hide Menu Item
        menuitem = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_('Hide', 'hide2:', '')
        self.menu.addItem_(menuitem)
        # Rest Menu Item
        menuitem = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_('Reload', 'reset:', '')
        self.menu.addItem_(menuitem)
        # Default event
        menuitem = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_('Quit', 'exit:', '')
        self.menu.addItem_(menuitem)
        # Bind it to the status item
        self.statusitem.setMenu_(self.menu)

        # Console window
        frame = NSMakeRect(0, 0, 550, 350)
        self.console_window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(frame, NSClosableWindowMask | NSTitledWindowMask, NSBackingStoreBuffered, False)
        self.console_window.setTitle_(GOAGENT_TITLE)
        self.console_window.setDelegate_(self)

        # Console view inside a scrollview
        self.scroll_view = NSScrollView.alloc().initWithFrame_(frame)
        self.scroll_view.setBorderType_(NSNoBorder)
        self.scroll_view.setHasVerticalScroller_(True)
        self.scroll_view.setHasHorizontalScroller_(False)
        self.scroll_view.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)

        self.console_view = NSTextView.alloc().initWithFrame_(frame)
        self.console_view.setVerticallyResizable_(True)
        self.console_view.setHorizontallyResizable_(True)
        self.console_view.setAutoresizingMask_(NSViewWidthSizable)

        self.scroll_view.setDocumentView_(self.console_view)

        contentView = self.console_window.contentView()
        contentView.addSubview_(self.scroll_view)

        # Hide dock icon
        NSApp.setActivationPolicy_(NSApplicationActivationPolicyProhibited)

    def registerObserver(self):
        nc = NSWorkspace.sharedWorkspace().notificationCenter()
        nc.addObserver_selector_name_object_(self, 'exit:', NSWorkspaceWillPowerOffNotification, None)

    def startGoAgent(self):
        for pycmd in ('python2.7', 'python2', 'python'):
            if os.system('which %s' % pycmd) == 0:
                cmd = '/usr/bin/env %s proxy.py' % pycmd
                break
        self.master, self.slave = pty.openpty()
        self.pipe = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=self.slave, stderr=self.slave, close_fds=True)
        self.pipe_fd = os.fdopen(self.master)

        self.performSelectorInBackground_withObject_('readProxyOutput', None)

    def stopGoAgent(self):
        self.pipe.terminate()

    def refreshDisplay_(self, line):
        #print line
        self.console_view.textStorage().mutableString().appendString_(line)
        need_scroll = NSMaxY(self.console_view.visibleRect()) >= NSMaxY(self.console_view.bounds())
        if need_scroll:
            range = NSMakeRange(len(self.console_view.textStorage().mutableString()), 0)
            self.console_view.scrollRangeToVisible_(range)

    def readProxyOutput(self):
        while(True):
            line = self.pipe_fd.readline()
            self.performSelectorOnMainThread_withObject_waitUntilDone_('refreshDisplay:', line, None)

    def show_(self, notification):
        self.console_window.center()
        self.console_window.orderFrontRegardless()
        self.console_window.setIsVisible_(True)

    def hide2_(self, notification):
        self.console_window.setIsVisible_(False)
        #self.console_window.orderOut(None)

    def reset_(self, notification):
        self.console_view.setString_('')
        self.stopGoAgent()
        self.startGoAgent()

    def exit_(self, notification):
        self.stopGoAgent()
        NSApp.terminate_(self)


def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    app = NSApplication.sharedApplication()
    delegate = GoAgentOSX.alloc().init()
    app.setDelegate_(delegate)

    AppHelper.runEventLoop()

if __name__ == '__main__':
    main()
