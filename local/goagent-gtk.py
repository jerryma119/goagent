#!/usr/bin/env python
# coding:utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '1.3'

import sys
import os
import re
import time
import platform

import pygtk
pygtk.require('2.0')
import gtk

try:
    import appindicator
except ImportError:
    sys.exit(gtk.MessageDialog (None, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, u'\u8bf7\u5b89\u88c5 python-appindicator').run())
try:
    import vte
except ImportError:
    sys.exit(gtk.MessageDialog (None, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, u'\u8bf7\u5b89\u88c5 python-vte').run())

def drop_desktop():
    filename = os.path.abspath(__file__)
    dirname = os.path.dirname(filename)
    DESKTOP_FILE = '''\
#!/usr/bin/env xdg-open
[Desktop Entry]
Name=GoAgent GTK
Comment=GoAgent GTK Shell
Categories=GTK;Utility;
Exec=/usr/bin/env python "%s"
Icon=%s/logo.png
Terminal=false
Type=Application''' % (filename, dirname)
    for dirname in map(os.path.expanduser, ['~/Desktop', u'~/桌面']):
        if os.path.isdir(dirname):
            filename = os.path.join(dirname, 'goagent-gtk.desktop')
            with open(filename, 'w') as fp:
                fp.write(DESKTOP_FILE)
            os.chmod(filename, 0755)

def should_visible():
    import ConfigParser
    ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
    config = ConfigParser.ConfigParser()
    config.read('proxy.ini')
    visible = config.has_option('listen', 'visible') and config.getint('listen', 'visible')
    return visible

#gtk.main_quit = lambda: None

class GoAgentAppIndicator:

    command = ['python', 'proxy.py']

    def __init__(self, window, terminal):
        self.window = window
        self.terminal = terminal

        self.window.add(terminal)
        self.childpid = self.terminal.fork_command(self.command[0], self.command, os.getcwd())
        if self.childpid > 0:
            self.childexited = self.terminal.connect('child-exited', self.on_child_exited);
            self.window.connect('delete-event', lambda w,e: gtk.main_quit())
        else:
            self.childexited = None

        if should_visible():
            self.window.show_all()

        self.ind = appindicator.Indicator('GoAgent', 'indicator-messages', appindicator.CATEGORY_APPLICATION_STATUS)
        self.ind.set_status(appindicator.STATUS_ACTIVE)
        self.ind.set_attention_icon('indicator-messages-new')
        self.ind.set_icon(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'logo.png'))

        self.menu = gtk.Menu()

        item = gtk.MenuItem(u'\u663e\u793a')
        item.connect('activate', self.on_show)
        item.show()
        self.menu.append(item)

        item = gtk.MenuItem(u'\u9690\u85cf')
        item.connect('activate', self.on_hide)
        item.show()
        self.menu.append(item)

        item = gtk.MenuItem(u'\u91cd\u65b0\u8f7d\u5165')
        item.connect('activate', self.on_reload)
        item.show()
        self.menu.append(item)

        item = gtk.MenuItem(u'\u9000\u51fa')
        item.connect('activate', self.on_quit)
        item.show()
        self.menu.append(item)

        self.menu.show()

        self.ind.set_menu(self.menu)

    def on_child_exited(self, term):
        if self.terminal.get_child_exit_status() == 0:
            gtk.main_quit()

    def on_show(self, widget, data=None):
        self.window.show_all()
        self.window.present()

    def on_hide(self, widget, data=None):
        self.window.hide_all()

    def on_reload(self, widget, data=None):
        if self.childexited:
            self.terminal.disconnect(self.childexited)
        os.system('kill -9 %s' % self.childpid)
        self.on_show(widget, data)
        self.childpid = self.terminal.fork_command(self.command[0], self.command, os.getcwd())
        self.childexited = self.terminal.connect('child-exited', lambda term:gtk.main_quit());

    def on_quit(self, widget, data=None):
        gtk.main_quit()

def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x:x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    if platform.dist()[0] == 'Ubuntu':
        drop_desktop()

    window = gtk.Window()
    terminal = vte.Terminal()
    indicator = GoAgentAppIndicator(window, terminal)
    gtk.main()

if __name__ == '__main__':
    main()
