#!/usr/bin/env python
# coding:utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '1.4'

import sys
import os
import re
import time
import thread
import platform

try:
    import pygtk
    pygtk.require('2.0')
    import gtk
    gtk.gdk.threads_init()
except Exception:
    sys.exit(os.system(u'gdialog --title "GoAgent GTK" --msgbox "\u8bf7\u5b89\u88c5 python-gtk2" 15 60'.encode(sys.getfilesystemencoding() or sys.getdefaultencoding(), 'replace')))
try:
    import pynotify
    pynotify.init('GoAgent Notify')
except ImportError:
    pynotify = None
try:
    import appindicator
except ImportError:
    sys.exit(gtk.MessageDialog (None, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, u'\u8bf7\u5b89\u88c5 python-appindicator').run())
try:
    import vte
except ImportError:
    sys.exit(gtk.MessageDialog (None, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, u'\u8bf7\u5b89\u88c5 python-vte').run())

def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        import time
        time.sleep(seconds)
        return target(*args, **kwargs)
    return thread.start_new_thread(wrap, args, kwargs)

def drop_desktop():
    filename = os.path.abspath(__file__)
    dirname = os.path.dirname(filename)
    DESKTOP_FILE = '''\
#!/usr/bin/env xdg-open
[Desktop Entry]
Type=Application
Name=GoAgent GTK
Comment=GoAgent GTK Launcher
Categories=Network;Proxy;
Exec=/usr/bin/env python "%s"
Icon=%s/logo.png
Terminal=false
StartupNotify=true
''' % (filename, dirname)
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
    message = u'GoAgent已经启动，单击托盘图标可以最小化'
    fail_message = u'GoAgent启动失败，请查看控制台窗口的错误信息。'

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

        spawn_later(0.5, self.show_startup_notify)

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

    def show_notify(self, message=None, timeout=None):
        if pynotify and message:
            notification = pynotify.Notification('GoAgent Notify', message)
            notification.set_hint('x', 200)
            notification.set_hint('y', 400)
            if timeout:
                notification.set_timeout(timeout)
            notification.show()

    def show_startup_notify(self):
        if self.check_child_exists():
            self.show_notify(self.message, timeout=3)

    def check_child_exists(self):
        if self.childpid <= 0:
            return False
        cmd = 'ps -p %s' % self.childpid
        lines = os.popen(cmd).read().strip().splitlines()
        if len(lines) < 2:
            return False
        return True

    def on_child_exited(self, term):
        if self.terminal.get_child_exit_status() == 0:
            gtk.main_quit()
        else:
            self.show_notify(self.fail_message)

    def on_show(self, widget, data=None):
        self.window.show_all()
        self.window.present()
        self.terminal.feed('\r')

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
