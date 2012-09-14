#!/usr/bin/env python
# coding:utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '2.0.5'

import sys
import os
import re
import time
import pygtk
pygtk.require('2.0')
import gtk
import appindicator

try:
    import vte
except ImportError:
    gtk.MessageDialog (None, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, u'请安装 python-vte').run()
    sys.exit (1)

XPM_DATA = [
		"16 16 102 2",
		"  	c None",
		". 	c #4E8DC0",
		"+ 	c #4A86BA",
		"@ 	c #4883B4",
		"# 	c #447EAD",
		"$ 	c #4078A7",
		"% 	c #3C719E",
		"& 	c #376896",
		"* 	c #4C8ABC",
		"= 	c #FFFFFF",
		"- 	c #457FAF",
		"; 	c #4179A8",
		"> 	c #3E74A2",
		", 	c #3A6F9B",
		"' 	c #366994",
		") 	c #4985B7",
		"! 	c #4680B1",
		"~ 	c #427BAA",
		"{ 	c #3E75A3",
		"] 	c #3B709D",
		"^ 	c #376A96",
		"/ 	c #4C8ABF",
		"( 	c #4885B6",
		"_ 	c #437DAD",
		": 	c #3D74A1",
		"< 	c #396C96",
		"[ 	c #366690",
		"} 	c #386C97",
		"| 	c #5291C6",
		"1 	c #4F8DC1",
		"2 	c #4B88BB",
		"3 	c #447DAD",
		"4 	c #4078A6",
		"5 	c #3D73A0",
		"6 	c #396D99",
		"7 	c #FFE255",
		"8 	c #FDDD4A",
		"9 	c #F9D53E",
		"0 	c #508FC3",
		"a 	c #4C89BC",
		"b 	c #4884B5",
		"c 	c #326087",
		"d 	c #FFDE4B",
		"e 	c #FFDA41",
		"f 	c #FDD536",
		"g 	c #4D8BBE",
		"h 	c #4680B0",
		"i 	c #3B709C",
		"j 	c #356892",
		"k 	c #ECCE45",
		"l 	c #FFDA42",
		"m 	c #FFD637",
		"n 	c #FFD32D",
		"o 	c #4A87B9",
		"p 	c #4781B2",
		"q 	c #437CAB",
		"r 	c #3F76A5",
		"s 	c #366993",
		"t 	c #FDD941",
		"u 	c #FFD738",
		"v 	c #FFCF23",
		"w 	c #4681B2",
		"x 	c #366791",
		"y 	c #F2E16E",
		"z 	c #FDE96A",
		"A 	c #FFE661",
		"B 	c #FFE357",
		"C 	c #FFDF4D",
		"D 	c #FFDB42",
		"E 	c #FFD32E",
		"F 	c #FFCF24",
		"G 	c #FDCB1B",
		"H 	c #437DAE",
		"I 	c #F5E36F",
		"J 	c #FFEB6C",
		"K 	c #FFE761",
		"L 	c #FFDB43",
		"M 	c #FFD739",
		"N 	c #FFCC1C",
		"O 	c #F3C11A",
		"P 	c #3D73A2",
		"Q 	c #3A709C",
		"R 	c #FFE762",
		"S 	c #FFE358",
		"T 	c #FFDF4E",
		"U 	c #FFD32F",
		"V 	c #E8C73D",
		"W 	c #EBC534",
		"X 	c #EBC22A",
		"Y 	c #EBBE21",
		"Z 	c #EBBB18",
		"` 	c #FFDB44",
		" .	c #FFD73A",
		"..	c #FFD330",
		"+.	c #FFD025",
		"@.	c #FDDE4E",
		"#.	c #FFD83A",
		"$.	c #FFD430",
		"%.	c #FFD026",
		"&.	c #FAD339",
		"*.	c #FDD22F",
		"=.	c #FAC719",
		"        . + @ # $ % &           ",
		"        * = - ; > , '           ",
		"        ) ! ~ { ] ^ '           ",
		"    / ( _ : < [ } ' '           ",
		"| 1 2 @ 3 4 5 6 ' ' '   7 8 9   ",
		"0 a b - ; : , ' ' ' c   d e f   ",
		"g ) h ~ { i ^ ' j c   k l m n   ",
		"o p q r s             t u n v   ",
		"w 3 4 x   y z A B C D u E F G   ",
		"H ; :   I J K B C L M E F N O   ",
		"  P Q   J R S T L M U F N N     ",
		"        R S T V W X Y Z Z       ",
		"        S T `  ...+.N           ",
		"        @.` #.$.%.= G           ",
		"          &.*.%.N =.            ",
		"                                "]

class GoAgentAppIndicator:

    def __init__(self, window):
        self.window = window

        self.ind = appindicator.Indicator("GoAgent", "indicator-messages", appindicator.CATEGORY_APPLICATION_STATUS)
        self.ind.set_status(appindicator.STATUS_ACTIVE)
        self.ind.set_attention_icon("indicator-messages-new")
        self.ind.set_icon(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'goagent.png'))

        self.menu = gtk.Menu()

        item = gtk.MenuItem(u'\u663e\u793a')
        item.connect("activate", self.show)
        item.show()
        self.menu.append(item)

        item = gtk.MenuItem(u'\u9690\u85cf')
        item.connect("activate", self.hide)
        item.show()
        self.menu.append(item)

        item = gtk.MenuItem(u'\u9000\u51fa')
        item.connect("activate", self.quit)
        item.show()
        self.menu.append(item)

        self.menu.show()

        self.ind.set_menu(self.menu)

    def show(self, widget, data=None):
        self.window.show_all()

    def hide(self, widget, data=None):
        self.window.hide_all()

    def quit(self, widget, data=None):
        gtk.main_quit()


def main():
    os.chdir(os.path.abspath(os.path.dirname(__file__)))
    v = vte.Terminal ()
    v.connect ("child-exited", lambda term: gtk.main_quit())
    #v.fork_command('python "%s/proxy.py"' % os.path.dirname(os.path.abspath(__file__)))
    v.fork_command('./proxy.py')
    window = gtk.Window()
    window.add(v)
    window.connect('delete-event', lambda window, event: gtk.main_quit())
    window.activate_focus()
    window.show_all()
    indicator = GoAgentAppIndicator(window)
    gtk.main()

if __name__ == "__main__":
    main()
