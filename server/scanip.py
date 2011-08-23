#!/usr/bin/env python
# -*- coding: utf-8 -*-

__version__ = '1.0'
__author__ = "phus.lu@gmail.com"

import sys, os, re, time
import socket, urllib2, threading, Queue

THREAD_NUMBER = 16
TIMEOUT = 2
KEYWORD = 'Google'

queue = Queue.Queue()

for ip in ('%s.%d' % (socket.gethostbyname('www.g.cn').rpartition('.')[0], i) for i in xrange(1,255)):
    queue.put(ip)
for i in xrange(THREAD_NUMBER):
    queue.put(None)

def ping():
    while 1:
        ip = queue.get()
        if ip is None:
            break
        try:
            url = 'https://%s/' % ip
            resp = urllib2.urlopen(url,timeout=TIMEOUT)
            if KEYWORD in resp.read():
                sys.stdout.write(ip+'\n')
        except:
            pass

threads = []
for i in xrange(THREAD_NUMBER):
    t = threading.Thread(target=ping)
    t.start()
    threads.append(t)
for t in threads:
    t.join()
