#!/usr/bin/env python
# -*- coding: utf-8 -*-

__version__ = '1.0'
__author__ = "phus.lu@gmail.com"

import sys, os, re, time
import socket, urllib2, threading, Queue
import logging
import ssl
import OpenSSL

logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%d/%b/%Y %H:%M:%S]')

THREAD_NUMBER = 32
TIMEOUT = 2

queue = Queue.Queue()

for ip in ('%s.%d' % (socket.gethostbyname('www.google.com.hk').rpartition('.')[0], i) for i in xrange(1,255)):
    queue.put(ip)
for i in xrange(THREAD_NUMBER):
    queue.put(None)

def ping():
    while 1:
        ip = queue.get()
        if ip is None:
            break
        try:
            cert = ssl.get_server_certificate((ip, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            if '*.google.com' in str(x509.get_subject()):
                sys.stdout.write(ip+'\n')
        except Exception, e:
            #logging.info('something wrong, %s', e)
            pass

threads = []
for i in xrange(THREAD_NUMBER):
    t = threading.Thread(target=ping)
    t.start()
    threads.append(t)
for t in threads:
    t.join()
