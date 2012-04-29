#!/usr/bin/env python
# coding=utf-8

__version__ = '1.9.0'
__author__ =  'phus.lu@gmail.com'
__password__ = ''

import gevent, gevent.monkey
gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)

import sys
import os
import time
import re
import socket
import select
import errno
import gevent.server

class LocalFetchServer(gevent.server.DatagramServer):
    def handle(self, data, address):
        print len(data), address
        self.socket.sendto('ooops', address)

if __name__ == '__main__':
    server = LocalFetchServer(('', 53))
    server.serve_forever()
