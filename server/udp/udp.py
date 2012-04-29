#!/usr/bin/env python
# coding=utf-8
# Based on GAppProxy by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

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
