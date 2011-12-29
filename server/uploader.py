#!/usr/bin/env python
# coding:utf-8

__version__ = '1.1'
__author__ = "phus.lu@gmail.com"

import sys, os, re, time
import socket
import random
import logging
sys.path.extend(['.', 'appcfg.zip'])

import fancy_urllib

class MultiplexConnection(object):
    '''multiplex tcp connection class'''

    retry = 3
    timeout = 5
    window = 8
    window_min = 4
    window_max = 60
    window_ack = 0

    def __init__(self, hosts, port):
        self.socket = None
        self._sockets = set([])
        self.connect(hosts, port, MultiplexConnection.timeout, MultiplexConnection.window)
    def connect(self, hostlist, port, timeout, window):
        for i in xrange(MultiplexConnection.retry):
            hosts = random.sample(hostlist, window) if len(hostlist) > window else hostlist
            logging.debug('MultiplexConnection try connect hosts=%s, port=%d', hosts, port)
            socks = []
            for host in hosts:
                sock_family = socket.AF_INET6 if ':' in host else socket.AF_INET
                sock = socket.socket(sock_family, socket.SOCK_STREAM)
                sock.setblocking(0)
                #logging.debug('MultiplexConnection connect_ex (%r, %r)', host, port)
                err = sock.connect_ex((host, port))
                self._sockets.add(sock)
                socks.append(sock)
            (_, outs, _) = select.select([], socks, [], timeout)
            if outs:
                self.socket = outs[0]
                self.socket.setblocking(1)
                self._sockets.remove(self.socket)
                if window > MultiplexConnection.window_min:
                    MultiplexConnection.window_ack += 1
                    if MultiplexConnection.window_ack > 10:
                        MultiplexConnection.window = window - 1
                        MultiplexConnection.window_ack = 0
                        logging.info('MultiplexConnection CONNECT port=%s OK 10 times, switch new window=%d', port, MultiplexConnection.window)
                break
            else:
                logging.warning('MultiplexConnection Cannot hosts %r:%r, window=%d', hosts, port, window)
        else:
            MultiplexConnection.window = min(int(round(window*1.5)), len(hostlist), self.window_max)
            MultiplexConnection.window_ack = 0
            raise RuntimeError(r'MultiplexConnection Connect hosts %s:%s fail %d times!' % (hosts, port, MultiplexConnection.retry))
    def close(self):
        for sock in self._sockets:
            try:
                sock.close()
                del sock
            except:
                pass
        del self._sockets

class Common(object):
    def __init__(self):
        self.HOSTS = {}
        self.GOOGLE_APPSPOT = []
        self.GOOGLE_APPSPOT += ['203.208.46.1', '203.208.46.2', '203.208.46.3', '203.208.46.4']
        self.GOOGLE_APPSPOT += ['74.125.71.83', '74.125.71.18', '74.125.71.17', '74.125.71.19']
        for host in ('www.g.cn', 'mail.google.com'):
            try:
                self.GOOGLE_APPSPOT += [x[-1][0] for x in socket.getaddrinfo(host, 443)]
            except Exception:
                logging.error('ssocket.getaddrinfo host=%r', host)
        self.GOOGLE_APPSPOT = list(set(self.GOOGLE_APPSPOT))

common = Common()

def socket_create_connection((host, port), timeout=None, source_address=None):
    logging.debug('socket_create_connection connect (%r, %r)', host, port)
    if '.google.com' in host:
        msg = 'socket_create_connection returns an empty list'
        try:
            conn = MultiplexConnection(common.GOOGLE_APPSPOT, port)
            sock = conn.socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            return sock
        except socket.error, msg:
            logging.error('socket_create_connection connect fail: (%r, %r)', common.GOOGLE_APPSPOT, port)
            sock = None
        if not sock:
            raise socket.error, msg
    else:
        msg = 'getaddrinfo returns an empty list'
        host = common.HOSTS.get(host) or host
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                if isinstance(timeout, (int, float)):
                    sock.settimeout(timeout)
                if source_address is not None:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock
            except socket.error, msg:
                if sock is not None:
                    sock.close()
        raise socket.error, msg
fancy_urllib._create_connection = socket_create_connection

def upload(dirname, appid):
    assert isinstance(dirname, basestring) and isinstance(appid, basestring)
    filename = os.path.join(dirname, 'app.yaml')
    assert os.path.isfile(filename)
    with open(filename, 'rb') as fp:
        yaml = fp.read()
    yaml=re.sub(r'application:\s*\S+', 'application: '+appid, yaml)
    with open(filename, 'wb') as fp:
        fp.write(yaml)
    import google.appengine.tools.appengine_rpc
    import google.appengine.tools.appcfg
    google.appengine.tools.appengine_rpc.HttpRpcServer.DEFAULT_COOKIE_FILE_PATH = './.appcfg_cookies'
    google.appengine.tools.appcfg.main(['appcfg', 'rollback', dirname])
    google.appengine.tools.appcfg.main(['appcfg', 'update', dirname])

def main():
    appids = raw_input('APPID:')
    if not re.match(r'[0-9a-zA-Z\-|]+', appids):
        print('appid Wrong Format, please login http://appengine.google.com to view the correct appid!')
        sys.exit(-1)
    for appid in appids.split('|'):
        upload(os.environ.get('uploaddir', 'golang').strip(), appid)

if __name__ == '__main__':
   try:
       main()
   except KeyboardInterrupt:
       pass