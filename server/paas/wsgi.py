#!/usr/bin/env python
# coding=utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '3.1.0'
__password__ = ''
__hostsdeny__ = ()  # __hostsdeny__ = ('.youtube.com', '.youku.com')
__content_type__ = 'image/gif'

import sys
import time
import struct
import itertools
import zlib
import logging
import httplib
import urlparse
import errno
import string
import socket
import select


HTTP_TIMEOUT = 20


def message_html(title, banner, detail=''):
    MESSAGE_TEMPLATE = '''
    <html><head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
    <title>$title</title>
    <style><!--
    body {font-family: arial,sans-serif}
    div.nav {margin-top: 1ex}
    div.nav A {font-size: 10pt; font-family: arial,sans-serif}
    span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
    div.nav A,span.big {font-size: 12pt; color: #0000cc}
    div.nav A {font-size: 10pt; color: black}
    A.l:link {color: #6f6f6f}
    A.u:link {color: green}
    //--></style>
    </head>
    <body text=#000000 bgcolor=#ffffff>
    <table border=0 cellpadding=2 cellspacing=0 width=100%>
    <tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message</b></td></tr>
    <tr><td> </td></tr></table>
    <blockquote>
    <H1>$banner</H1>
    $detail
    <p>
    </blockquote>
    <table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
    </body></html>
    '''
    return string.Template(MESSAGE_TEMPLATE).substitute(title=title, banner=banner, detail=detail)


class XORCipher(object):
    """XOR Cipher Class"""
    def __init__(self, key):
        self.__key_gen = itertools.cycle(key).next

    def encrypt(self, data):
        return ''.join(chr(ord(x) ^ ord(self.__key_gen())) for x in data)


class XORFileObject(object):
    """fileobj for xor"""
    def __init__(self, stream, key):
        self.__stream = stream
        self.__cipher = XORCipher(key)
    def __getattr__(self, attr):
        if attr not in ('__stream', '__key_gen'):
            return getattr(self.__stream, attr)
    def read(self, size=-1):
        return self.__cipher.encrypt(self.__stream.read(size))


def forward_socket(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, pongcallback=None, trans=None):
    try:
        timecount = timeout
        while 1:
            timecount -= tick
            if timecount <= 0:
                break
            (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
            if errors:
                break
            if ins:
                for sock in ins:
                    data = sock.recv(bufsize)
                    if trans:
                        data = data.translate(trans)
                    if data:
                        if sock is remote:
                            local.sendall(data)
                            timecount = maxpong or timeout
                            if pongcallback:
                                try:
                                    #remote_addr = '%s:%s'%remote.getpeername()[:2]
                                    #logging.debug('call remote=%s pongcallback=%s', remote_addr, pongcallback)
                                    pongcallback()
                                except Exception as e:
                                    logging.warning('remote=%s pongcallback=%s failed: %s', remote, pongcallback, e)
                                finally:
                                    pongcallback = None
                        else:
                            remote.sendall(data)
                            timecount = maxping or timeout
                    else:
                        return
    except socket.error as e:
        if e[0] not in (10053, 10054, 10057, errno.EPIPE):
            raise
    finally:
        if local:
            local.close()
        if remote:
            remote.close()


def application(environ, start_response):
    if environ['REQUEST_METHOD'] == 'GET':
        start_response('302 Found', [('Location', 'https://www.google.com')])
        raise StopIteration

    wsgi_input = environ['wsgi.input']
    data = wsgi_input.read(2)
    metadata_length, = struct.unpack('!h', data)
    metadata = wsgi_input.read(metadata_length)

    metadata = zlib.decompress(metadata, -zlib.MAX_WBITS)
    headers = {}
    for line in metadata.splitlines():
        if line:
            keyword, value = line.split(':', 1)
            headers[keyword.title()] = value.strip()
    method = headers.pop('G-Method')
    url = headers.pop('G-Url')
    timeout = HTTP_TIMEOUT

    kwargs = {}
    any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('G-'))

    if __password__ and __password__ != kwargs.get('password'):
        random_host = 'g%d%s' % (int(time.time()*100), environ['HTTP_HOST'])
        conn = httplib.HTTPConnection(random_host, timeout=timeout)
        conn.request('GET', '/')
        response = conn.getresponse(True)
        status_line = '%s %s' % (response.status, httplib.responses.get(response.status, 'OK'))
        start_response(status_line, response.getheaders())
        yield response.read()
        raise StopIteration

    if __hostsdeny__ and urlparse.urlparse(url).netloc.endswith(__hostsdeny__):
        start_response('403 Forbidden', [('Content-Type', 'text/html')])
        yield message_html('403 Forbidden Host', 'Hosts Deny(%s)' % url, detail='url=%r' % url)
        raise StopIteration

    headers['Connection'] = 'close'
    payload = environ['wsgi.input'].read() if 'Content-Length' in headers else None
    if 'Content-Encoding' in headers:
        if headers['Content-Encoding'] == 'deflate':
            payload = zlib.decompress(payload, -zlib.MAX_WBITS)
            headers['Content-Length'] = str(len(payload))
            del headers['Content-Encoding']

    logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')

    if method == 'CONNECT':
        if not socket:
            start_response('403 Forbidden', [('Content-Type', 'text/html')])
            yield message_html('403 Forbidden CONNECT', 'socket not available', detail='`import socket` raised ImportError')
            raise StopIteration
        rfile = wsgi_input.rfile
        sock = rfile._sock
        host, _, port = url.rpartition(':')
        port = int(port)
        remote_sock = socket.create_connection((host, port), timeout=timeout)
        start_response('200 OK', [])
        forward_socket(sock, remote_sock)
        yield 'out'
    else:
        try:
            scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
            HTTPConnection = httplib.HTTPSConnection if scheme == 'https' else httplib.HTTPConnection
            if params:
                path += ';' + params
            if query:
                path += '?' + query
            conn = HTTPConnection(netloc, timeout=timeout)
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            start_response('200 OK', [('Content-Type', __content_type__)])
            for keyword, value in response.msg.items():
                yield '%s: %s\r\n' % (keyword.title(), value)
            yield '\r\n\r\n'
            cipher = kwargs.get('password') and XORCipher(kwargs['password'][0])
            while 1:
                data = response.read(8192)
                if not data:
                    response.close()
                    break
                if not cipher:
                    yield data
                else:
                    yield cipher.encrypt(data)
        except httplib.HTTPException:
            raise


try:
    import sae
    application = sae.create_wsgi_app(application)
except ImportError:
    pass
try:
    import bae.core.wsgi
    application = bae.core.wsgi.WSGIApplication(application)
except ImportError:
    pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    import gevent
    import gevent.server
    import gevent.wsgi
    import gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)

    server = gevent.wsgi.WSGIServer(('', int(sys.argv[1])), application)
    logging.info('local paas_application serving at %s:%s', server.address[0], server.address[1])
    server.serve_forever()
