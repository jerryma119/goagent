#!/usr/bin/env python
# coding:utf-8

__version__ = '3.1.2'
__password__ = '123456'
__hostsdeny__ = ()  # __hostsdeny__ = ('.youtube.com', '.youku.com')
__content_type__ = 'image/gif'
__timeout__ = 20

try:
    import gevent
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all()
except ImportError:
    pass

import sys
import re
import time
import itertools
import functools
import logging
import string
import urlparse
import httplib
import struct
import zlib
import collections
import Queue

normcookie = functools.partial(re.compile(', ([^ =]+(?:=|$))').sub, '\\r\\nSet-Cookie: \\1')

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
        assert isinstance(key, basestring) and key
        self.__key_gen = itertools.cycle([ord(x) for x in key]).next

    def encrypt(self, data):
        return ''.join(chr(ord(x) ^ self.__key_gen()) for x in data)


def decode_request(data):
    metadata_length, = struct.unpack('!h', data[:2])
    metadata = zlib.decompress(data[2:2+metadata_length], -zlib.MAX_WBITS)
    body = data[2+metadata_length:]
    headers = dict(x.split(':', 1) for x in metadata.splitlines() if x)
    method = headers.pop('G-Method')
    url = headers.pop('G-Url')
    kwargs = {}
    any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('G-'))
    if headers.get('Content-Encoding', '') == 'deflate':
        body = zlib.decompress(body, -zlib.MAX_WBITS)
        headers['Content-Length'] = str(len(body))
        del headers['Content-Encoding']
    return method, url, headers, kwargs, body


QUEUE_MODULE = __import__('gevent.queue', fromlist=['.']) if 'gevent.wsi' in sys.modules else Queue
HTTP_CONNECTION_CACHE = collections.defaultdict(QUEUE_MODULE.PriorityQueue)

def application(environ, start_response):
    if environ['REQUEST_METHOD'] == 'GET':
        start_response('302 Found', [('Location', 'https://www.google.com')])
        raise StopIteration

    post_data = environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH') or -1))
    method, url, headers, kwargs, body = decode_request(post_data)
    scheme, netloc, path, _, query, _ = urlparse.urlparse(url)
    cipher = XORCipher(__password__[0])

    if __password__ != kwargs.get('password'):
        start_response('403 Forbidden', [('Content-Type', 'text/html')])
        yield message_html('403 Wrong Password', 'Wrong Password(%s)' % kwargs.get('password'), detail='please edit proxy.ini')
        raise StopIteration

    if __hostsdeny__ and netloc.endswith(__hostsdeny__):
        start_response('200 OK', [('Content-Type', __content_type__)])
        yield cipher.encrypt('HTTP/1.1 403 Forbidden\r\nContent-type: text/html\r\n\r\n')
        yield cipher.encrypt(message_html('403 Forbidden Host', 'Hosts Deny(%s)' % netloc, detail='url=%r' % url))
        raise StopIteration

    timeout = int(kwargs.get('timeout') or __timeout__)
    fetchmax = int(kwargs.get('fetchmax') or 3)
    ConnectionType = httplib.HTTPSConnection if scheme == 'https' else httplib.HTTPConnection
    header_sent = False
    try:
        connection = None
        response = None
        for i in xrange(fetchmax):
            try:
                while True:
                    try:
                        mtime, connection = HTTP_CONNECTION_CACHE[(scheme, netloc)].get_nowait()
                        if time.time() - mtime < 16:
                            break
                        else:
                            connection.close()
                    except Queue.Empty:
                        connection = ConnectionType(netloc, timeout=timeout)
                        break
                connection.request(method, '%s?%s' % (path, query) if query else path, body=body, headers=headers)
                response = connection.getresponse(buffering=True)
                break
            except Exception as e:
                if i == fetchmax - 1:
                    raise
        start_response('200 OK', [('Content-Type', __content_type__)])
        header_sent = True
        if response.getheader('Set-Cookie'):
            response.msg['Set-Cookie'] = normcookie(response.getheader('Set-Cookie'))
        yield cipher.encrypt('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding')))
        while True:
            data = response.read(8192)
            if not data:
                response.close()
                HTTP_CONNECTION_CACHE[(scheme, netloc)].put((time.time(), connection))
                return
            yield cipher.encrypt(data)
    except Exception as e:
        import traceback
        if not header_sent:
            start_response('200 OK', [('Content-Type', __content_type__)])
        yield cipher.encrypt('HTTP/1.1 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n')
        yield cipher.encrypt(message_html('500 Internal Server Error', 'urlfetch %r: %r' % (url, e), '<pre>%s</pre>' % traceback.format_exc()))
        raise StopIteration

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


def run_wsgi_app(address, app):
    if 'gevent' in sys.modules:
        from gevent.wsgi import WSGIServer
        return WSGIServer(address, app).serve_forever()
    else:
        from gunicorn.app.base import Application
        class GunicornApplication(Application):
            def init(self, parser, opts, args):
                return {'bind': '%s:%d' % address}
            def load(self):
                return application
        GunicornApplication().run()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    host, _, port = sys.argv[1].rpartition(':')
    logging.info('local python application serving at %s:%s', host, port)
    run_wsgi_app((host, int(port)), application)
