#!/usr/bin/env python
# coding=utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '3.1.2'
__password__ = '123456'
__hostsdeny__ = ()  # __hostsdeny__ = ('.youtube.com', '.youku.com')

import gevent.monkey
gevent.monkey.patch_all(subprocess=True)

import sys
import time
import itertools
import logging
import string
import urlparse
import httplib


TIMEOUT = 20


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
        self.__key_gen = itertools.cycle([ord(x) for x in key]).next

    def encrypt(self, data):
        return ''.join(chr(ord(x) ^ self.__key_gen()) for x in data)


def application(environ, start_response):
    if environ['REQUEST_METHOD'] == 'GET':
        start_response('302 Found', [('Location', 'https://www.google.com')])
        raise StopIteration

    query_string = environ['QUERY_STRING']
    kwargs = dict(urlparse.parse_qsl(query_string))
    host = kwargs.pop('host')
    port = int(kwargs.pop('port'))
    timeout = int(kwargs.get('timeout') or TIMEOUT)

    logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], host, port, 'HTTP/1.1')

    if __password__ and __password__ != kwargs.get('password'):
        random_host = 'g%d%s' % (int(time.time()*100), environ['HTTP_HOST'])
        conn = httplib.HTTPConnection(random_host, timeout=timeout)
        conn.request('GET', '/')
        response = conn.getresponse(True)
        status_line = '%s %s' % (response.status, httplib.responses.get(response.status, 'OK'))
        start_response(status_line, response.getheaders())
        yield response.read()
        raise StopIteration

    if __hostsdeny__ and host.endswith(__hostsdeny__):
        start_response('403 Forbidden', [('Content-Type', 'text/html')])
        yield message_html('403 Forbidden Host', 'Hosts Deny(%s)' % host, detail='host=%r' % host)
        raise StopIteration

    wsgi_input = environ['wsgi.input']

    remote = socket.create_connection((host, port), timeout=timeout)
    if kwargs.get('ssl'):
        remote = ssl.wrap_socket(remote)

    while True:
        data = wsgi_input.read(8192)
        if not data:
            break
        remote.send(data)
    start_response('200 OK', [])
    forward_socket(wsgi_input.socket, remote)
    yield 'out'


if __name__ == '__main__':
    import gevent.wsgi
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    server = gevent.wsgi.WSGIServer(('', int(sys.argv[1])), application)
    logging.info('local paas_application serving at %s:%s', server.address[0], server.address[1])
    server.serve_forever()
