#!/usr/bin/env python
# coding=utf-8
# Based on GAppProxy by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

__version__ = '1.6'
__author__ =  'phus.lu@gmail.com'
__password__ = ''

import sys, os, re, time, struct, zlib, binascii, logging
import webapp2
from google.appengine.api import urlfetch
from google.appengine.runtime import apiproxy_errors, DeadlineExceededError

FetchMax = 3
FetchMaxSize = 1024*1024
Deadline = (30, 60)

def encode_data(dic):
    return '&'.join('%s=%s' % (k, binascii.b2a_hex(str(v))) for k, v in dic.iteritems())

def decode_data(qs):
    return dict((k, binascii.a2b_hex(v)) for k, _, v in (x.partition('=') for x in qs.split('&')))

class MainPage(webapp2.RequestHandler):

    def send_response(self, status, headers, content):
        strheaders = encode_data(headers)
        #logging.debug('response status=%s, headers=%s, content length=%d', status, headers, len(content))
        if 'text' == headers.get('content-type', 'text/plain')[:4]:
            data = '1' + zlib.compress('%s%s%s' % (struct.pack('>3I', status, len(strheaders), len(content)), strheaders, content))
        else:
            data = '0%s%s%s' % (struct.pack('>3I', status, len(strheaders), len(content)), strheaders, content)
        self.response.headers['Content-Type'] = 'image/gif'
        self.response.out.write(data)

    def send_notify(self, method, url, status, content):
        logging.warning('%r Failed: url=%r, status=%r', method, url, status)
        content = '<h2>Fetch Server Info</h2><hr noshade="noshade"><p>%s %r</p><p>Return Code: %d</p><p>Message: %s</p>' % (method, url, status, content)
        self.send_response(status, {'content-type':'text/html'}, content)

    def post(self):
        request = decode_data(zlib.decompress(self.request.body))
        #logging.debug('post() get fetch request %s', request)

        method = request['method']
        url = request['url']
        payload = request['payload']

        if __password__ and __password__ != request.get('password', ''):
            return self.send_notify(method, url, 403, 'Wrong password.')

        fetchmethod = getattr(urlfetch, method, '')
        if not fetchmethod:
            return self.send_notify(method, url, 501, 'Invalid Method')

        if 'http' != url[:4]:
            return self.send_notify(method, url, 501, 'Unsupported Scheme')

        deadline = Deadline[1 if payload else 0]

        headers = dict((k, v.lstrip()) for k, _, v in (line.partition(':') for line in request['headers'].splitlines()))
        headers['connection'] = 'close'

        fetchrange = 'bytes=0-%d' % (FetchMaxSize - 1)
        if 'range' in headers:
            try:
                start, end = re.search(r'(\d+)?-(\d+)?', headers['range']).group(1, 2)
                if start or end:
                    if not start and int(end) > FetchMaxSize:
                        end = '1023'
                    elif not end or int(end)-int(start)+1 > FetchMaxSize:
                        end = str(FetchMaxSize - 1 + int(start))
                    fetchrange = 'bytes=%s-%s' % (start, end)
            except:
                pass

        errors = []
        for i in xrange(int(request.get('fetchmax', FetchMax))):
            try:
                response = urlfetch.fetch(url, payload, fetchmethod, headers, False, False, deadline, False)
                if response.status_code < 400:
                    break
                else:
                    errors.append('%s %r return %s' % (method, url, response.status_code))
                    time.sleep(4)
            except apiproxy_errors.OverQuotaError, e:
                time.sleep(4)
            except DeadlineExceededError, e:
                errors.append(str(e))
                logging.error('DeadlineExceededError(deadline=%s, url=%r)', deadline, url)
                time.sleep(1)
                deadline = Deadline[1]
            except urlfetch.DownloadError, e:
                errors.append(str(e))
                logging.error('DownloadError(deadline=%s, url=%r)', deadline, url)
                time.sleep(1)
                deadline = Deadline[1]
            except urlfetch.InvalidURLError, e:
                return self.send_notify(method, url, 501, 'Invalid URL: %s' % e)
            except urlfetch.ResponseTooLargeError, e:
                if method == 'GET':
                    deadline = Deadline[1]
                    headers['range'] = fetchrange
                else:
                    return self.send_notify(method, url, 500, 'Response Too Large: %s' % e)
            except Exception, e:
                errors.append(str(e))
                if i==0 and method=='GET':
                    deadline = Deadline[1]
                    headers['range'] = fetchrange
        else:
            return self.send_notify(method, url, 500, 'Urlfetch error: %s' % errors)

        headers = response.headers
        if 'set-cookie' in headers:
            scs = headers['set-cookie'].split(', ')
            cookies = []
            i = -1
            for sc in scs:
                if re.match(r'[^ =]+ ', sc):
                    try:
                        cookies[i] = '%s, %s' % (cookies[i], sc)
                    except IndexError:
                        pass
                else:
                    cookies.append(sc)
                    i += 1
            headers['set-cookie'] = '\r\nset-cookie: '.join(cookies)
        headers['connection'] = 'close'
        return self.send_response(response.status_code, headers, response.content)

    def get(self):
        self.response.headers['Content-Type'] = 'text/html; charset=utf-8'
        self.response.out.write('''\
<html>
<head>
    <link rel="icon" type="image/vnd.microsoft.icon" href="https://ssl.gstatic.com/codesite/ph/images/phosting.ico">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>GoAgent %(version)s 已经在工作了</title>
</head>
<body>
    <table width="800" border="0" align="center">
        <tr><td align="center"><hr></td></tr>
        <tr><td align="center">
            <b><h1>GoAgent %(version)s 已经在工作了</h1></b>
        </td></tr>
        <tr><td align="center"><hr></td></tr>

        <tr><td align="center">
            GoAgent是一个开源的HTTP Proxy软件,使用Python编写,运行于Google App Engine平台上.
        </td></tr>
        <tr><td align="center"><hr></td></tr>

        <tr><td align="center">
            更多相关介绍,请参考<a href="http://code.google.com/p/goagent/">GoAgent项目主页</a>.
        </td></tr>
        <tr><td align="center"><hr></td></tr>

    </table>
</body>
</html>
''' % dict(version=__version__))

app = webapp2.WSGIApplication([('/fetch.py', MainPage)])
