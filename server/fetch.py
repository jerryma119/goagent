#!/usr/bin/env python
# coding=utf-8
# Based on GAppProxy by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

__version__ = '1.5'
__author__ =  'phus.lu@gmail.com'
__password__ = ''

import sys, os, re, time, struct, zlib, binascii, logging
from google.appengine.api import urlfetch
from google.appengine.runtime import apiproxy_errors, DeadlineExceededError

FetchMax = 2
FetchMaxSize = 1024*1024
Deadline = (16, 32)

def gae_encode_data(dic):
    return '&'.join('%s=%s' % (k, binascii.b2a_hex(str(v))) for k, v in dic.iteritems())

def gae_decode_data(qs):
    return dict((k, binascii.a2b_hex(v)) for k, v in (x.split('=') for x in qs.split('&')))

def print_response(status, headers, content):
    strheaders = gae_encode_data(headers)
    if 'text' == headers['content-type'][:4]:
        data = 'Content-Type: image/gif\r\n\r\n1' + zlib.compress('%s%s%s' % (struct.pack('>3I', status, len(strheaders), len(content)), strheaders, content))
    else:
        data = 'Content-Type: image/gif\r\n\r\n0%s%s%s' % (struct.pack('>3I', status, len(strheaders), len(content)), strheaders, content)
    sys.stdout.write(data)

def print_notify(method, url, status, content):
    logging.warning('%r Failed: url=%r, status=%r', method, url, status)
    content = '<h2>Fetch Server Info</h2><hr noshade="noshade"><p>%s %r</p><p>Code: %d</p><p>Message: %s</p>' % (method, url, status, content)
    headers = {'content-type':'text/html', 'content-length':len(content)}
    print_response(status, headers, content)

def post():
    request = gae_decode_data(zlib.decompress(sys.stdin.read()))
    #logging.debug('post() get fetch request %s', request)

    method = request['method']
    url = request['url']
    payload = request['payload']

    if __password__ and __password__ != request.get('password', ''):
        return print_notify(method, url, 403, 'Wrong password.')

    fetch_method = getattr(urlfetch, method, '')
    if not fetch_method:
        return print_notify(method, url, 501, 'Invalid Method')

    if 'http' != url[:4]:
        return print_notify(method, url, 501, 'Unsupported Scheme')

    deadline = Deadline[1 if payload else 0]

    fetch_range = 'bytes=0-%d' % (FetchMaxSize - 1)
    headers = {}
    for line in request['headers'].splitlines():
        key, _, value = line.partition(':')
        if not value:
            continue
        key, value = key.strip().lower(), value.strip()
        if key =='range':
            m = re.search(r'(\d+)?-(\d+)?', value)
            if m is None:
                continue
            start, end = m.group(1, 2)
            if not start and not end:
                continue
            if not start and int(end) > FetchMaxSize:
                end = '1023'
            elif not end or int(end)-int(start)+1 > FetchMaxSize:
                end = str(FetchMaxSize - 1 + int(start))
            fetch_range = ('bytes=%s-%s' % (start, end))
        headers[key] = value
    headers['connection'] = 'close'

    for i in xrange(int(request.get('fetchmax', FetchMax))):
        try:
            response = urlfetch.fetch(url, payload, fetch_method, headers, follow_redirects=False, deadline=deadline, validate_certificate=False)
            #if method=='GET' and len(response.content)>0x1000000:
            #    raise urlfetch.ResponseTooLargeError(None)
            break
        except apiproxy_errors.OverQuotaError, e:
            time.sleep(4)
        except DeadlineExceededError:
            logging.error('DeadlineExceededError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = Deadline[1]
        except urlfetch.InvalidURLError, e:
            return print_notify(method, url, 501, 'Invalid URL: %s' % e)
        except urlfetch.ResponseTooLargeError, e:
            if method == 'GET':
                deadline = Deadline[1]
                headers['Range'] = fetch_range
            else:
                print_notify(method, url, 500, 'Response Too Large: %s' % e)
        except Exception, e:
            if i==0 and method=='GET':
                deadline = Deadline[1]
                headers['Range'] = fetch_range
    else:
        print_notify(method, url, 500, 'Urlfetch error: %s' % e)

    headers = dict((k,v) for k, v in response.headers.iteritems() if k[0] != 'x')
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
        headers['set-cookie'] = '\r\nSet-Cookie: '.join(cookies)
    headers['connection'] = 'close'
    return print_response(response.status_code, headers, response.content)

def get():
    print 'Content-Type: text/html; charset=utf-8'
    print ''
    print '''\
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

        <tr><td align="center">
            <img src="https://code.google.com/appengine/images/appengine-silver-120x30.gif" />
        </td></tr>
        <tr><td align="center"><hr></td></tr>
    </table>
</body>
</html>
''' % dict(version=__version__)

def main():
    if os.environ['REQUEST_METHOD'] == 'POST':
        post()
    else:
        get()

if __name__ == '__main__':
    main()