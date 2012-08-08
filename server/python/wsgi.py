#!/usr/bin/env python
# coding=utf-8

__version__ = '1.8.11'
__author__ =  'phus.lu@gmail.com'
__password__ = ''

import sys, os, re, time, struct, zlib, binascii, logging, httplib, urllib2, urlparse
try:
    from google.appengine.api import urlfetch
    from google.appengine.runtime import apiproxy_errors, DeadlineExceededError
except ImportError:
    urlfetch = None
try:
    import sae
except ImportError:
    sae = None
try:
    import socket, select, ssl, thread
except:
    socket = None

FetchMax = 3
FetchMaxSize = 1024*1024*4
Deadline = 30

def io_copy(source, dest):
    try:
        io_read  = getattr(source, 'read', None) or getattr(source, 'recv')
        io_write = getattr(dest, 'write', None) or getattr(dest, 'sendall')
        while 1:
            data = io_read(8192)
            if not data:
                break
            io_write(data)
    except Exception as e:
        logging.exception('io_copy(source=%r, dest=%r) error: %s', source, dest, e)
    finally:
        pass

def httplib_headers_normalize(response_headers):
    """return (headers, content_encoding, transfer_encoding)"""
    headers = []
    for keyword, value in response_headers:
        if keyword == 'connection':
            headers.append(('Connection', 'close'))
        elif keyword != 'set-cookie':
            headers.append((keyword.title(), value))
        else:
            scs = value.split(', ')
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
            headers += [('Set-Cookie', x) for x in cookies]
    return headers

class HTTPNoRedirectHandler(urllib2.HTTPRedirectHandler):
    http_error_301 = http_error_302 = http_error_303 = http_error_304 = http_error_307 = urllib2.HTTPDefaultErrorHandler.http_error_default

def paas_application(environ, start_response):
    cookie  = environ['HTTP_COOKIE']
    request = decode_data(zlib.decompress(cookie.decode('base64')))

    url     = request['url']
    method  = request['method']

    logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')

    headers = dict((k.title(),v.lstrip()) for k, _, v in (line.partition(':') for line in request['headers'].splitlines()))

    payload = None
    content_length = int(headers.get('Content-Length',0))
    if content_length:
        payload = environ['wsgi.input'].read(content_length)

    if method != 'CONNECT':
        try:
            opener   = urllib2.build_opener(HTTPNoRedirectHandler)
            request  = urllib2.Request(url, data=payload, headers=headers)
            request.get_method = lambda:method

            try:
                response = opener.open(request)
            except urllib2.HTTPError as http_error:
                response = http_error
            except urllib2.URLError as url_error:
                raise

            headers = [(k, v.strip()) for k, _, v in (line.partition(':') for line in response.headers.headers) if k != 'Transfer-Encoding']
            start_response('%d %s' % (response.code, response.msg), headers)
            while 1:
                data = response.read(8192)
                if not data:
                    response.close()
                    raise StopIteration
                else:
                    yield data
        except httplib.HTTPException as e:
            raise

def encode_data(dic):
    return '&'.join('%s=%s' % (k, binascii.b2a_hex(v)) for k, v in dic.iteritems() if v)

def decode_data(qs):
    return dict((k,binascii.a2b_hex(v)) for k, _, v in (x.partition('=') for x in qs.split('&')))

def send_response(start_response, status, headers, content, content_type='image/gif'):
    strheaders = encode_data(headers)
    #logging.debug('response status=%s, headers=%s, content length=%d', status, headers, len(content))
    if headers.get('content-type', '').startswith(('text/', 'application/json', 'application/javascript')):
        data = '1' + zlib.compress('%s%s%s' % (struct.pack('>3I', status, len(strheaders), len(content)), strheaders, content))
    else:
        data = '0%s%s%s' % (struct.pack('>3I', status, len(strheaders), len(content)), strheaders, content)
    start_response('200 OK', [('Content-type', content_type)])
    return [data]

def send_notify(start_response, method, url, status, content):
    logging.warning('%r Failed: url=%r, status=%r', method, url, status)
    content = '<h2>Python Server Fetch Info</h2><hr noshade="noshade"><p>%s %r</p><p>Return Code: %d</p><p>Message: %s</p>' % (method, url, status, content)
    send_response(start_response, status, {'content-type':'text/html'}, content)

def gae_post(environ, start_response):
    request = decode_data(zlib.decompress(environ['wsgi.input'].read(int(environ['CONTENT_LENGTH']))))
    #logging.debug('post() get fetch request %s', request)

    method = request['method']
    url = request['url']
    payload = request['payload']

    if __password__ and __password__ != request.get('password', ''):
        return send_notify(start_response, method, url, 403, 'Wrong password.')

    fetchmethod = getattr(urlfetch, method, '')
    if not fetchmethod:
        return send_notify(start_response, method, url, 501, 'Invalid Method')

    deadline = Deadline

    headers = dict((k.title(),v.lstrip()) for k, _, v in (line.partition(':') for line in request['headers'].splitlines()))
    headers['Connection'] = 'close'

    errors = []
    for i in xrange(FetchMax if 'fetchmax' not in request else int(request['fetchmax'])):
        try:
            response = urlfetch.fetch(url, payload, fetchmethod, headers, False, False, deadline, False)
            break
        except apiproxy_errors.OverQuotaError, e:
            time.sleep(4)
        except DeadlineExceededError, e:
            errors.append(str(e))
            logging.error('DeadlineExceededError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = Deadline * 2
        except urlfetch.DownloadError, e:
            errors.append(str(e))
            logging.error('DownloadError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = Deadline * 2
        except urlfetch.InvalidURLError, e:
            return send_notify(start_response, method, url, 501, 'Invalid URL: %s' % e)
        except urlfetch.ResponseTooLargeError, e:
            response = e.response
            logging.error('DownloadError(deadline=%s, url=%r) response(%s)', deadline, url, response and response.headers)
            if response and response.headers.get('content-length'):
                response.status_code = 206
                response.headers['accept-ranges']  = 'bytes'
                response.headers['content-range']  = 'bytes 0-%d/%s' % (len(response.content)-1, response.headers['content-length'])
                response.headers['content-length'] = len(response.content)
                break
            else:
                headers['Range'] = 'bytes=0-%d' % FetchMaxSize
            deadline = Deadline * 2
        except Exception, e:
            errors.append(str(e))
            if i==0 and method=='GET':
                deadline = Deadline * 2
    else:
        return send_notify(start_response, method, url, 500, 'Python Server: Urlfetch error: %s' % errors)

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
        headers['set-cookie'] = '\r\nSet-Cookie: '.join(cookies)
    headers['connection'] = 'close'
    return send_response(start_response, response.status_code, headers, response.content)

def gae_get(environ, start_response):
    timestamp = long(os.environ['CURRENT_VERSION_ID'].split('.')[1])/pow(2,28)
    ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp+8*3600))
    html = u'GoAgent Python Server %s \u5df2\u7ecf\u5728\u5de5\u4f5c\u4e86\uff0c\u90e8\u7f72\u65f6\u95f4 %s\n' % (__version__, ctime)
    start_response('200 OK', [('Content-type', 'text/plain; charset=utf-8')])
    return [html.encode('utf8')]

def app(environ, start_response):
    if urlfetch and environ['REQUEST_METHOD'] == 'POST':
        return gae_post(environ, start_response)
    elif not urlfetch:
        return paas_application(environ, start_response)
    else:
        return gae_get(environ, start_response)

if sae:
    application = sae.create_wsgi_app(app)
else:
    application = app

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    import gevent, gevent.pywsgi, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
    def read_requestline(self):
        line = self.rfile.readline(8192)
        while line == '\r\n':
            line = self.rfile.readline(8192)
        return line
    gevent.pywsgi.WSGIHandler.read_requestline = read_requestline
    host, _, port = sys.argv[1].rpartition(':') if len(sys.argv) == 2 else ('', ':', 443)
    if '-ssl' in sys.argv[1:]:
        ssl_args = dict(certfile=os.path.splitext(__file__)[0]+'.pem')
    else:
        ssl_args = dict()
    server = gevent.pywsgi.WSGIServer((host, int(port)), application, log=None, **ssl_args)
    server.environ.pop('SERVER_SOFTWARE')
    logging.info('serving %s://%s:%s/wsgi.py', 'https' if ssl_args else 'http', server.address[0] or '0.0.0.0', server.address[1])
    server.serve_forever()

