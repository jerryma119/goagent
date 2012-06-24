#!/usr/bin/env python
# coding=utf-8

__version__ = '1.8.11'
__author__ =  'phus.lu@gmail.com'
__password__ = ''

import sys, os, re, time, struct, zlib, binascii, logging, httplib, urlparse
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
    import socket, select, ssl
except:
    socket = None

FetchMax = 3
FetchMaxSize = 1024*1024*4
Deadline = 30

def socket_forward(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, idlecall=None):
    timecount = timeout
    try:
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
                    if data:
                        if sock is local:
                            remote.sendall(data)
                            timecount = maxping or timeout
                        else:
                            local.sendall(data)
                            timecount = maxpong or timeout
                    else:
                        return
            else:
                if idlecall:
                    try:
                        idlecall()
                    except Exception:
                        logging.exception('socket_forward idlecall fail')
                    finally:
                        idlecall = None
    except Exception:
        logging.exception('socket_forward error')
        raise
    finally:
        if idlecall:
            idlecall()

def socks5_server(sock, rfile=None):
    if not rfile:
        rfile = sock.makefile('rb', -1)
    # 1. Version
    rfile.read(ord(rfile.read(2)[1]))
    sock.send(b'\x05\x00');
    # 2. Request
    _, mode, _, addrtype = rfile.read(4)
    if addrtype == b'\x01':       # IPv4
        host = socket.inet_ntoa(rfile.read(4))
    elif addrtype == b'\x03':     # Domain name
        host = rfile.read(ord(rfile.read(1)[0]))
    port = int(struct.unpack('>H', rfile.read(2))[0])
    reply = b'\x05\x00\x00\x01'
    try:
        logging.info('socks5_server mode=%r', mode)
        if mode == b'\x01':  # 1. TCP Connect
            remote = socket.create_connection((host, port))
            logging.info('TCP Connect to %s:%s', host, port)
            local = remote.getsockname()
            reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
        else:
            reply = b'\x05\x07\x00\x01' # Command not supported
    except socket.error:
        # Connection refused
        reply = b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
    sock.send(reply)
    # 3. Transfering
    if reply[1] == b'\x00':  # Success
        if mode == b'\x01':    # 1. Tcp connect
            socket_forward(sock, remote)

def paas_socks5(environ, start_response):
    wsgi_input = environ['wsgi.input']
    sock = None
    rfile = None
    if hasattr(wsgi_input, 'rfile'):
        sock = wsgi_input.rfile._sock
        rfile = wsgi_input.rfile
    elif hasattr(wsgi_input, '_sock'):
        sock = wsgi_input._sock
    elif hasattr(wsgi_input, 'fileno'):
        sock = socket.fromfd(wsgi_input.fileno())
    if not sock:
        raise RuntimeError('cannot extract socket from wsgi_input=%r' % wsgi_input)
    socks5_server(sock, rfile=rfile)

def paas_post(environ, start_response):
    request = decode_data(zlib.decompress(environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH') or -1))))
    #logging.debug('post() get fetch request %s', request)

    method = request['method']
    url = request['url']
    payload = request['payload'] or None

    headers = dict((k.title(),v.lstrip()) for k, _, v in (line.partition(':') for line in request['headers'].splitlines()))
    headers['Connection'] = 'close'

    if 'dns' in request:
        headers['Host'] = urlparse.urlparse(url).netloc
        url = re.sub(r'://.+?([:/])', '://%s\\1' % request['dns'], url)

    if __password__ and __password__ != request.get('password', ''):
        # return send_notify(start_response, method, url, 403, 'Wrong password.')
        # avoid GFW detect
        return paas_get(environ, start_response)

    deadline = Deadline
    errors = []

    scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
    HTTPConnection = httplib.HTTPSConnection if scheme == 'https' else httplib.HTTPConnection
    if params:
        path += ';' + params
    if query:
        path += '?' + query
    for i in xrange(FetchMax if 'fetchmax' not in request else int(request['fetchmax'])):
        try:
            conn = HTTPConnection(netloc, timeout=deadline)
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            if response.length and response.length > FetchMaxSize:
                m = re.search('bytes=(\d+)-', headers.get('Range', ''))
                start = int(m.group(1) if m else 0)
                headers['Range'] = 'bytes=%d-%d' % (start, start+FetchMaxSize-1)
                response.close()
                continue
            break
        except Exception, e:
            errors.append(str(e))
            time.sleep(1)
            if i==0 and method=='GET':
                deadline = Deadline * 2
    else:
        return send_notify(start_response, method, url, 500, 'Python PaaS Server: HTTPConnection error: %s' % errors)

    headers = dict(response.getheaders())
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

    return send_response(start_response, response.status, headers, response.read(), 'text/html; charset=UTF-8')

def paas_get(environ, start_response):
    host = 'go%s%s' % (int(time.time()*1000000), environ['HTTP_HOST'])
    try:
        conn = httplib.HTTPConnection(host)
        conn.request('GET', '/')
        response = conn.getresponse()
        message = '%s %s' % (response.status, response.reason)
        start_response(message, response.getheaders())
        return [response.read()]
    except Exception as e:
        start_response('503 Service Unavailable', [('Content-Type', 'text/html; charset=UTF-8')])
        return ['']

def paas_application(environ, start_response):
    method = environ['REQUEST_METHOD']
    if method == 'PUT':
        return paas_socks5(environ, start_response)
    elif method == 'POST':
        return paas_post(environ, start_response)
    else:
        return paas_get(environ, start_response)

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
    server = gevent.pywsgi.WSGIServer((host, int(port)), application, **ssl_args)
    server.environ.pop('SERVER_SOFTWARE')
    logging.info('serving %s://%s:%s/wsgi.py', 'https' if ssl_args else 'http', server.address[0] or '0.0.0.0', server.address[1])
    server.serve_forever()

