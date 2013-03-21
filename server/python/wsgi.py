#!/usr/bin/env python
# coding=utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '2.1.14'
__password__ = ''
__hostsdeny__ = ()  # __hostsdeny__ = ('.youtube.com', '.youku.com')

import sys
import os
import re
import time
import struct
import zlib
import logging
import httplib
import urlparse
import cStringIO
import errno
try:
    from google.appengine.api import urlfetch
    from google.appengine.runtime import apiproxy_errors
except ImportError:
    urlfetch = None
try:
    import sae
except ImportError:
    sae = None
try:
    import socket
    import select
except ImportError:
    socket = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None

URLFETCH_MAX = 2
URLFETCH_MAXSIZE = 4*1024*1024
URLFETCH_DEFLATE_MAXSIZE = 4*1024*1024
URLFETCH_TIMEOUT = 60


def message_html(title, banner, detail=''):
    ERROR_TEMPLATE = '''
<html><head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<title>{{title}}</title>
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
<tr><td>&nbsp;</td></tr></table>
<blockquote>
<H1>{{banner}}</H1>
{{detail}}
<!--
<script type="text/javascript" src="http://www.qq.com/404/search_children.js" charset="utf-8"></script>
//-->
<p>
</blockquote>
<table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
</body></html>
'''
    kwargs = dict(title=title, banner=banner, detail=detail)
    template = ERROR_TEMPLATE
    for keyword, value in kwargs.items():
        template = template.replace('{{%s}}' % keyword, value)
    return template


def gae_application(environ, start_response):
    if environ['REQUEST_METHOD'] == 'GET':
        if '204' in environ['QUERY_STRING']:
            start_response('204 No Content', [])
            yield ''
        else:
            timestamp = long(os.environ['CURRENT_VERSION_ID'].split('.')[1])/2**28
            ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp+8*3600))
            html = u'GoAgent Python Server %s \u5df2\u7ecf\u5728\u5de5\u4f5c\u4e86\uff0c\u90e8\u7f72\u65f6\u95f4 %s\n' % (__version__, ctime)
            start_response('200 OK', [('Content-Type', 'text/plain; charset=utf-8')])
            yield html.encode('utf8')
        raise StopIteration

    # inflate = lambda x:zlib.decompress(x, -15)
    wsgi_input = environ['wsgi.input']
    data = wsgi_input.read(2)
    metadata_length, = struct.unpack('!h', data)
    metadata = wsgi_input.read(metadata_length)

    metadata = zlib.decompress(metadata, -15)
    headers = dict(x.split(':', 1) for x in metadata.splitlines() if x)
    method = headers.pop('G-Method')
    url = headers.pop('G-Url')

    kwargs = {}
    any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('G-'))

    #logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')
    #logging.info('request headers=%s', headers)

    if __password__ and __password__ != kwargs.get('password', ''):
        start_response('403 Forbidden', [('Content-Type', 'text/html')])
        yield message_html('403 Wrong password', 'Wrong password(%r)' % kwargs.get('password', ''), 'GoAgent proxy.ini password is wrong!')
        raise StopIteration

    netloc = urlparse.urlparse(url).netloc

    if __hostsdeny__ and netloc.endswith(__hostsdeny__):
        start_response('403 Forbidden', [('Content-Type', 'text/html')])
        yield message_html('403 Hosts Deny', 'Hosts Deny(%r)' % netloc, detail='url=%r' % url)
        raise StopIteration

    if netloc.startswith(('127.0.0.', '::1', 'localhost')):
        start_response('400 Bad Request', [('Content-Type', 'text/html')])
        html = ''.join('<a href="https://%s/">%s</a><br/>' % (x, x) for x in ('google.com', 'mail.google.com'))
        yield message_html('GoAgent %s is Running' % __version__, 'Now you can visit some websites', html)
        raise StopIteration

    fetchmethod = getattr(urlfetch, method, None)
    if not fetchmethod:
        start_response('405 Method Not Allowed', [('Content-Type', 'text/html')])
        yield message_html('405 Method Not Allowed', 'Method Not Allowed: %r' % method, detail='Method Not Allowed URL=%r' % url)
        raise StopIteration

    deadline = URLFETCH_TIMEOUT
    validate_certificate = bool(int(kwargs.get('validate', 0)))
    headers = dict(headers)
    payload = environ['wsgi.input'].read() if 'Content-Length' in headers else None
    if 'Content-Encoding' in headers:
        if headers['Content-Encoding'] == 'deflate':
            payload = zlib.decompress(payload, -15)
            headers['Content-Length'] = str(len(payload))
            del headers['Content-Encoding']

    accept_encoding = headers.get('Accept-Encoding', '')

    errors = []
    for i in xrange(int(kwargs.get('fetchmax', URLFETCH_MAX))):
        try:
            response = urlfetch.fetch(url, payload, fetchmethod, headers, allow_truncated=False, follow_redirects=False, deadline=deadline, validate_certificate=validate_certificate)
            break
        except apiproxy_errors.OverQuotaError as e:
            time.sleep(5)
        except urlfetch.DeadlineExceededError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            logging.error('DeadlineExceededError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = URLFETCH_TIMEOUT * 2
        except urlfetch.DownloadError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            logging.error('DownloadError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = URLFETCH_TIMEOUT * 2
        except urlfetch.ResponseTooLargeError as e:
            response = e.response
            logging.error('ResponseTooLargeError(deadline=%s, url=%r) response(%r)', deadline, url, response)
            m = re.search(r'=\s*(\d+)-', headers.get('Range') or headers.get('range') or '')
            if m is None:
                headers['Range'] = 'bytes=0-%d' % int(kwargs.get('fetchmaxsize', URLFETCH_MAXSIZE))
            else:
                headers.pop('Range', '')
                headers.pop('range', '')
                start = int(m.group(1))
                headers['Range'] = 'bytes=%s-%d' % (start, start+int(kwargs.get('fetchmaxsize', URLFETCH_MAXSIZE)))
            deadline = URLFETCH_TIMEOUT * 2
        except urlfetch.SSLCertificateError as e:
            errors.append('%r, should validate=0 ?' % e)
            logging.error('%r, deadline=%s', e, deadline)
        except Exception as e:
            errors.append(str(e))
            if i == 0 and method == 'GET':
                deadline = URLFETCH_TIMEOUT * 2
    else:
        start_response('500 Internal Server Error', [('Content-Type', 'text/html')])
        error_string = '<br />\n'.join(errors)
        if not error_string:
            error_string = 'Internal Server Error. <p/><a href="javascript:window.location.reload(true);">refresh</a> current page or visit <a href="https://appengine.google.com/" target="_blank">appengine.google.com</a> for error logs'
        yield message_html('502 Urlfetch Error', 'Python Urlfetch Error: %r' % method,  error_string)
        raise StopIteration

    #logging.debug('url=%r response.status_code=%r response.headers=%r response.content[:1024]=%r', url, response.status_code, dict(response.headers), response.content[:1024])

    data = response.content
    if 'content-encoding' not in response.headers and len(response.content) < URLFETCH_DEFLATE_MAXSIZE and response.headers.get('content-type', '').startswith(('text/', 'application/json', 'application/javascript')):
        if 'deflate' in accept_encoding:
            response.headers['Content-Encoding'] = 'deflate'
            data = zlib.compress(data)[2:-4]
        elif 'gzip' in accept_encoding:
            response.headers['Content-Encoding'] = 'gzip'
            compressobj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0)
            dataio = cStringIO.StringIO()
            dataio.write('\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff')
            dataio.write(compressobj.compress(data))
            dataio.write(compressobj.flush())
            dataio.write(struct.pack('<LL', zlib.crc32(data) & 0xFFFFFFFFL, len(data) & 0xFFFFFFFFL))
            data = dataio.getvalue()
    response.headers['Content-Length'] = str(len(data))
    response_headers = zlib.compress('\n'.join('%s:%s' % (k.title(), v) for k, v in response.headers.items() if not k.startswith('x-google-')))[2:-4]
    start_response('200 OK', [('Content-Type', 'image/gif')])
    yield struct.pack('!hh', int(response.status_code), len(response_headers))+response_headers
    yield data


def paas_application(environ, start_response):
    if environ['REQUEST_METHOD'] == 'GET':
        start_response('302 Found', [('Location', 'https://www.google.com')])
        raise StopIteration

    # inflate = lambda x:zlib.decompress(x, -15)
    wsgi_input = environ['wsgi.input']
    data = wsgi_input.read(2)
    metadata_length, = struct.unpack('!h', data)
    metadata = wsgi_input.read(metadata_length)

    metadata = zlib.decompress(metadata, -15)
    headers = dict(x.split(':', 1) for x in metadata.splitlines() if x)
    method = headers.pop('G-Method')
    url = headers.pop('G-Url')

    kwargs = {}
    any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('G-'))

    headers['Connection'] = 'close'

    payload = environ['wsgi.input'].read() if 'Content-Length' in headers else None
    if 'Content-Encoding' in headers:
        if headers['Content-Encoding'] == 'deflate':
            payload = zlib.decompress(payload, -15)
            headers['Content-Length'] = str(len(payload))
            del headers['Content-Encoding']

    if __password__ and __password__ != kwargs.get('password'):
        random_host = 'g%d%s' % (int(time.time()*100), environ['HTTP_HOST'])
        conn = httplib.HTTPConnection(random_host, timeout=3)
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

    timeout = URLFETCH_TIMEOUT
    xorchar = ord(kwargs.get('xorchar') or '\x00')

    logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')

    if method != 'CONNECT':
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

            headers = [('X-Status', str(response.status))]
            headers += [(k, v) for k, v in response.msg.items() if k != 'transfer-encoding']
            start_response('200 OK', headers)

            bufsize = 8192
            while 1:
                data = response.read(bufsize)
                if not data:
                    response.close()
                    break
                if xorchar:
                    yield ''.join(chr(ord(x) ^ xorchar) for x in data)
                else:
                    yield data
        except httplib.HTTPException:
            raise


def forward_socket(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, pongcallback=None, bitmask=None):
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
                    if bitmask:
                        data = ''.join(chr(ord(x) ^ bitmask) for x in data)
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


class CertUtil(object):
    """CertUtil module, based on mitmproxy"""

    ca_vendor = 'GoAgent'
    ca_lock = __import__('threading').Lock()

    @staticmethod
    def create_ca():
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(2)
        subj = ca.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationName = CertUtil.ca_vendor
        subj.organizationalUnitName = '%s Root' % CertUtil.ca_vendor
        subj.commonName = '%s CA' % CertUtil.ca_vendor
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'nsCertType', True, b'sslCA'),
            OpenSSL.crypto.X509Extension(b'extendedKeyUsage', True, b'serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca), ])
        ca.sign(key, 'sha1')
        return key, ca

    @staticmethod
    def dump_ca(keyfile='CA.key', certfile='CA.crt'):
        key, ca = CertUtil.create_ca()
        with open(keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))

    @staticmethod
    def _get_cert(commonname, certdir='certs', ca_keyfile='CA.key', ca_certfile='CA.crt', sans=[]):
        import hashlib
        with open(ca_keyfile, 'rb') as fp:
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, fp.read())
        with open(ca_certfile, 'rb') as fp:
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read())

        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationalUnitName = '%s Branch' % CertUtil.ca_vendor
        if commonname[0] == '.':
            subj.commonName = '*' + commonname
            subj.organizationName = '*' + commonname
            sans = ['*'+commonname] + [x for x in sans if x != '*'+commonname]
        else:
            subj.commonName = commonname
            subj.organizationName = commonname
            sans = [commonname] + [x for x in sans if x != commonname]
        req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha1')

        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        try:
            cert.set_serial_number(int(hashlib.md5(commonname).hexdigest(), 16))
        except OpenSSL.SSL.Error:
            cert.set_serial_number(int(time.time()*1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        if commonname[0] == '.':
            sans = ['*'+commonname] + [s for s in sans if s != '*'+commonname]
        else:
            sans = [commonname] + [s for s in sans if s != commonname]
        cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, 'sha1')

        keyfile = os.path.join(certdir, commonname + '.key')
        with open(keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        certfile = os.path.join(certdir, commonname + '.crt')
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))

        return keyfile, certfile

    @staticmethod
    def get_cert(commonname, certdir='certs', ca_keyfile='CA.key', ca_certfile='CA.crt', sans=[]):
        if len(commonname) >= 32 and commonname.count('.') >= 2:
            commonname = re.sub(r'^[^\.]+', '', commonname)
        keyfile = os.path.join(certdir, commonname + '.key')
        certfile = os.path.join(certdir, commonname + '.crt')
        if os.path.exists(certfile):
            return keyfile, certfile
        elif OpenSSL is None:
            return ca_keyfile, ca_certfile
        else:
            with CertUtil.ca_lock:
                if os.path.exists(certfile):
                    return keyfile, certfile
                return CertUtil._get_cert(commonname, certdir, ca_keyfile, ca_certfile, sans)

    @staticmethod
    def import_ca(certfile):
        dirname, basename = os.path.split(certfile)
        commonname = os.path.splitext(certfile)[0]
        if OpenSSL:
            try:
                with open(certfile, 'rb') as fp:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read())
                    commonname = (v for k, v in x509.get_subject().get_components() if k == 'O').next()
            except Exception as e:
                logging.error('load_certificate(certfile=%r) failed:%s', certfile, e)
        cmd = ''
        if sys.platform.startswith('win'):
            cmd = 'cd /d "%s" && .\certmgr.exe -add %s -c -s -r localMachine Root >NUL' % (dirname, basename)
        elif sys.platform == 'darwin':
            cmd = 'security find-certificate -a -c "%s" | grep "%s" >/dev/null || security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s"' % (commonname, commonname, certfile)
        elif sys.platform.startswith('linux'):
            import platform
            platform_distname = platform.dist()[0]
            if platform_distname == 'Ubuntu':
                pemfile = "/etc/ssl/certs/%s.pem" % commonname
                new_certfile = "/usr/local/share/ca-certificates/%s.crt" % commonname
                if not os.path.exists(pemfile):
                    cmd = 'cp "%s" "%s" && update-ca-certificates' % (certfile, new_certfile)
        return os.system(cmd)

    @staticmethod
    def check_ca():
        #Check CA exists
        import glob
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'CA.crt')
        certdir = os.path.join(os.path.dirname(__file__), 'certs')
        if not os.path.exists(capath):
            if not OpenSSL:
                logging.critical('CA.key is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            if os.name == 'nt':
                os.system('certmgr.exe -del -n "%s CA" -c -s -r localMachine Root' % CertUtil.ca_vendor)
            if os.path.exists(certdir):
                if os.path.isdir(certdir):
                    any(os.remove(x) for x in (glob.glob(certdir+'/*.crt')+glob.glob(certdir+'/*.key')))
                else:
                    os.remove(certdir)
                os.mkdir(certdir)
            CertUtil.dump_ca('CA.key', 'CA.crt')
        #Check CA imported
        if CertUtil.import_ca(capath) != 0:
            logging.warning('install root certificate failed, Please run as administrator/root/sudo')
        #Check Certs Dir
        if not os.path.exists(certdir):
            os.makedirs(certdir)


def light_handler(sock, address):
    bufsize = 8192
    rfile = sock.makefile('rb', 0)
    wfile = sock.makefile('wb', 0)
    remote_addr, remote_port = address
    try:
        line = rfile.readline(bufsize)
        if not line:
            raise socket.error(10053)
        method, path = line.split()[:2]
        headers = {}
        while 1:
            line = rfile.readline(bufsize)
            if not line or line == '\r\n':
                break
            keyword, _, value = line.partition(':')
            headers[keyword.title()] = value.strip()
        logging.info('%s:%s "%s %s HTTP/1.1" - -', remote_addr, remote_port, method, path)
        if method == 'CONNECT':
            host, _, port = path.rpartition(':')
            remote = socket.create_connection((host, int(port)))
            wfile.write('HTTP/1.1 200 OK\r\n\r\n')
            forward_socket(sock._sock, remote)
        else:
            host = headers.get('Host') or urlparse.urlparse(path).netloc
            if re.search(r':\d+$', host):
                host, _, port = host.rpartition(':')
                port = int(port)
            else:
                port = 80
            if path.startswith('http://'):
                path = re.sub(r'http://[^/]+', '', path)
            payload = None
            if 'Content-Length' in headers:
                payload = rfile.read(int(headers.get('Content-Length', 0)))
            conn = httplib.HTTPConnection(host, port=port)
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            version = 'HTTP/1.1' if response.version == 11 else 'HTTP/1.0'
            data = '%s %s\r\n%s\r\n' % (version, response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.msg.items() if k != 'transfer-encoding'))
            wfile.write(data)
            left = int(response.getheader('Content-Length', 0))
            if left:
                while 1:
                    if not left:
                        break
                    data = response.read(min(left, bufsize))
                    if not data:
                        break
                    wfile.write(data)
                    left -= len(data)
                response.close()
            else:
                while 1:
                    data = response.read(bufsize)
                    if not data:
                        break
                    wfile.write(data)
                response.close()
    except socket.error as e:
        if e[0] not in (10053, errno.EPIPE):
            raise
    finally:
        rfile.close()
        wfile.close()
        sock.close()


app = gae_application if urlfetch else paas_application
application = app if sae is None else sae.create_wsgi_app(app)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    import gevent
    import gevent.server
    import gevent.wsgi
    import gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)

    import getopt
    options = dict(getopt.getopt(sys.argv[1:], 'l:p:a:')[0])
    host = options.get('-l', '0.0.0.0')
    port = options.get('-p', '443')
    app = options.get('-a', 'light')

    if app == 'light':
        server = gevent.server.StreamServer((host, int(port)), light_handler, keyfile='ca.pem', certfile='ca.pem')
    else:
        server = gevent.wsgi.WSGIServer((host, int(port)), paas_application)

    logging.info('serving %s at https://%s:%s/', app.upper(), server.address[0], server.address[1])
    server.serve_forever()
