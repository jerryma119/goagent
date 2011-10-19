#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

__version__ = '1.6.1'
__author__ = "{phus.lu,hewigovens}@gmail.com (Phus Lu and Hewig Xu)"

import sys, os, re, time, errno, binascii, zlib
import struct, random, hashlib
import fnmatch, base64, logging, ConfigParser
import thread, threading
import socket, ssl, select
import httplib, urllib2, urlparse
import BaseHTTPServer, SocketServer
try:
    import ctypes
except ImportError:
    ctypes = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    import ntlm, ntlm.HTTPNtlmAuthHandler
except ImportError:
    ntlm = None

logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%d/%b/%Y %H:%M:%S]')

ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
COMMON_CONFIG = ConfigParser.ConfigParser()
COMMON_CONFIG.read(os.path.splitext(__file__)[0] + '.ini')
COMMON_LISTEN_IP            = COMMON_CONFIG.get('listen', 'ip')
COMMON_LISTEN_PORT          = COMMON_CONFIG.getint('listen', 'port')
COMMON_LISTEN_VISIBLE       = COMMON_CONFIG.getint('listen', 'visible')
COMMON_GAE_ENABLE           = COMMON_CONFIG.getint('gae', 'enable')
COMMON_GAE_APPIDS           = COMMON_CONFIG.get('gae', 'appid').replace('.appspot.com', '').split('|')
COMMON_GAE_SERVER           = '%s.appspot.com' % COMMON_GAE_APPIDS[0]
COMMON_GAE_PASSWORD         = COMMON_CONFIG.get('gae', 'password').strip()
COMMON_GAE_DEBUGLEVEL       = COMMON_CONFIG.getint('gae', 'debuglevel')
COMMON_GAE_PATH             = COMMON_CONFIG.get('gae', 'path')
COMMON_PHP_ENABLE           = COMMON_CONFIG.getint('php', 'enable')
COMMON_PHP_IP               = COMMON_CONFIG.get('php', 'ip')
COMMON_PHP_PORT             = COMMON_CONFIG.getint('php', 'port')
COMMON_PHP_FETCHSERVER      = COMMON_CONFIG.get('php', 'fetchserver')
COMMON_PROXY_ENABLE         = COMMON_CONFIG.getint('proxy', 'enable')
COMMON_PROXY_HOST           = COMMON_CONFIG.get('proxy', 'host')
COMMON_PROXY_PORT           = COMMON_CONFIG.getint('proxy', 'port')
COMMON_PROXY_USERNAME       = COMMON_CONFIG.get('proxy', 'username')
COMMON_PROXY_PASSWROD       = COMMON_CONFIG.get('proxy', 'password')
COMMON_PROXY_NTLM           = bool(COMMON_CONFIG.getint('proxy', 'ntlm')) if COMMON_CONFIG.has_option('proxy', 'ntlm') else '\\' in COMMON_PROXY_USERNAME
COMMON_APPSPOT_MODE         = COMMON_CONFIG.get('appspot', 'mode')
COMMON_APPSPOT_AUTOSWITCH   = COMMON_CONFIG.getint('appspot', 'autoswitch') if COMMON_CONFIG.has_option('appspot', 'autoswitch') else 0
COMMON_APPSPOT_HOSTS_CN     = tuple(COMMON_CONFIG.get('appspot', 'cn').split('|'))
COMMON_APPSPOT_HOSTS_HK     = tuple(COMMON_CONFIG.get('appspot', 'hk').split('|'))
COMMON_APPSPOT_HOSTS_IPV6   = tuple(COMMON_CONFIG.get('appspot', 'ipv6').split('|'))
COMMON_APPSPOT_HOSTS        = {'cn':COMMON_APPSPOT_HOSTS_CN,'hk':COMMON_APPSPOT_HOSTS_HK,'ipv6':COMMON_APPSPOT_HOSTS_IPV6}[COMMON_CONFIG.get('appspot', 'hosts')]
COMMON_GOOGLE_SITES         = tuple(COMMON_CONFIG.get('google', 'sites').split('|'))
COMMON_GOOGLE_FORCEHTTPS    = frozenset(COMMON_CONFIG.get('google', 'forcehttps').split('|'))
COMMON_GOOGLE_WITHGAE       = frozenset(COMMON_CONFIG.get('google', 'withgae').split('|'))
COMMON_GOOGLE_HOSTS         = tuple(COMMON_CONFIG.get('google', 'hosts').split('|'))
COMMON_FETCHMAX_LOCAL       = COMMON_CONFIG.getint('fetchmax', 'local') if COMMON_CONFIG.get('fetchmax', 'local') else 3
COMMON_FETCHMAX_SERVER      = COMMON_CONFIG.get('fetchmax', 'server')
COMMON_AUTORANGE_HOSTS      = tuple(COMMON_CONFIG.get('autorange', 'hosts').split('|'))
COMMON_AUTORANGE_HOSTS_TAIL = tuple(x.rpartition('*')[2] for x in COMMON_AUTORANGE_HOSTS)
COMMON_AUTORANGE_ENDSWITH   = frozenset(COMMON_CONFIG.get('autorange', 'endswith').split('|'))
COMMON_HOSTS                = dict((k, v) for k, v in COMMON_CONFIG.items('hosts') if not k.startswith('_'))

def common_info():
    info = ''
    info += '------------------------------------------------------\n'
    info += 'GoAgent Version : %s (python/%s pyopenssl/%s)\n' % (__version__, sys.version.partition(' ')[0], (OpenSSL.version.__version__ if OpenSSL else 'Disabled'))
    info += 'Listen Address  : %s:%d\n' % (COMMON_LISTEN_IP, COMMON_LISTEN_PORT)
    info += 'Local Proxy     : %s:%s\n' % (COMMON_PROXY_HOST, COMMON_PROXY_PORT) if COMMON_PROXY_ENABLE else ''
    info += 'Debug Level     : %s\n' % COMMON_GAE_DEBUGLEVEL if COMMON_GAE_DEBUGLEVEL else ''
    info += 'GAE Mode        : %s\n' % COMMON_APPSPOT_MODE if COMMON_GAE_ENABLE else ''
    info += 'GAE APPID       : %s\n' % '|'.join(COMMON_GAE_APPIDS)
    info += 'PHP Mode Listen : %s:%d\n' % (COMMON_PHP_IP, COMMON_PHP_PORT) if COMMON_PHP_ENABLE else ''
    info += 'PHP FetchServer : %s\n' % COMMON_PHP_FETCHSERVER if COMMON_PHP_ENABLE else ''
    info += '------------------------------------------------------\n'
    return info

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
    def connect(self, hosts, port, timeout, window):
        for i in xrange(MultiplexConnection.retry):
            if len(hosts) > window:
                hosts = random.sample(hosts, window)
            logging.debug('MultiplexConnection connect %d hosts, port=%s', len(hosts), port)
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
                    if MultiplexConnection.window_ack > 10 and window > MultiplexConnection.window_min:
                        MultiplexConnection.window = window - 1
                        MultiplexConnection.window_ack = 0
                        logging.info('MultiplexConnection CONNECT port=%s OK 10 times, switch new window=%d', port, MultiplexConnection.window)
                break
            else:
                logging.warning('MultiplexConnection Cannot hosts %r:%r, window=%d', hosts, port, window)
        else:
            MultiplexConnection.window = min(int(round(window*1.5)), len(hosts), self.window_max)
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

def socket_create_connection((host, port), timeout=None, source_address=None):
    logging.debug('socket_create_connection connect (%r, %r)', host, port)
    if host == COMMON_GAE_SERVER:
        msg = 'socket_create_connection returns an empty list'
        try:
            #logging.debug('socket_create_connection connect hosts: (%r, %r)', COMMON_APPSPOT_HOSTS, port)
            conn = MultiplexConnection(COMMON_APPSPOT_HOSTS, port)
            sock = conn.socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            return sock
        except socket.error, msg:
            logging.error('socket_create_connection connect fail: (%r, %r)', COMMON_GOOGLE_HOSTS, port)
            sock = None
        if not sock:
            raise socket.error, msg
    else:
        msg = 'getaddrinfo returns an empty list'
        host = COMMON_HOSTS.get(host) or host
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
socket.create_connection = socket_create_connection

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
                    except Exception, e:
                        logging.warning('socket_forward idlecall fail:%s', str(e))
                    finally:
                        idlecall = None
    except Exception, ex:
        logging.warning('socket_forward error=%s', ex)
        raise
    finally:
        if idlecall:
            idlecall()

_httplib_HTTPConnection_putrequest = httplib.HTTPConnection.putrequest
def httplib_HTTPConnection_putrequest(self, method, url, skip_host=0, skip_accept_encoding=1):
    return _httplib_HTTPConnection_putrequest(self, method, url, skip_host, skip_accept_encoding)
httplib.HTTPConnection.putrequest = httplib_HTTPConnection_putrequest

def proxy_auth_header(username, password):
    return 'Proxy-Authorization: Basic %s' + base64.b64encode('%s:%s'%(username, password))

class CertUtil(object):
    '''CertUtil module, based on WallProxy 0.4.0'''

    CA = None
    CALock = threading.Lock()

    @staticmethod
    def readFile(filename):
        content = None
        with open(filename, 'rb') as fp:
            content = fp.read()
        return content

    @staticmethod
    def writeFile(filename, content):
        with open(filename, 'wb') as fp:
            fp.write(str(content))

    @staticmethod
    def createKeyPair(type=None, bits=1024):
        if type is None:
            type = OpenSSL.crypto.TYPE_RSA
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(type, bits)
        return pkey

    @staticmethod
    def createCertRequest(pkey, digest='sha1', **subj):
        req = OpenSSL.crypto.X509Req()
        subject = req.get_subject()
        for k,v in subj.iteritems():
            setattr(subject, k, v)
        req.set_pubkey(pkey)
        req.sign(pkey, digest)
        return req

    @staticmethod
    def createCertificate(req, (issuerKey, issuerCert), serial, (notBefore, notAfter), digest='sha1'):
        cert = OpenSSL.crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(issuerKey, digest)
        return cert

    @staticmethod
    def loadPEM(pem, type):
        handlers = ('load_privatekey', 'load_certificate_request', 'load_certificate')
        return getattr(OpenSSL.crypto, handlers[type])(OpenSSL.crypto.FILETYPE_PEM, pem)

    @staticmethod
    def dumpPEM(obj, type):
        handlers = ('dump_privatekey', 'dump_certificate_request', 'dump_certificate')
        return getattr(OpenSSL.crypto, handlers[type])(OpenSSL.crypto.FILETYPE_PEM, obj)

    @staticmethod
    def makeCA():
        pkey = CertUtil.createKeyPair(bits=2048)
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': 'GoAgent',
                'organizationalUnitName': 'GoAgent Root', 'commonName': 'GoAgent CA'}
        req = CertUtil.createCertRequest(pkey, **subj)
        cert = CertUtil.createCertificate(req, (pkey, req), 0, (0, 60*60*24*7305))  #20 years
        return (CertUtil.dumpPEM(pkey, 0), CertUtil.dumpPEM(cert, 2))

    @staticmethod
    def makeCert(host, (cakey, cacrt), serial):
        pkey = CertUtil.createKeyPair()
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': host,
                'organizationalUnitName': 'GoAgent Branch', 'commonName': host}
        req = CertUtil.createCertRequest(pkey, **subj)
        cert = CertUtil.createCertificate(req, (cakey, cacrt), serial, (0, 60*60*24*7305))
        return (CertUtil.dumpPEM(pkey, 0), CertUtil.dumpPEM(cert, 2))

    @staticmethod
    def getCertificate(host):
        basedir = os.path.dirname(__file__)
        keyFile = os.path.join(basedir, 'certs/%s.key' % host)
        crtFile = os.path.join(basedir, 'certs/%s.crt' % host)
        if os.path.exists(keyFile):
            return (keyFile, crtFile)
        if OpenSSL is None:
            keyFile = os.path.join(basedir, 'CA.key')
            crtFile = os.path.join(basedir, 'CA.crt')
            return (keyFile, crtFile)
        if not os.path.isfile(keyFile):
            with CertUtil.CALock:
                if not os.path.isfile(keyFile):
                    logging.info('CertUtil getCertificate for %r', host)
                    for serial in (int(hashlib.md5(host).hexdigest(),16), int(time.time() * 100)):
                        try:
                            key, crt = CertUtil.makeCert(host, CertUtil.CA, serial)
                            CertUtil.writeFile(keyFile, key)
                            CertUtil.writeFile(crtFile, crt)
                            break
                        except:
                            logging.exception('CertUtil.makeCert failed: host=%r, serial=%r', host, serial)
                    else:
                        keyFile = os.path.join(basedir, 'CA.key')
                        crtFile = os.path.join(basedir, 'CA.crt')
        return (keyFile, crtFile)

    @staticmethod
    def checkCA():
        #Check CA exists
        keyFile = os.path.join(os.path.dirname(__file__), 'CA.key')
        crtFile = os.path.join(os.path.dirname(__file__), 'CA.crt')
        if not os.path.exists(keyFile):
            if not OpenSSL:
                logging.critical('CA.crt is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            key, crt = CertUtil.makeCA()
            CertUtil.writeFile(keyFile, key)
            CertUtil.writeFile(crtFile, crt)
            [os.remove(os.path.join('certs', x)) for x in os.listdir('certs')]
        #Check CA imported
        cmd = {
                'win32'  : r'cd /d "%s" && certmgr.exe -add CA.crt -c -s -r localMachine Root >NUL' % os.path.dirname(__file__),
                #'darwin' : r'sudo security add-trusted-cert -d –r trustRoot –k /Library/Keychains/System.keychain CA.crt',
              }.get(sys.platform)
        if cmd and os.system(cmd) != 0:
            logging.warn('GoAgent install trusted root CA certificate failed, Please run goagent by administrator/root.')
        if OpenSSL:
            keyFile = os.path.join(os.path.dirname(__file__), 'CA.key')
            crtFile = os.path.join(os.path.dirname(__file__), 'CA.crt')
            cakey = CertUtil.readFile(keyFile)
            cacrt = CertUtil.readFile(crtFile)
            CertUtil.CA = (CertUtil.loadPEM(cakey, 0), CertUtil.loadPEM(cacrt, 2))

def encode_data(dic):
    return '&'.join('%s=%s' % (k, binascii.b2a_hex(str(v))) for k, v in dic.iteritems())

def decode_data(qs):
    return dict((k, binascii.a2b_hex(v)) for k, v in (x.split('=') for x in qs.split('&')))

def build_opener():
    if COMMON_PROXY_ENABLE:
        proxy = '%s:%s@%s:%d'%(COMMON_PROXY_USERNAME, COMMON_PROXY_PASSWROD, COMMON_PROXY_HOST, COMMON_PROXY_PORT)
        handlers = [urllib2.ProxyHandler({'http':proxy,'https':proxy})]
        if COMMON_PROXY_NTLM:
            if ntlm is None:
                logging.critical('You need install python-ntlm to support windows domain proxy! "%s:%s"', COMMON_PROXY_HOST, COMMON_PROXY_PORT)
                sys.exit(-1)
            passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
            passman.add_password(None, '%s:%s' % (COMMON_PROXY_HOST, COMMON_PROXY_PORT), COMMON_PROXY_USERNAME, COMMON_PROXY_PASSWROD)
            auth_NTLM = ntlm.HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
            handlers.append(auth_NTLM)
    else:
        handlers = [urllib2.ProxyHandler({})]
    opener = urllib2.build_opener(*handlers)
    opener.addheaders = []
    return opener

def build_gae_fetchserver():
    if not COMMON_PROXY_ENABLE:
        fetchserver = '%s://%s%s' % (COMMON_APPSPOT_MODE, COMMON_GAE_SERVER, COMMON_GAE_PATH)
    else:
        fetchserver = '%s://%s%s' % (COMMON_APPSPOT_MODE, random.choice(COMMON_APPSPOT_HOSTS), COMMON_GAE_PATH)
    return fetchserver

class LocalProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    part_size = 1024 * 1024
    skip_headers = frozenset(['host', 'vary', 'via', 'x-forwarded-for', 'proxy-authorization', 'proxy-connection', 'upgrade', 'keep-alive'])
    opener = build_opener()
    setuplock = threading.Lock()
    fetchhost = COMMON_GAE_SERVER
    fetchserver = build_gae_fetchserver()

    def handle_fetch_error(self, error):
        global COMMON_APPSPOT_MODE, COMMON_APPSPOT_HOSTS, COMMON_GAE_APPIDS, COMMON_GAE_SERVER
        if isinstance(error, urllib2.HTTPError):
            # seems that current appid is over qouta, swith to next appid
            if error.code == 503:
                COMMON_GAE_APPIDS.append(COMMON_GAE_APPIDS.pop(0))
                COMMON_GAE_SERVER = '%s.appspot.com' % COMMON_GAE_APPIDS[0]
                LocalProxyHandler.fetchhost = COMMON_GAE_SERVER
                LocalProxyHandler.fetchserver = build_gae_fetchserver()
                logging.info('Appspot 503 Error, switch to new fetchserver: %r', LocalProxyHandler.fetchserver)
                return True
            # seems that www.google.cn:80 is down, switch to https
            if error.code in (502, 504):
                COMMON_APPSPOT_MODE = 'https'
                LocalProxyHandler.fetchserver = build_gae_fetchserver()
                if COMMON_APPSPOT_AUTOSWITCH:
                    COMMON_APPSPOT_HOSTS = COMMON_APPSPOT_HOSTS_HK
                return True
        elif isinstance(error, urllib2.URLError):
            if error.reason[0] in (11004, 10051, 10054, 10060, 'timed out'):
                # it seems that google.cn is reseted, switch to https
                if error.reason[0] == 10054:
                    MultiplexConnection.window_ack = 0
                    MultiplexConnection.window = min(int(round(MultiplexConnection.window*1.5)), MultiplexConnection.window_max)
                    if COMMON_APPSPOT_AUTOSWITCH:
                        COMMON_APPSPOT_MODE = 'https'
                        COMMON_APPSPOT_HOSTS = COMMON_APPSPOT_HOSTS_HK
                        LocalProxyHandler.fetchserver = build_gae_fetchserver()
                        return True
        elif isinstance(error, httplib.HTTPException):
            COMMON_APPSPOT_MODE = 'https'
            LocalProxyHandler.fetchserver = build_gae_fetchserver()
            return True
        else:
            logging.warning('LocalProxyHandler.fetch Exception %s', error, exc_info=True)

    def fetch(self, url, payload, method, headers):
        errors = []
        params = {'url':url, 'method':method, 'headers':headers, 'payload':payload}
        logging.debug('LocalProxyHandler _fetch params %s', params)
        if COMMON_GAE_PASSWORD:
            params['password'] = COMMON_GAE_PASSWORD
        if COMMON_FETCHMAX_SERVER:
            params['fetchmax'] = int(COMMON_FETCHMAX_SERVER)
        params = encode_data(params)
        for i in xrange(COMMON_FETCHMAX_LOCAL):
            try:
                fetchserver = LocalProxyHandler.fetchserver
                logging.debug('LocalProxyHandler _fetch %r by %r', url, fetchserver)
                request = urllib2.Request(fetchserver, zlib.compress(params, 9))
                request.add_header('Content-Type', '')
                if COMMON_PROXY_ENABLE:
                    request.add_header('Host', self.fetchhost)
                response = self.opener.open(request)
                data = response.read()
                response.close()
            except Exception, e:
                if self.handle_fetch_error(e):
                    sys.stdout.write(common_info())
                errors.append(str(e))
                continue

            try:
                if data[0] == '0':
                    raw_data = data[1:]
                elif data[0] == '1':
                    raw_data = zlib.decompress(data[1:])
                else:
                    raise ValueError('Data format not match(%s)' % url)
                data = {}
                data['code'], hlen, clen = struct.unpack('>3I', raw_data[:12])
                tlen = 12+hlen+clen
                realtlen = len(raw_data)
                if realtlen == tlen:
                    data['content'] = raw_data[12+hlen:]
                elif realtlen > tlen:
                    data['content'] = raw_data[12+hlen:tlen]
                else:
                    raise ValueError('Data length is short than excepted!')

                if data['code'] == 555:     #Urlfetch Failed
                    raise ValueError(data['content'])
                data['headers'] = decode_data(raw_data[12:12+hlen])
                return (0, data)
            except Exception, e:
                errors.append(str(e))
        return (-1, errors)

    def rangefetch(self, m, data):
        m = map(int, m.groups())
        start = m[0]
        end = m[2] - 1
        if 'range' in self.headers:
            req_range = re.search(r'(\d+)?-(\d+)?', self.headers['range'])
            if req_range:
                req_range = [u and int(u) for u in req_range.groups()]
                if req_range[0] is None:
                    if req_range[1] is not None:
                        if m[1]-m[0]+1==req_range[1] and m[1]+1==m[2]:
                            return False
                        if m[2] >= req_range[1]:
                            start = m[2] - req_range[1]
                else:
                    start = req_range[0]
                    if req_range[1] is not None:
                        if m[0]==req_range[0] and m[1]==req_range[1]:
                            return False
                        if end > req_range[1]:
                            end = req_range[1]
            data['headers']['content-range'] = 'bytes %d-%d/%d' % (start, end, m[2])
        elif start == 0:
            data['code'] = 200
            del data['headers']['content-range']
        data['headers']['content-length'] = end-start+1
        partSize = self.part_size

        respline = '%s %d %s\r\n' % (self.protocol_version, data['code'], '')
        strheaders = ''.join('%s: %s\r\n' % ('-'.join(x.title() for x in k.split('-')), v) for k, v in data['headers'].iteritems())
        self.wfile.write(respline+strheaders+'\r\n')

        if start == m[0]:
            self.wfile.write(data['content'])
            start = m[1] + 1
            partSize = len(data['content'])
        failed = 0
        logging.info('>>>>>>>>>>>>>>> Range Fetch started')
        while start <= end:
            self.headers['Range'] = 'bytes=%d-%d' % (start, start + partSize - 1)
            retval, data = self.fetch(self.path, '', self.command, self.headers)
            if retval != 0:
                time.sleep(4)
                continue
            m = re.search(r'bytes\s+(\d+)-(\d+)/(\d+)', data['headers'].get('content-range',''))
            if not m or int(m.group(1))!=start:
                if failed >= 1:
                    break
                failed += 1
                continue
            start = int(m.group(2)) + 1
            logging.info('>>>>>>>>>>>>>>> %s %d' % (data['headers']['content-range'], end))
            failed = 0
            self.wfile.write(data['content'])
        logging.info('>>>>>>>>>>>>>>> Range Fetch ended')
        return True

    def address_string(self):
        return '%s:%s' % (self.client_address[0], self.client_address[1])

    def send_response(self, code, message=None):
        self.log_request(code)
        message = message or self.responses.get(code, ('GoAgent Notify',))[0]
        self.wfile.write('%s %d %s\r\n' % (self.protocol_version, code, message))

    def end_error(self, code, message=None, data=None):
        if not data:
            self.send_error(code, message)
        else:
            self.send_response(code, message)
            self.wfile.write(data)

    def setup(self):
        if not COMMON_GAE_ENABLE:
            LocalProxyHandler.do_CONNECT = LocalProxyHandler.do_CONNECT_Direct
            LocalProxyHandler.do_METHOD  = LocalProxyHandler.do_METHOD_Direct
        LocalProxyHandler.do_GET     = LocalProxyHandler.do_METHOD
        LocalProxyHandler.do_POST    = LocalProxyHandler.do_METHOD
        LocalProxyHandler.do_PUT     = LocalProxyHandler.do_METHOD
        LocalProxyHandler.do_DELETE  = LocalProxyHandler.do_METHOD
        LocalProxyHandler.do_OPTIONS = LocalProxyHandler.do_METHOD
        LocalProxyHandler.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(':')
        if host.endswith(COMMON_GOOGLE_SITES) and host not in COMMON_GOOGLE_WITHGAE:
            return self.do_CONNECT_Direct()
        elif host in COMMON_HOSTS:
            return self.do_CONNECT_Direct()
        else:
            return self.do_CONNECT_Thunnel()

    def do_CONNECT_Direct(self):
        try:
            logging.debug('LocalProxyHandler.do_CONNECT_Directt %s' % self.path)
            host, _, port = self.path.rpartition(':')
            idlecall = None
            if not COMMON_PROXY_ENABLE:
                if host.endswith(COMMON_GOOGLE_SITES):
                    conn = MultiplexConnection(COMMON_GOOGLE_HOSTS, int(port))
                    sock = conn.socket
                    idlecall=conn.close
                else:
                    sock = socket.create_connection((host, int(port)))
                self.log_request(200)
                self.wfile.write('%s 200 Tunnel established\r\n\r\n' % self.protocol_version)
            else:
                sock = socket.create_connection((COMMON_PROXY_HOST, COMMON_PROXY_PORT))
                if host.endswith(COMMON_GOOGLE_SITES):
                    ip = random.choice(COMMON_GOOGLE_HOSTS)
                else:
                    ip = random.choice(COMMON_HOSTS.get(host, host)[0])
                data = '%s %s:%s %s\r\n' % (self.command, ip, port, self.protocol_version)
                data += ''.join('%s: %s\r\n' % (k, self.headers[k]) for k in self.headers if k != 'host')
                if COMMON_PROXY_USERNAME and not COMMON_PROXY_NTLM:
                    data += '%s\r\n' % proxy_auth_header(COMMON_PROXY_USERNAME, COMMON_PROXY_PASSWROD)
                data += '\r\n'
                sock.sendall(data)
            socket_forward(self.connection, sock, idlecall=idlecall)
        except:
            logging.exception('LocalProxyHandler.do_CONNECT_Direct Error')
        finally:
            try:
                sock.close()
                del sock
            except:
                pass

    def do_CONNECT_Thunnel(self):
        # for ssl proxy
        host, _, port = self.path.rpartition(':')
        keyFile, crtFile = CertUtil.getCertificate(host)
        self.log_request(200)
        self.connection.sendall('%s 200 OK\r\n\r\n' % self.protocol_version)
        try:
            self._realpath = self.path
            self._realrfile = self.rfile
            self._realwfile = self.wfile
            self._realconnection = self.connection
            self.connection = ssl.wrap_socket(self.connection, keyFile, crtFile, True)
            self.rfile = self.connection.makefile('rb', self.rbufsize)
            self.wfile = self.connection.makefile('wb', self.wbufsize)
            self.raw_requestline = self.rfile.readline()
            if self.raw_requestline == '':
                return
            self.parse_request()
            if self.path[0] == '/':
                self.path = 'https://%s%s' % (self._realpath, self.path)
                self.requestline = '%s %s %s' % (self.command, self.path, self.protocol_version)
            self.do_METHOD_Thunnel()
        except socket.error, e:
            logging.exception('do_CONNECT_Thunnel socket.error: %s', e)
        finally:
            self.connection.shutdown(socket.SHUT_WR)
            self.rfile = self._realrfile
            self.wfile = self._realwfile
            self.connection = self._realconnection

    def do_METHOD(self):
        host = self.headers['host']
        if host.endswith(COMMON_GOOGLE_SITES) and host not in COMMON_GOOGLE_WITHGAE:
            if host in COMMON_GOOGLE_FORCEHTTPS:
                self.send_response(301)
                self.send_header('Location', self.path.replace('http://', 'https://'))
                self.end_headers()
                return
            return self.do_METHOD_Direct()
        elif host in COMMON_HOSTS:
            return self.do_METHOD_Direct()
        else:
            return self.do_METHOD_Thunnel()

    def do_METHOD_Direct(self):
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(self.path, 'http')
        try:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        except ValueError:
            host = netloc
            port = 80
        try:
            self.log_request()
            idlecall = None
            if not COMMON_PROXY_ENABLE:
                if host.endswith(COMMON_GOOGLE_SITES):
                    conn = MultiplexConnection(COMMON_GOOGLE_HOSTS, port)
                    sock = conn.socket
                    idlecall = conn.close
                else:
                    sock = socket.create_connection((host, port))
                self.headers['connection'] = 'close'
                data = '%s %s %s\r\n'  % (self.command, urlparse.urlunparse(('', '', path, params, query, '')), self.request_version)
                data += ''.join('%s: %s\r\n' % (k, self.headers[k]) for k in self.headers if not k.startswith('proxy-'))
                data += '\r\n'
            else:
                sock = socket.create_connection((COMMON_PROXY_HOST, COMMON_PROXY_PORT))
                if host.endswith(COMMON_GOOGLE_SITES):
                    host = random.choice(COMMON_GOOGLE_HOSTS)
                else:
                    host = COMMON_HOSTS.get(host, host)
                url = urlparse.urlunparse((scheme, host + ('' if port == 80 else ':%d' % port), path, params, query, ''))
                data ='%s %s %s\r\n'  % (self.command, url, self.request_version)
                data += ''.join('%s: %s\r\n' % (k, self.headers[k]) for k in self.headers if k != 'host')
                data += 'Host: %s\r\n' % netloc
                if COMMON_PROXY_USERNAME and not COMMON_PROXY_NTLM:
                    data += '%s\r\n' % proxy_auth_header(COMMON_PROXY_USERNAME, COMMON_PROXY_PASSWROD)
                data += 'Proxy-connection: close\r\n'
                data += '\r\n'

            content_length = int(self.headers.get('content-length', 0))
            if content_length > 0:
                data += self.rfile.read(content_length)
            sock.sendall(data)
            socket_forward(self.connection, sock, idlecall=idlecall)
        except Exception, ex:
            logging.exception('LocalProxyHandler.do_GET Error, %s', ex)
        finally:
            try:
                sock.close()
                del sock
            except:
                pass

    def do_METHOD_Thunnel(self):
        host = self.headers.dict.get('host')
        if self.path[0] == '/':
            self.path = 'http://%s%s' % (host, self.path)
        payload_len = int(self.headers.get('content-length', 0))
        if payload_len > 0:
            payload = self.rfile.read(payload_len)
        else:
            payload = ''

        headers = ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.dict.iteritems() if k not in self.skip_headers)

        if host.endswith(COMMON_AUTORANGE_HOSTS_TAIL):
            for pattern in COMMON_AUTORANGE_HOSTS:
                if host.endswith(pattern) or fnmatch.fnmatch(host, pattern):
                    logging.debug('autorange pattern=%r match url=%r', pattern, self.path)
                    headers += 'range: bytes=0-%d\r\n' % self.part_size
                    break

        retval, data = self.fetch(self.path, payload, self.command, headers)
        try:
            if retval == -1:
                return self.end_error(502, str(data))
            code = data['code']
            headers = data['headers']
            self.log_request(code)
            if code == 206 and self.command=='GET':
                m = re.search(r'bytes\s+(\d+)-(\d+)/(\d+)', headers.get('content-range',''))
                if m and self.rangefetch(m, data):
                    return
            content = '%s %d %s\r\n%s\r\n%s' % (self.protocol_version, code, self.responses.get(code, ('GoAgent Notify', ''))[0], ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems()), data['content'])
            self.connection.sendall(content)
            if 'close' == headers.get('connection',''):
                self.close_connection = 1
        except socket.error, (err, _):
            # Connection closed before proxy return
            if err in (10053, errno.EPIPE):
                return

class PHPProxyHandler(LocalProxyHandler):

    fetchserver = COMMON_PHP_FETCHSERVER
    fetchhost   = re.sub(':\d+$', '', urlparse.urlparse(fetchserver).netloc)

    def handle_fetch_error(self, error):
        logging.error('PHPProxyHandler handle_fetch_error %s', error)

    def setup(self):
        if COMMON_PROXY_ENABLE:
            logging.info('Local Proxy is enable, PHPProxyHandler dont resole DNS')
        else:
            fetchhost = self.fetchhost
            logging.info('PHPProxyHandler.setup check %s is in COMMON_HOSTS', fetchhost)
            if fetchhost not in COMMON_HOSTS:
                with LocalProxyHandler.setuplock:
                    if fetchhost not in COMMON_HOSTS:
                        try:
                            logging.info('Resole php fetchserver address.')
                            COMMON_HOSTS[fetchhost] = socket.gethostbyname(fetchhost)
                            logging.info('Resole php fetchserver address OK. %s', COMMON_HOSTS[fetchhost])
                        except Exception, e:
                            logging.exception('PHPProxyHandler.setup resolve fail: %s', e)
        PHPProxyHandler.do_CONNECT = LocalProxyHandler.do_CONNECT_Thunnel
        PHPProxyHandler.do_GET     = LocalProxyHandler.do_METHOD_Thunnel
        PHPProxyHandler.do_POST    = LocalProxyHandler.do_METHOD_Thunnel
        PHPProxyHandler.do_PUT     = LocalProxyHandler.do_METHOD_Thunnel
        PHPProxyHandler.do_DELETE  = LocalProxyHandler.do_METHOD_Thunnel
        PHPProxyHandler.setup      = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

class LocalProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

def main():
    if ctypes and os.name == 'nt':
        ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)
        if not COMMON_LISTEN_VISIBLE:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    if COMMON_GAE_DEBUGLEVEL:
        logging.root.setLevel(logging.DEBUG)
    CertUtil.checkCA()
    sys.stdout.write(common_info())
    LocalProxyServer.address_family = (socket.AF_INET, socket.AF_INET6)[':' in COMMON_LISTEN_IP]

    if COMMON_PHP_ENABLE:
        httpd = LocalProxyServer((COMMON_PHP_IP, COMMON_PHP_PORT), PHPProxyHandler)
        thread.start_new_thread(httpd.serve_forever, ())
    httpd = LocalProxyServer((COMMON_LISTEN_IP, COMMON_LISTEN_PORT), LocalProxyHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    main()