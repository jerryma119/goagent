#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

__version__ = '1.3'
__author__ =  'phus.lu@gmail.com;hewigovens@gmail.com'

import sys, os, re, time, errno, binascii, zlib
import struct, random, hashlib, ctypes
import fnmatch, base64, logging, ConfigParser
import threading
import socket, ssl, select
import httplib, urllib2, urlparse
import BaseHTTPServer, SocketServer
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    import ntlm, ntlm.HTTPNtlmAuthHandler
except ImportError:
    ntlm = None

logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%d/%b/%Y %H:%M:%S]')

class Common(object):
    '''global config module, similar with GappProxy 2.0.0'''

    ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')

    def __init__(self):
        '''read proxy.ini config'''
        self.config = ConfigParser.ConfigParser()
        self.config.read(os.path.splitext(__file__)[0] + '.ini')

        self.LISTEN_IP      = self.config.get('listen', 'ip')
        self.LISTEN_PORT    = self.config.getint('listen', 'port')
        self.LISTEN_VISIBLE = self.config.getint('listen', 'visible')

        self.GAE_APPIDS     = tuple(self.config.get('gae', 'appid').replace('.appspot.com', '').split('|'))
        self.GAE_PASSWORD   = self.config.get('gae', 'password').strip()
        self.GAE_DEBUGLEVEL = self.config.getint('gae', 'debuglevel')
        self.GAE_PATH       = self.config.get('gae', 'path')
        self.GAE_BINDHOSTS  = tuple(self.config.get('gae', 'bindhosts').split('|')) if self.config.has_option('gae', 'bindhosts') else ()
        self.GAE_CERTS      = self.config.get('gae', 'certs').split('|')

        self.PROXY_ENABLE   = self.config.getint('proxy', 'enable')
        self.PROXY_HOST     = self.config.get('proxy', 'host')
        self.PROXY_PORT     = self.config.getint('proxy', 'port')
        self.PROXY_USERNAME = self.config.get('proxy', 'username')
        self.PROXY_PASSWROD = self.config.get('proxy', 'password')
        self.PROXY_NTLM     = bool(self.config.getint('proxy', 'ntlm')) if self.config.has_option('proxy', 'ntlm') else '\\' in self.PROXY_USERNAME

        self.GOOGLE_PREFER     = self.config.get('google', 'prefer')
        self.GOOGLE_AUTOSWITCH = self.config.getint('google', 'autoswitch')
        self.GOOGLE_SITES      = tuple(self.config.get('google', 'sites').split('|'))
        self.GOOGLE_FORCEHTTPS = tuple(self.config.get('google', 'forcehttps').split('|'))
        self.GOOGLE_HTTP       = [x.split('|') for x in self.config.get('google', 'http').split('||')]
        self.GOOGLE_HTTPS      = [x.split('|') for x in self.config.get('google', 'https').split('||')]
        self.GOOGLE_HOSTS      = self.GOOGLE_HTTP if self.GOOGLE_PREFER == 'http' else self.GOOGLE_HTTPS

        self.FETCHMAX_LOCAL  = self.config.getint('fetchmax', 'local') if self.config.get('fetchmax', 'local') else 3
        self.FETCHMAX_SERVER = self.config.get('fetchmax', 'server')

        self.AUTORANGE_HOSTS      = tuple(self.config.get('autorange', 'hosts').split('|'))
        self.AUTORANGE_HOSTS_TAIL = tuple(x.rpartition('*')[2] for x in self.AUTORANGE_HOSTS)
        self.AUTORANGE_ENDSWITH   = frozenset(self.config.get('autorange', 'endswith').split('|'))

        self.HOSTS = dict((k, v) for k, v in self.config.items('hosts') if not k.startswith('_'))
        if self.config.getint('hosts', '__merge__'):
            try:
                hosts = os.path.join(os.environ['windir'], r'System32\drivers\etc\hosts') if os.name=='nt' else '/etc/hosts'
                config = [(x.split()[1], x.split()[0]) for x in open(hosts) if x.strip() and not x.strip().startswith('#') and not x.split()[0].startswith(('127.0.0', '::'))]
                self.HOSTS.update(config)
            except Exception, e:
                logging.warning('Merge system hosts config failed! error=%r', e)

    def __str__(self):
        return repr(tuple((x, getattr(self, x)) for x in dir(self) if re.match(r'[A-Z]+_[A-Z]+', x)))

    def info(self):
        info = ''
        info += '--------------------------------------------\n'
        info += 'OpenSSL Module : %s\n' % ('Enabled' if OpenSSL else 'Disabled')
        info += 'Listen Address : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Debug Level    : %s\n' % self.GAE_DEBUGLEVEL if self.GAE_DEBUGLEVEL else ''
        info += 'Local Proxy    : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'GAE Mode       : %s\n' % self.GOOGLE_PREFER
        info += 'GAE APPID      : %s\n' % '|'.join(self.GAE_APPIDS)
        info += 'GAE BindHost   : %s\n' % '|'.join(self.GAE_BINDHOSTS) if self.GAE_BINDHOSTS else ''
        info += '--------------------------------------------\n'
        return info

if __name__ == '__main__':
    common = Common()

class MultiplexConnection(object):
    '''multiplex tcp connection class'''

    timeout = 5
    window = 8
    window_min = 4
    window_max = 64
    window_ack = 0

    def __init__(self, hostslist, port):
        self.socket = None
        self._sockets = set([])
        self.connect(hostslist, port, MultiplexConnection.timeout, MultiplexConnection.window)
    def connect(self, hostslist, port, timeout, window):
        for i, hosts in enumerate(hostslist):
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
                if i > 0:
                    hostslist[i:], hostslist[:i] = hostslist[:i], hostslist[i:]
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
            MultiplexConnection.window = min(int(round(window*1.5)), self.window_max)
            MultiplexConnection.window_ack = 0
            logging.warning(r'MultiplexConnection Cannot Connect to hostslist %s:%s, switch new window=%d', hostslist, port, MultiplexConnection.window)
            raise RuntimeError(r'MultiplexConnection Cannot Connect to hostslist %s:%s' % (hostslist, port))
    def __del__(self):
        for sock in self._sockets:
            try:
                sock.close()
                del sock
            except:
                pass
        del self._sockets

def socket_create_connection(address, timeout=None, source_address=None):
    host, port = address
    logging.debug('socket_create_connection connect (%r, %r)', host, port)
    if host.endswith(common.GOOGLE_SITES):
        msg = 'socket_create_connection returns an empty list'
        try:
            hostslist = common.GOOGLE_HOSTS
            #logging.debug('socket_create_connection connect hostslist: (%r, %r)', hostslist, port)
            conn = MultiplexConnection(hostslist, port)
            #conn.close()
            sock = conn.socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            return sock
        except socket.error, msg:
            logging.error('socket_create_connection connect fail: (%r, %r)', hostslist, port)
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
socket.create_connection = socket_create_connection

_httplib_HTTPConnection_putrequest = httplib.HTTPConnection.putrequest
def httplib_HTTPConnection_putrequest(self, method, url, skip_host=0, skip_accept_encoding=1):
    return _httplib_HTTPConnection_putrequest(self, method, url, skip_host, skip_accept_encoding)
httplib.HTTPConnection.putrequest = httplib_HTTPConnection_putrequest

def socket_forward(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None):
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
    except Exception, ex:
        logging.warning('socket_forward error=%s', ex)
    finally:
        pass

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
            crtFile = os.path.join(basedir, 'CA.cer')
            return (keyFile, crtFile)
        if not os.path.isfile(keyFile):
            with CertUtil.CALock:
                if not os.path.isfile(keyFile):
                    logging.info('CertUtil getCertificate for %r', host)
                    serial = int(hashlib.md5(host).hexdigest(),16)
                    key, crt = CertUtil.makeCert(host, CertUtil.CA, serial)
                    CertUtil.writeFile(keyFile, key)
                    CertUtil.writeFile(crtFile, crt)
        return (keyFile, crtFile)

    @staticmethod
    def checkCA():
        #Check CA imported
        if os.name == 'nt':
            #if 'GoAgent CA' not in  os.popen(r'certmgr.exe -s -r localMachine root').read():
                if os.system(r'certmgr.exe -add CA.cer -c -s -r localMachine Root >NUL') != 0:
                    logging.warn('Import GoAgent CA failed -- CA.cer')
        if OpenSSL:
            keyFile = os.path.join(os.path.dirname(__file__), 'CA.key')
            crtFile = os.path.join(os.path.dirname(__file__), 'CA.cer')
            cakey = CertUtil.readFile(keyFile)
            cacrt = CertUtil.readFile(crtFile)
            CertUtil.CA = (CertUtil.loadPEM(cakey, 0), CertUtil.loadPEM(cacrt, 2))
            for host in common.GAE_CERTS:
                CertUtil.getCertificate(host)

def gae_encode_data(dic):
    return '&'.join('%s=%s' % (k, binascii.b2a_hex(str(v))) for k, v in dic.iteritems())

def gae_decode_data(qs):
    return dict((k, binascii.a2b_hex(v)) for k, v in (x.split('=') for x in qs.split('&')))

def build_opener():
    if common.PROXY_ENABLE:
        proxy = '%s:%s@%s:%d'%(common.PROXY_USERNAME, common.PROXY_PASSWROD, common.PROXY_HOST, common.PROXY_PORT)
        handlers = [urllib2.ProxyHandler({'http':proxy,'https':proxy})]
        if common.PROXY_NTLM:
            if ntlm is None:
                logging.critical('You need install python-ntlm to support windows domain proxy! "%s:%s"', common.PROXY_HOST, common.PROXY_PORT)
                sys.exit(-1)
            passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
            passman.add_password(None, '%s:%s' % (common.PROXY_HOST, common.PROXY_PORT), common.PROXY_USERNAME, common.PROXY_PASSWROD)
            auth_NTLM = ntlm.HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
            handlers.append(auth_NTLM)
    else:
        handlers = [urllib2.ProxyHandler({})]
    opener = urllib2.build_opener(*handlers)
    opener.addheaders = []
    return opener

def proxy_auth_header(username, password):
    return 'Proxy-Authorization: Basic %s' + base64.b64encode('%s:%s'%(username, password))

class GaeProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    part_size = 1024 * 1024
    skip_headers = frozenset(['host', 'vary', 'via', 'x-forwarded-for', 'proxy-authorization', 'proxy-connection', 'upgrade', 'keep-alive'])
    opener = build_opener()

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

    def _fetch(self, url, method, headers, payload):
        errors = []
        params = {'url':url, 'method':method, 'headers':headers, 'payload':payload}
        logging.debug('GaeProxyHandler fetch params %s', params)
        if common.GAE_PASSWORD:
            params['password'] = common.GAE_PASSWORD
        if common.FETCHMAX_SERVER:
            params['fetchmax'] = int(common.FETCHMAX_SERVER)
        params = gae_encode_data(params)
        for i in xrange(common.FETCHMAX_LOCAL):
            try:
                if len(common.GAE_APPIDS) == 1:
                    appid = common.GAE_APPIDS[0]
                elif common.GAE_BINDHOSTS and urlparse.urlsplit(url)[1].endswith(common.GAE_BINDHOSTS):
                    appid = common.GAE_APPIDS[0]
                else:
                    appid = random.choice(common.GAE_APPIDS)
                logging.debug('GaeProxyHandler fetch %r appid=%r', url, appid)
                if not common.PROXY_ENABLE:
                    fetchserver = '%s://%s.appspot.com%s' % (common.GOOGLE_PREFER, appid, common.GAE_PATH)
                else:
                    fetchhost = random.choice(common.GOOGLE_HOSTS[0])
                    fetchserver = '%s://%s%s' % (common.GOOGLE_PREFER, fetchhost, common.GAE_PATH)
                request = urllib2.Request(fetchserver, zlib.compress(params, 9))
                request.add_header('Content-Type', 'application/octet-stream')
                if common.PROXY_ENABLE:
                    request.add_header('Host', '%s.appspot.com' % appid)
                response = self.opener.open(request)
                data = response.read()
                response.close()
            except urllib2.HTTPError, e:
                # www.google.cn:80 is down, switch to https
                if e.code in (502, 504):
                    common.GOOGLE_PREFER = 'https'
                    common.GOOGLE_HOSTS = common.GOOGLE_HTTPS
                    sys.stdout.write(common.info())
                errors.append('%d: %s' % (e.code, httplib.responses.get(e.code, 'Unknown HTTPError')))
                continue
            except urllib2.URLError, e:
                if e.reason[0] in (11004, 10051, 10054, 10060, 'timed out'):
                    # it seems that google.cn is reseted, switch to https
                    if e.reason[0] == 10054:
                        MultiplexConnection.window_ack = 0
                        MultiplexConnection.window = min(int(round(MultiplexConnection.window*1.5)), MultiplexConnection.window_max)
                        if common.GOOGLE_AUTOSWITCH:
                            common.GOOGLE_PREFER = 'https'
                            common.GOOGLE_HOSTS = common.GOOGLE_HTTPS
                            sys.stdout.write(common.info())
                errors.append(str(e))
                continue
            except Exception, e:
                errors.append(repr(e))
                logging.exception('_fetch Exception %s', e)
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
                if len(raw_data) != 12+hlen+clen:
                    raise ValueError('Data length not match')
                data['content'] = raw_data[12+hlen:]
                if data['code'] == 555:     #Urlfetch Failed
                    raise ValueError(data['content'])
                data['headers'] = gae_decode_data(raw_data[12:12+hlen])
                return (0, data)
            except Exception, e:
                errors.append(str(e))
        return (-1, errors)

    def _RangeFetch(self, m, data):
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
        self.send_response(data['code'])
        for k,v in data['headers'].iteritems():
            self.send_header(k.title(), v)
        self.end_headers()
        if start == m[0]:
            self.wfile.write(data['content'])
            start = m[1] + 1
            partSize = len(data['content'])
        failed = 0
        logging.info('>>>>>>>>>>>>>>> Range Fetch started')
        while start <= end:
            self.headers['Range'] = 'bytes=%d-%d' % (start, start + partSize - 1)
            retval, data = self._fetch(self.path, self.command, self.headers, '')
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

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(':')
        if host.endswith(common.GOOGLE_SITES) or host in common.HOSTS:
            return self.do_CONNECT_Direct()
        else:
            return self.do_CONNECT_GAE()

    def do_CONNECT_Direct(self):
        try:
            logging.debug('GaeProxyHandler.do_CONNECT_Directt %s' % self.path)
            host, _, port = self.path.rpartition(':')
            if not common.PROXY_ENABLE:
                sock = socket.create_connection((host, int(port)))
                self.log_request(200)
                self.wfile.write('%s 200 Tunnel established\r\n\r\n' % self.protocol_version)
            else:
                sock = socket.create_connection((common.PROXY_HOST, common.PROXY_PORT))
                if host.endswith(common.GOOGLE_SITES):
                    ip = random.choice(common.GOOGLE_HOSTS[0])
                else:
                    ip = random.choice(common.HOSTS.get(host, host)[0])
                data = '%s %s:%s %s\r\n' % (self.command, ip, port, self.protocol_version)
                data += ''.join('%s: %s\r\n' % (k, self.headers[k]) for k in self.headers if k != 'host')
                if common.PROXY_USERNAME and not common.PROXY_NTLM:
                    data += '%s\r\n' % proxy_auth_header(common.PROXY_USERNAME, common.PROXY_PASSWROD)
                data += '\r\n'
                sock.sendall(data)
            socket_forward(self.connection, sock)
        except:
            logging.exception('GaeProxyHandler.do_CONNECT_Direct Error')
        finally:
            try:
                sock.close()
            except:
                pass

    def do_CONNECT_GAE(self):
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
            self.do_METHOD_GAE()
        except socket.error, e:
            logging.exception('do_CONNECT_GAE socket.error: %s', e)
        finally:
            self.connection.shutdown(socket.SHUT_WR)
            self.rfile = self._realrfile
            self.wfile = self._realwfile
            self.connection = self._realconnection

    def do_METHOD(self):
        host = self.headers.get('host')
        if host.endswith(common.GOOGLE_SITES) or host.partition(':')[0] in common.HOSTS:
            if self.path.startswith(common.GOOGLE_FORCEHTTPS):
                self.send_response(301)
                self.send_header('Location', self.path.replace('http://', 'https://'))
                self.end_headers()
                return
            return self.do_METHOD_Direct()
        else:
            return self.do_METHOD_GAE()

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
            if not common.PROXY_ENABLE:
                sock = socket.create_connection((host, port))
                self.headers['connection'] = 'close'
                data = '%s %s %s\r\n'  % (self.command, urlparse.urlunparse(('', '', path, params, query, '')), self.request_version)
                data += ''.join('%s: %s\r\n' % (k, self.headers[k]) for k in self.headers if not k.startswith('proxy-'))
                data += '\r\n'
            else:
                sock = socket.create_connection((common.PROXY_HOST, common.PROXY_PORT))
                if host.endswith(common.GOOGLE_SITES):
                    host = random.choice(common.GOOGLE_HOSTS[0])
                else:
                    host = common.HOSTS.get(host, host)
                url = urlparse.urlunparse((scheme, host + ('' if port == 80 else ':%d' % port), path, params, query, ''))
                data ='%s %s %s\r\n'  % (self.command, url, self.request_version)
                data += ''.join('%s: %s\r\n' % (k, self.headers[k]) for k in self.headers if k != 'host')
                data += 'Host: %s\r\n' % netloc
                if common.PROXY_USERNAME and not common.PROXY_NTLM:
                    data += '%s\r\n' % proxy_auth_header(common.PROXY_USERNAME, common.PROXY_PASSWROD)
                data += 'Proxy-connection: close\r\n'
                data += '\r\n'

            content_length = int(self.headers.get('content-length', 0))
            if content_length > 0:
                data += self.rfile.read(content_length)
            sock.sendall(data)
            socket_forward(self.connection, sock)
        except Exception, ex:
            logging.exception('GaeProxyHandler.do_GET Error, %s', ex)
        finally:
            try:
                sock.close()
            except:
                pass

    def do_METHOD_GAE(self):
        host = self.headers.dict.get('host')
        if self.path[0] == '/':
            self.path = 'http://%s%s' % (host, self.path)
        payload_len = int(self.headers.get('content-length', 0))
        if payload_len > 0:
            payload = self.rfile.read(payload_len)
        else:
            payload = ''

        headers = ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.dict.iteritems() if k not in self.skip_headers)

        if host.endswith(common.AUTORANGE_HOSTS_TAIL):
            for pattern in common.AUTORANGE_HOSTS:
                if host.endswith(pattern) or fnmatch.fnmatch(host, pattern):
                    logging.debug('autorange pattern=%r match url=%r', pattern, self.path)
                    headers += 'Range: bytes=0-%d\r\n' % self.part_size
                    break

        retval, data = self._fetch(self.path, self.command, headers, payload)
        try:
            if retval == -1:
                return self.end_error(502, str(data))
            code = data['code']
            headers = data['headers']
            self.log_request(code)
            if code == 206 and self.command=='GET':
                m = re.search(r'bytes\s+(\d+)-(\d+)/(\d+)', headers.get('content-range',''))
                if m and self._RangeFetch(m, data):
                    return
            content = '%s %d %s\r\n%s\r\n%s' % (self.protocol_version, code, self.responses.get(code, ('GoAgent Notify', ''))[0], ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems()), data['content'])
            self.connection.sendall(content)
            if 'close' == headers.get('connection',''):
                self.close_connection = 1
        except socket.error, (err, _):
            # Connection closed before proxy return
            if err in (10053, errno.EPIPE):
                return

    do_GET = do_METHOD
    do_POST = do_METHOD
    do_PUT = do_METHOD
    do_DELETE = do_METHOD

class LocalProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == '__main__':
    if ctypes and os.name == 'nt':
        ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)
        if not common.LISTEN_VISIBLE:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    if common.GAE_DEBUGLEVEL:
        logging.root.setLevel(logging.DEBUG)
    CertUtil.checkCA()
    sys.stdout.write(common.info())
    SocketServer.TCPServer.address_family = (socket.AF_INET, socket.AF_INET6)[':' in common.LISTEN_IP]
    httpd = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), GaeProxyHandler)
    httpd.serve_forever()
