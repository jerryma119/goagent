#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

__version__ = 'beta'
__author__ =  'phus.lu@gmail.com'

import sys, os, re, time
import errno, zlib, struct, binascii, base64
import logging
import httplib, urllib, urllib2, urlparse, socket, select
import BaseHTTPServer, SocketServer
import random
import ConfigParser
import ssl
import ctypes
import threading, Queue
try:
    import OpenSSL
except ImportError:
    OpenSSL = None

logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%d/%b/%Y %H:%M:%S]')

class Common(object):
    '''global config module, based on GappProxy 2.0.0'''
    FILENAME = sys.argv[1] if len(sys.argv) == 2 and os.path.isfile(os.sys.argv[1]) else os.path.splitext(__file__)[0] + '.ini'
    ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')

    def __init__(self):
        '''read proxy.ini config'''
        self.config = ConfigParser.ConfigParser()
        self.config.read(self.__class__.FILENAME)

        self.LISTEN_IP      = self.config.get('listen', 'ip')
        self.LISTEN_PORT    = self.config.getint('listen', 'port')
        self.LISTEN_VISIBLE = self.config.getint('listen', 'visible')

        self.GAE_APPIDS     = self.config.get('gae', 'appid').replace('.appspot.com', '').split('|')
        self.GAE_PASSWORD   = self.config.get('gae', 'password').strip()
        self.GAE_DEBUG      = self.config.get('gae', 'debug')
        self.GAE_PATH       = self.config.get('gae', 'path')
        self.GAE_BINDHOSTS  = tuple(self.config.get('gae', 'bindhosts').split('|')) if self.config.has_option('gae', 'bindhosts') else ()
        self.GAE_CERTS      = self.config.get('gae', 'certs').split('|')

        self.PROXY_ENABLE   = self.config.getint('proxy', 'enable')
        self.PROXY_TYPE     = self.config.get('proxy', 'type') if self.config.has_option('proxy', 'type') else 'http'
        self.PROXY_HOST     = self.config.get('proxy', 'host')
        self.PROXY_PORT     = self.config.getint('proxy', 'port')
        self.PROXY_USERNAME = self.config.get('proxy', 'username')
        self.PROXY_PASSWROD = self.config.get('proxy', 'password')

        self.GOOGLE_PREFER     = self.config.get('google', 'prefer')
        self.GOOGLE_SITES      = tuple(self.config.get('google', 'sites').split('|'))
        self.GOOGLE_FORCEHTTPS = tuple(self.config.get('google', 'forcehttps').split('|'))
        self.GOOGLE_HOSTS      = [x.split('|') for x in self.config.get('google', 'hosts').split('||')]

        self.AUTORANGE_HOSTS    = tuple(self.config.get('autorange', 'hosts').split('|'))
        self.AUTORANGE_ENDSWITH = set(self.config.get('autorange', 'endswith').split('|'))

        self.HOSTS = dict(self.config.items('hosts'))

    def info(self):
        info = ''
        info += '--------------------------------------------\n'
        info += 'OpenSSL Module : %s\n' % ('Enabled' if OpenSSL else 'Disabled')
        info += 'Listen Address : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Log Level      : %s\n' % self.GAE_DEBUG
        info += 'Local Proxy    : %s://%s:%s\n' % (self.PROXY_TYPE, self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
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
    window = 4
    window_ack = 0

    def __init__(self, hostslist, port):
        self.socket = None
        self._sockets = set([])
        self.connect(hostslist, port, MultiplexConnection.timeout, MultiplexConnection.window)
    def connect(self, hostslist, port, timeout, window):
        for i, hosts in enumerate(hostslist):
            if len(hosts) > window:
                hosts = random.sample(hosts, window)
            logging.debug('MultiplexConnection connect (%s, %s)', hosts, port)
            socs = []
            for host in hosts:
                soc_family = socket.AF_INET6 if ':' in host else socket.AF_INET
                soc = socket.socket(soc_family, socket.SOCK_STREAM)
                soc.setblocking(0)
                logging.debug('MultiplexConnection connect_ex (%r, %r)', host, port)
                err = soc.connect_ex((host, port))
                self._sockets.add(soc)
                socs.append(soc)
            (_, outs, _) = select.select([], socs, [], timeout)
            if outs:
                self.socket = outs[0]
                self.socket.setblocking(1)
                self._sockets.remove(self.socket)
                if window > 1:
                    MultiplexConnection.window_ack += 1
                    if MultiplexConnection.window_ack > 16:
                        MultiplexConnection.window = window - 1
                        MultiplexConnection.window_ack = 0
                        logging.info('MultiplexConnection CONNECT port=443 OK 10 times, switch new window=%d', MultiplexConnection.window)
                break
            else:
                logging.warning('MultiplexConnection Cannot hosts %r:%r, window=%d', hosts, port, window)
        else:
            MultiplexConnection.window = min(int(round(window*1.5)), 64)
            MultiplexConnection.window_ack = 0
            logging.warning(r'MultiplexConnection Cannot Connect to hostslist %s:%s, switch new window=%d', hostslist, port, MultiplexConnection.window)
            raise RuntimeError(r'MultiplexConnection Cannot Connect to hostslist %s:%s' % (hostslist, port))
    def close(self):
        for soc in self._sockets:
            try:
                soc.close()
            except:
                pass

def socket_create_connection(address, timeout=None, source_address=None):
    host, port = address
    logging.debug('socket_create_connection connect (%r, %r)', host, port)
    if host.endswith(common.GOOGLE_SITES):
        msg = 'socket_create_connection returns an empty list'
        try:
            hostslist = common.GOOGLE_HOSTS
            logging.debug("socket_create_connection connect hostslist: (%r, %r)", hostslist, port)
            conn = MultiplexConnection(hostslist, port)
            conn.close()
            soc = conn.socket
            #soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            return soc
        except socket.error, msg:
            logging.error('socket_create_connection connect fail: (%r, %r)', hostslist, port)
            soc = None
        if not soc:
            raise socket.error, msg
    else:
        msg = "getaddrinfo returns an empty list"
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
    count = timeout // tick
    try:
        while 1:
            count -= 1
            (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
            if errors:
                break
            if ins:
                for soc in ins:
                    data = soc.recv(bufsize)
                    if data:
                        if soc is local:
                            remote.send(data)
                            count = maxping or timeout // tick
                        else:
                            local.send(data)
                            count = maxpong or timeout // tick
            if count == 0:
                break
    except Exception, ex:
        logging.warning('socket_forward error=%s', ex)
        raise

class RootCA(object):
    '''RootCA module, based on WallProxy 0.4.0'''

    CA = None
    CALock = threading.Lock()

    @staticmethod
    def readFile(filename):
        try:
            f = open(filename, 'rb')
            c = f.read()
            f.close()
            return c
        except IOError:
            return None

    @staticmethod
    def writeFile(filename, content):
        f = open(filename, 'wb')
        f.write(str(content))
        f.close()

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
        pkey = RootCA.createKeyPair(bits=2048)
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': 'GoAgent',
                'organizationalUnitName': 'GoAgent Root', 'commonName': 'GoAgent CA'}
        req = RootCA.createCertRequest(pkey, **subj)
        cert = RootCA.createCertificate(req, (pkey, req), 0, (0, 60*60*24*7305))  #20 years
        return (RootCA.dumpPEM(pkey, 0), RootCA.dumpPEM(cert, 2))

    @staticmethod
    def makeCert(host, (cakey, cacrt), serial):
        pkey = RootCA.createKeyPair()
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': host,
                'organizationalUnitName': 'GoAgent Branch', 'commonName': host}
        req = RootCA.createCertRequest(pkey, **subj)
        cert = RootCA.createCertificate(req, (cakey, cacrt), serial, (0, 60*60*24*7305))
        return (RootCA.dumpPEM(pkey, 0), RootCA.dumpPEM(cert, 2))

    @staticmethod
    def getCertificate(host):
        basedir = os.path.dirname(__file__)
        keyFile = os.path.join(basedir, 'certs/%s.key' % host)
        crtFile = os.path.join(basedir, 'certs/%s.crt' % host)
        if os.path.exists(keyFile):
            return (keyFile, crtFile)
        if not OpenSSL:
            keyFile = os.path.join(basedir, 'CA.key')
            crtFile = os.path.join(basedir, 'CA.crt')
            return (keyFile, crtFile)
        if not os.path.isfile(keyFile):
            try:
                RootCA.CALock.acquire()
                if not os.path.isfile(keyFile):
                    logging.info('RootCA getCertificate for %r', host)
                    serialFile = os.path.join(basedir, 'CA.srl')
                    SERIAL = RootCA.readFile(serialFile)
                    SERIAL = int(SERIAL)+1
                    key, crt = RootCA.makeCert(host, RootCA.CA, SERIAL)
                    RootCA.writeFile(keyFile, key)
                    RootCA.writeFile(crtFile, crt)
                    RootCA.writeFile(serialFile, str(SERIAL))
            finally:
                RootCA.CALock.release()
        return (keyFile, crtFile)

    @staticmethod
    def checkCA():
        #Check CA imported
        if os.name == 'nt':
            basedir = os.path.dirname(__file__)
            os.environ['PATH'] += os.pathsep + basedir
            #cmd = r'certmgr.exe -add "%s\CA.crt" -c -s -r localMachine Root >NUL' % basedir
            cmd = r'certutil.exe -store Root "GoAgent CA" >NUL || certutil.exe -f -addstore root CA.crt'
            if os.system(cmd) != 0:
                logging.warn('Import GoAgent CA \'CA.crt\' %r failed.', cmd)
        #Check CA file
        cakeyFile = os.path.join(os.path.dirname(__file__), 'CA.key')
        cacrtFile = os.path.join(os.path.dirname(__file__), 'CA.crt')
        cakey = RootCA.readFile(cakeyFile)
        cacrt = RootCA.readFile(cacrtFile)
        if OpenSSL:
            RootCA.CA = (RootCA.loadPEM(cakey, 0), RootCA.loadPEM(cacrt, 2))
            for host in common.GAE_CERTS:
                RootCA.getCertificate(host)

def gae_encode_data(dic):
    return '&'.join('%s=%s' % (k, binascii.b2a_hex(str(v))) for k, v in dic.iteritems())

def gae_decode_data(qs):
    return dict((k, binascii.a2b_hex(v)) for k, v in (x.split('=') for x in qs.split('&')))

def build_opener():
    if common.PROXY_ENABLE:
        proxies = {common.PROXY_TYPE:'%s:%d'%(common.PROXY_HOST, common.PROXY_PORT)}
        proxy_handler = urllib2.ProxyHandler(proxies)
    else:
        proxy_handler = urllib2.ProxyHandler({})
    opener = urllib2.build_opener(proxy_handler)
    opener.addheaders = []
    return opener

class GaeProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    part_size = 1048576
    skip_headers = set(['host', 'vary', 'via', 'x-forwarded-for', 'proxy-authorization', 'proxy-connection', 'upgrade', 'keep-alive'])
    opener = build_opener()

    def address_string(self):
        return '%s:%s' % self.client_address[:2]

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
        self.connection.close()

    def finish(self):
        try:
            self.wfile.close()
            self.rfile.close()
        except socket.error, (err, _):
            # Connection closed by browser
            if err == 10053 or err == errno.EPIPE:
                self.log_message('socket.error: [%s] "Software caused connection abort"', err)
            else:
                raise

    def _fetch(self, url, method, headers, payload):
        errors = []
        params = {'url':url, 'method':method, 'headers':headers, 'payload':payload}
        logging.debug('GaeProxyHandler fetch params %s', params)
        if common.GAE_PASSWORD:
            params['password'] = common.GAE_PASSWORD
        params = gae_encode_data(params)
        for i in range(1, 4):
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
                if e.code == 502 or e.code == 504:
                    common.GOOGLE_PREFER = 'https'
                    sys.stdout.write(common.info())
                errors.append('%d: %s' % (e.code, httplib.responses.get(e.code, 'Unknown HTTPError')))
                continue
            except urllib2.URLError, e:
                if e.reason[0] in (11004, 10051, 10054, 10060, 'timed out'):
                    # it seems that google.cn is reseted, switch to https
                    if e.reason[0] == 10054:
                        MultiplexConnection.window_ack = 0
                        MultiplexConnection.window = min(int(round(MultiplexConnection.window*1.5)), 64)
                        common.GOOGLE_PREFER = 'https'
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
        self.connection.close()
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
                soc = socket.create_connection((host, int(port)))
                self.log_request(200)
                self.wfile.write('%s 200 Tunnel established\r\n\r\n' % self.protocol_version)
            else:
                soc = socket.create_connection((common.PROXY_HOST, common.PROXY_PORT))
                if host.endswith(common.GOOGLE_SITES):
                    ip = random.choice(common.GOOGLE_HOSTS[0])
                else:
                    ip = random.choice(common.HOSTS.get(host, host)[0])
                data = '%s %s:%s %s\r\n\r\n' % (self.command, ip, port, self.protocol_version)
                if common.PROXY_USERNAME:
                    data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode('%s:%s'%(urllib.unquote(common.PROXY_USERNAME), urllib.unquote(common.PROXY_PASSWROD))).strip()
                soc.send(data)
            socket_forward(self.connection, soc, maxping=8)
        except:
            logging.exception('GaeProxyHandler.do_CONNECT_Direct Error')
            self.send_error(502, 'GaeProxyHandler.do_CONNECT_Direct Error')
        finally:
            try:
                self.connection.close()
            except:
                pass
            try:
                soc.close()
            except:
                pass

    def do_CONNECT_GAE(self):
        # for ssl proxy
        host, _, port = self.path.rpartition(':')
        keyFile, crtFile = RootCA.getCertificate(host)
        self.log_request(200)
        self.connection.send('%s 200 OK\r\n\r\n' % self.protocol_version)
        try:
            ssl_sock = ssl.wrap_socket(self.connection, keyFile, crtFile, True)
            self._realconnection = self.connection
            self._realpath = self.path
            self.connection = ssl_sock
            self.rfile = self.connection.makefile('rb', self.rbufsize)
            self.wfile = self.connection.makefile('wb', self.wbufsize)
            self.raw_requestline = self.rfile.readline()
            self.parse_request()
            if self.path[0] == '/':
                self.path = 'https://%s%s' % (self._realpath, self.path)
                #self.requestline = '%s %s %s' % (self.command, self.path, self.protocol_version)
            self.do_METHOD_GAE()
            self._realconnection.close()
        except socket.error, e:
            logging.exception('do_CONNECT_GAE socket.error: %s', e)
            return

    def do_METHOD(self):
        host = self.headers.get('host')
        if host.endswith(common.GOOGLE_SITES) or host in common.HOSTS:
            if self.path.startswith(common.GOOGLE_FORCEHTTPS):
                self.send_response(301)
                self.send_header("Location", self.path.replace('http://', 'https://'))
                self.end_headers()
                return
            if not common.PROXY_ENABLE:
                return self.do_METHOD_Direct()
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
                soc = socket.create_connection((host, port))
                data = '%s %s %s\r\n'  % (self.command, urlparse.urlunparse(('', '', path, params, query, '')), self.request_version)
                data += ''.join('%s: %s\r\n' % (k, self.headers[k]) for k in self.headers if not k.startswith('proxy-'))
                data += '\r\n'
            else:
                soc = socket.create_connection((common.PROXY_HOST, common.PROXY_PORT))
                if host.endswith(common.GOOGLE_SITES):
                    host = random.choice(common.GOOGLE_HOSTS[0])
                else:
                    host = common.HOSTS.get(host, host)
                data ='%s %s %s\r\n'  % (self.command, urlparse.urlunparse((scheme, host + ('' if port == 80 else ':%d' % port), path, params, query, '')), self.request_version)
                data += ''.join('%s: %s\r\n' % (k, self.headers[k]) for k in self.headers if k != 'host' and not k.startswith('proxy-'))
                data += 'Host: %s\r\n' % netloc
                if common.PROXY_USERNAME:
                    data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode('%s:%s'%(urllib.unquote(common.PROXY_USERNAME), urllib.unquote(common.PROXY_PASSWROD))).strip()
                data += 'Proxy-connection: close\r\n'
                data += '\r\n'
            content_length = int(self.headers.get('content-length', 0))
            if content_length > 0:
                data += self.rfile.read(content_length)
            soc.send(data)
            socket_forward(self.connection, soc, maxping=10)
        except Exception, ex:
            logging.exception('SimpleProxyHandler.do_GET Error, %s', ex)
            self.send_error(502, 'SimpleProxyHandler.do_GET Error (%s)' % ex)
        finally:
            try:
                self.connection.close()
            except:
                pass
            try:
                soc.close()
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
        if host.endswith(common.AUTORANGE_HOSTS) or self.path.rpartition('.')[2] in common.AUTORANGE_ENDSWITH:
            headers += 'Range: bytes=0-%d\r\n' % self.part_size

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
            if headers.get('connection', '').lower() == 'close':
                self.close_connection = 1
            content = '%s %d %s\r\n%s\r\n%s' % (self.protocol_version, code, self.responses.get(code, ('GoAgent Notify', ''))[0], ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems()), data['content'])
            self.connection.send(content)
        except socket.error, (err, _):
            # Connection closed before proxy return
            if err == errno.EPIPE or err == 10053:
                return
        self.connection.shutdown(socket.SHUT_WR)
        self.connection.close()

    do_GET = do_METHOD
    do_POST = do_METHOD
    do_PUT = do_METHOD
    do_DELETE = do_METHOD

class LocalProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == '__main__':
    RootCA.checkCA()
    if common.GAE_DEBUG != 'INFO':
        logging.root.setLevel(getattr(logging, common.GAE_DEBUG, logging.DEBUG))
    sys.stdout.write(common.info())
    if os.name == 'nt' and not common.LISTEN_VISIBLE:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    SocketServer.TCPServer.address_family = {True:socket.AF_INET6, False:socket.AF_INET}[':' in common.LISTEN_IP]
    httpd = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), GaeProxyHandler)
    httpd.serve_forever()
