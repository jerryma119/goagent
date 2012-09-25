#!/usr/bin/env python
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>
#      Hewig Xu       <hewigovens@gmail.com>
#      Ayanamist Yang <ayanamist@gmail.com>
#      Max Lv         <max.c.lv@gmail.com>
#      AlsoTang       <alsotang@gmail.com>
#      Yonsm          <YonsmGuo@gmail.com>

from __future__ import with_statement

__version__ = '2.0.6'
__config__  = 'proxy.ini'

import sys
import os
import gevent, gevent.server, gevent.monkey
gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
try:
    from gevent.lock import Semaphore as LockType
except ImportError:
    from gevent.coros import Semaphore as LockType

import re
import time
import errno
import zlib
import random
import httplib
import base64
import urlparse
import socket
import ssl
import select
import collections
import cStringIO
import ConfigParser
import traceback
import struct
import hashlib
import fnmatch
try:
    import logging
except ImportError:
    logging = None
try:
    import ctypes
except ImportError:
    ctypes = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None

class CertUtil(object):
    """CertUtil module, based on mitmproxy"""

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
        subj.organizationName = 'GoAgent'
        subj.organizationalUnitName = 'GoAgent Root'
        subj.commonName = 'GoAgent'
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'nsCertType', True, b'sslCA'),
            OpenSSL.crypto.X509Extension(b'extendedKeyUsage', True,
                b'serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca),
            ])
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
    def _get_cert(commonname, certdir='certs', ca_keyfile='CA.key', ca_certfile='CA.crt', sans = []):
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
        subj.organizationalUnitName = 'GoAgent Branch'
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
            sans = ['*'+commonname] + [x for x in sans if x != '*'+commonname]
        else:
            sans = [commonname] + [x for x in sans if x != commonname]
        cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, 'sha1')

        keyfile  = os.path.join(certdir, commonname + '.key')
        with open(keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        certfile = os.path.join(certdir, commonname + '.crt')
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))

        return keyfile, certfile

    @staticmethod
    def get_cert(commonname, certdir='certs', ca_keyfile='CA.key', ca_certfile='CA.crt', sans = []):
        if len(commonname) >= 32:
            commonname = re.sub(r'^[^\.]+', '', commonname)
        keyfile  = os.path.join(certdir, commonname + '.key')
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
    def check_ca():
        #Check CA exists
        capath = os.path.join(os.path.dirname(__file__), 'CA.key')
        if not os.path.exists(capath):
            if not OpenSSL:
                logging.critical('CA.key is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            if os.name == 'nt':
                os.system('certmgr.exe -del -n "GoAgent CA" -c -s -r localMachine Root')
            [os.remove(os.path.join('certs', x)) for x in os.listdir('certs')]
            CertUtil.dump_ca('CA.key', 'CA.crt')
            #Check CA imported
        cmd = {
            'win32'  : r'cd /d "%s" && certmgr.exe -add CA.crt -c -s -r localMachine Root >NUL' % os.path.dirname(__file__),
            }.get(sys.platform)
        if cmd and os.system(cmd) != 0:
            logging.warning('GoAgent install trusted root CA certificate failed, Please run goagent by administrator/root.')
            #Check Certs Dir
        certdir = os.path.join(os.path.dirname(__file__), 'certs')
        if not os.path.exists(certdir):
            os.makedirs(certdir)

class SimpleLogging(object):
    """Simple Logger Class"""

    CRITICAL = 50
    FATAL = CRITICAL
    ERROR = 40
    WARNING = 30
    WARN = WARNING
    INFO = 20
    DEBUG = 10
    NOTSET = 0
    def __init__(self, *args, **kwargs):
        self.level = SimpleLogging.INFO
        if self.level > SimpleLogging.DEBUG:
            self.debug = self.dummy
        self.__write = sys.stdout.write
    @classmethod
    def getLogger(cls, *args, **kwargs):
        return cls(*args, **kwargs)
    def basicConfig(self, *args, **kwargs):
        self.level = kwargs.get('level', SimpleLogging.INFO)
        if self.level > SimpleLogging.DEBUG:
            self.debug = self.dummy
    def log(self, level, fmt, *args, **kwargs):
        self.__write('%s - [%s] %s\n' % (level, time.ctime()[4:-5], fmt%args))
    def dummy(self, *args, **kwargs):
        pass
    def debug(self, fmt, *args, **kwargs):
        self.log('DEBUG', fmt, *args, **kwargs)
    def info(self, fmt, *args, **kwargs):
        self.log('INFO', fmt, *args)
    def warning(self, fmt, *args, **kwargs):
        self.log('WARNING', fmt, *args, **kwargs)
    def warn(self, fmt, *args, **kwargs):
        self.log('WARNING', fmt, *args, **kwargs)
    def error(self, fmt, *args, **kwargs):
        self.log('ERROR', fmt, *args, **kwargs)
    def exception(self, fmt, *args, **kwargs):
        self.log('ERROR', fmt, *args, **kwargs)
        traceback.print_exc(file=sys.stderr)
    def critical(self, fmt, *args, **kwargs):
        self.log('CRITICAL', fmt, *args, **kwargs)

class SimpleHTTPServer(gevent.server.StreamServer):
    """A lightweight HTTP Server based gevent"""

    MessageClass = dict

    def __init__(self, listener, application, backlog=None, spawn='default', **ssl_args):
        gevent.server.StreamServer.__init__(self, listener, backlog=backlog, spawn=spawn, **ssl_args)
        self.application = application

    def parse_request(self, rfile, bufsize=8192):
        line = rfile.readline(bufsize)
        if not line:
            raise socket.error('empty line')
        method, path, version = line.split(' ', 2)
        headers = self.MessageClass()
        while 1:
            line = rfile.readline(bufsize)
            if not line or line == '\r\n':
                break
            keyword, _, value = line.partition(':')
            keyword = keyword.title()
            value = value.strip()
            headers[keyword] = value
        return method, path, version, headers

    def handle(self, sock, address):
        rfile = sock.makefile('rb', -1)
        try:
            method, path, version, headers = self.parse_request(rfile)
            self.application(sock, address, rfile, method, path, version, headers, self)
        except socket.error as e:
            if e[0] not in (10053, 'empty line'):
                raise

class Http(object):
    """Http Request Class"""

    protocol_version = 'HTTP/1.1'
    spawn_later = gevent.spawn_later

    def __init__(self, min_window=3, max_window=64, max_retry=2, max_timeout=30, spawn_later=None):
        self.min_window = min_window
        self.max_window = max_window
        self.max_retry = max_retry
        self.max_timeout = max_timeout
        self.window = min_window
        self.window_ack = 0
        self.timeout = max_timeout // 2
        self.dns = collections.defaultdict(set)
        self.crlf = 0
        if spawn_later is not None:
            self.spawn_later = spawn_later

    def dns_resolve(self, host, dnsserver='', ipv4_only=True):
        iplist = self.dns[host]
        if not iplist:
            if not dnsserver:
                ips = [x[-1][0] for x in socket.getaddrinfo(host, 80)]
                iplist.update()
            else:
                #resolver = gevent.resolver_ares.Resolver(servers=[dnsserver], tcp_port=53)
                #ips = [x[-1][0] for x in resolver.getaddrinfo(host, 80)]
                index = os.urandom(2)
                hoststr = ''.join(chr(len(x))+x for x in host.split('.'))
                data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (index, hoststr)
                data = struct.pack('!H', len(data)) + data
                address_family = socket.AF_INET6 if ':' in dnsserver else socket.AF_INET
                sock = None
                try:
                    sock = socket.socket(family=address_family)
                    sock.connect((dnsserver, 53))
                    sock.sendall(data)
                    rfile = sock.makefile('rb')
                    size = struct.unpack('!H', rfile.read(2))[0]
                    data = rfile.read(size)
                    ips = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xC0.\x00\x01\x00\x01.{6}(.{4})', data)]
                except Exception, e:
                    raise
                finally:
                    if sock:
                        sock.close()
            if ipv4_only:
                ips = [ip for ip in ips if re.match(r'\d+.\d+.\d+.\d+', ip)]
            iplist.update(ips)
        return iplist

    def create_connection(self, (host, port), timeout=None, source_address=None):
        logging.debug('Http.create_connection connect (%r, %r)', host, port)
        for i in xrange(self.max_retry):
            try:
                iplist = self.dns_resolve(host)
                window = self.window
                ips = iplist if len(iplist) <= window else random.sample(iplist, window)
                sock  = None
                socks = []
                for ip in ips:
                    sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
                    sock.setblocking(0)
                    sock.connect_ex((ip, port))
                    socks.append(sock)
                _, outs, _ = select.select([], socks, [], self.timeout)
                if outs:
                    sock = outs.pop(0)
                    sock.setblocking(1)
                    if window > self.min_window:
                        self.window_ack += 1
                        if self.window_ack > 10:
                            self.window_ack = 0
                            self.window = window - 1
                            logging.info('Http.create_connection to (%s, %r) successed, switch window=%r', iplist, port, self.window)
                    socks.remove(sock)
                    self.spawn_later(0.5, lambda ss:any(x.close() for x in ss), socks)
                    return sock
                else:
                    self.window = int(1.5 * self.window)
                    if self.window > self.max_window:
                        self.window = self.max_window
                    if self.window > len(iplist):
                        self.window = len(iplist)
                    self.window_ack = 0
                    logging.error('Http.create_connection to (%s, %r) failed, switch window=%r', ips, port, self.window)
            except Exception as e:
                logging.error('%s', e)

    def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None):
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
                        if data:
                            if sock is local:
                                remote.sendall(data)
                                timecount = maxping or timeout
                            else:
                                local.sendall(data)
                                timecount = maxpong or timeout
                        else:
                            return
        except socket.error as e:
            if e[0] not in (10053, 10054, errno.EPIPE):
                raise
        finally:
            local.close()
            remote.close()

    def _request(self, sock, method, path, protocol_version, headers, data, crlf=None):
        request_data = '\r\n' * (crlf or self.crlf)
        request_data += '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems())
        request_data += '\r\n' if not data else '\r\n'+data
        wfile = sock.makefile('wb', 0)
        wfile.write(request_data)

        rfile = sock.makefile('rb', -1)

        response_line = rfile.readline(8192)
        if not response_line:
            raise socket.error('empty line')
        version, code, _ = response_line.split(' ', 2)
        code = int(code)

        headers = {}
        content_length = 0
        connection = ''
        transfer_encoding = ''
        while 1:
            line = rfile.readline(8192)
            if not line or line == '\r\n':
                break
            keyword, _, value = line.partition(':')
            keyword = keyword.title()
            headers[keyword] = value.strip()
        return code, headers, rfile

    def request(self, method, url, data=None, headers={}, fullurl=False):
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
        if not re.search(r':\d+$', netloc):
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        if query:
            path += '?' + query

        if 'Host' not in headers:
            headers['Host'] = host

        for i in xrange(self.max_retry):
            try:
                sock = self.create_connection((host, port), self.timeout)
                if sock:
                    if scheme == 'https':
                        sock = ssl.wrap_socket(sock)
                    code, headers, rfile = self._request(sock, method, path, self.protocol_version, headers, data)
                    return code, headers, rfile
            except Exception as e:
                logging.warn('Http.request failed:%s', e)
                if sock:
                    sock.close()
                continue

    def copy_response(self, code, headers, write=None):
        need_return = False
        if write is None:
            output = cStringIO.StringIO()
            write = output.write
            need_return = True
        if 'Set-Cookie' in headers:
            headers['Set-Cookie'] = re.sub(', ([^ =]+(?:=|$))', '\\r\\nSet-Cookie: \\1', headers['Set-Cookie'])
        write('HTTP/1.1 %s\r\n%s\r\n' % (code, ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems())))
        if need_return:
            return output.getvalue()

    def copy_body(self, rfile, headers, write=None):
        need_return = False
        if write is None:
            output = cStringIO.StringIO()
            write = output.write
            need_return = True
        content_length = int(headers.get('Content-Length', 0))
        if content_length:
            left = content_length
            while left > 0:
                data = rfile.read(min(left, 8192))
                if not data:
                    break
                left -= len(data)
                write(data)
        elif headers.get('Connection', '').lower() == 'close':
            while 1:
                data = rfile.read(8192)
                if not data:
                    break
                write(data)
        elif headers.get('Transfer-Encoding', '').lower() == 'chunked':
            while 1:
                line = rfile.readline(8192)
                if not line:
                    break
                write(line)
                if line == '\r\n':
                    continue
                count = int(line , 16)
                if count == 0:
                    break
                else:
                    write(rfile.read(count))
        else:
            pass
        if need_return:
            return output.getvalue()

class Common(object):
    """Global Config Object"""

    def __init__(self):
        """load config from proxy.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        self.CONFIG.read(os.path.join(os.path.dirname(__file__), __config__))

        self.LISTEN_IP            = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT          = self.CONFIG.getint('listen', 'port')
        self.LISTEN_VISIBLE       = self.CONFIG.getint('listen', 'visible')

        self.GAE_ENABLE           = self.CONFIG.getint('gae', 'enable')
        self.GAE_APPIDS           = self.CONFIG.get('gae', 'appid').replace('.appspot.com', '').split('|')
        self.GAE_PASSWORD         = self.CONFIG.get('gae', 'password').strip()
        self.GAE_PATH             = self.CONFIG.get('gae', 'path')
        self.GAE_PROFILE          = self.CONFIG.get('gae', 'profile')
        self.GAE_MULCONN          = self.CONFIG.getint('gae', 'mulconn')
        self.GAE_RANGESIZE        = self.CONFIG.getint('gae', 'rangesize') if self.CONFIG.has_option('gae', 'rangesize') else 4194304
        self.GAE_DEBUGLEVEL       = self.CONFIG.getint('gae', 'debuglevel') if self.CONFIG.has_option('gae', 'debuglevel') else 0

        self.PAAS_ENABLE           = self.CONFIG.getint('paas', 'enable')
        self.PAAS_LISTEN           = self.CONFIG.get('paas', 'listen')
        self.PAAS_PASSWORD         = self.CONFIG.get('paas', 'password') if self.CONFIG.has_option('paas', 'password') else ''
        self.PAAS_FETCHSERVER      = self.CONFIG.get('paas', 'fetchserver')
        self.PAAS_FETCHHOST        = urlparse.urlparse(self.CONFIG.get('paas', 'fetchserver')).netloc.rsplit(':', 1)[0]

        if self.CONFIG.has_section('socks5'):
            self.SOCKS5_ENABLE           = self.CONFIG.getint('socks5', 'enable')
            self.SOCKS5_LISTEN           = self.CONFIG.get('socks5', 'listen')
            self.SOCKS5_PASSWORD         = self.CONFIG.get('socks5', 'password') if self.CONFIG.has_option('socks5', 'password') else ''
            self.SOCKS5_FETCHSERVER      = self.CONFIG.get('socks5', 'fetchserver')
        else:
            self.SOCKS5_ENABLE           = 0

        if self.CONFIG.has_section('pac'):
            # XXX, cowork with GoAgentX
            self.PAC_ENABLE           = self.CONFIG.getint('pac','enable')
            self.PAC_IP               = self.CONFIG.get('pac','ip')
            self.PAC_PORT             = self.CONFIG.getint('pac','port')
            self.PAC_FILE             = self.CONFIG.get('pac','file').lstrip('/')
        else:
            self.PAC_ENABLE           = 0

        self.PROXY_ENABLE         = self.CONFIG.getint('proxy', 'enable')
        self.PROXY_HOST           = self.CONFIG.get('proxy', 'host')
        self.PROXY_PORT           = self.CONFIG.getint('proxy', 'port')
        self.PROXY_USERNAME       = self.CONFIG.get('proxy', 'username')
        self.PROXY_PASSWROD       = self.CONFIG.get('proxy', 'password')

        self.GOOGLE_MODE          = self.CONFIG.get(self.GAE_PROFILE, 'mode')
        self.GOOGLE_HOSTS         = tuple(self.CONFIG.get(self.GAE_PROFILE, 'hosts').split('|'))
        self.GOOGLE_SITES         = tuple(self.CONFIG.get(self.GAE_PROFILE, 'sites').split('|'))
        self.GOOGLE_FORCEHTTPS    = frozenset(self.CONFIG.get(self.GAE_PROFILE, 'forcehttps').split('|'))
        self.GOOGLE_WITHGAE       = frozenset(self.CONFIG.get(self.GAE_PROFILE, 'withgae').split('|'))

        self.FETCHMAX_LOCAL       = self.CONFIG.getint('fetchmax', 'local') if self.CONFIG.get('fetchmax', 'local') else 3
        self.FETCHMAX_SERVER      = self.CONFIG.get('fetchmax', 'server')

        if self.CONFIG.has_section('crlf'):
            # XXX, cowork with GoAgentX
            self.CRLF_ENABLE          = self.CONFIG.getint('crlf', 'enable')
            self.CRLF_DNSSERVER       = self.CONFIG.get('crlf', 'dns')
            self.CRLF_SITES           = tuple(self.CONFIG.get('crlf', 'sites').split('|'))
        else:
            self.CRLF_ENABLE          = 0

        self.USERAGENT_ENABLE     = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING     = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE          = self.CONFIG.getint('love','enable')
        self.LOVE_TIMESTAMP       = self.CONFIG.get('love', 'timestamp')
        self.LOVE_TIP             = [re.sub(r'(?i)\\u([0-9a-f]{4})', lambda m:unichr(int(m.group(1),16)), x) for x in self.CONFIG.get('love','tip').split('|')]

        self.HOSTS                = dict((k, tuple(v.split('|')) if v else tuple()) for k, v in self.CONFIG.items('hosts'))

        self.build_gae_fetchserver()

    def build_gae_fetchserver(self):
        """rebuild gae fetch server config"""
        if self.PROXY_ENABLE:
            self.GOOGLE_MODE = 'https'
        self.GAE_FETCHHOST = '%s.appspot.com' % self.GAE_APPIDS[0]
        if not self.PROXY_ENABLE:
            # append '?' to url, it can avoid china telicom/unicom AD
            self.GAE_FETCHSERVER = '%s://%s%s?' % (self.GOOGLE_MODE, self.GAE_FETCHHOST, self.GAE_PATH)
        else:
            self.GAE_FETCHSERVER = '%s://%s%s?' % (self.GOOGLE_MODE, random.choice(self.GOOGLE_HOSTS), self.GAE_PATH)

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version   : %s (python/%s gevent/%s pyopenssl/%s)\n' % (__version__, sys.version.partition(' ')[0], gevent.__version__, (OpenSSL.version.__version__ if OpenSSL else 'Disabled'))
        info += 'Listen Address    : %s:%d\n' % (self.LISTEN_IP,self.LISTEN_PORT)
        info += 'Local Proxy       : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'Debug Level       : %s\n' % self.GAE_DEBUGLEVEL if self.GAE_DEBUGLEVEL else ''
        info += 'GAE Mode          : %s\n' % self.GOOGLE_MODE if self.GAE_ENABLE else ''
        info += 'GAE Profile       : %s\n' % self.GAE_PROFILE
        info += 'GAE APPID         : %s\n' % '|'.join(self.GAE_APPIDS)
        if common.PAAS_ENABLE:
            info += 'PAAS Listen       : %s\n' % common.PAAS_LISTEN
            info += 'PAAS FetchServer  : %s\n' % common.PAAS_FETCHSERVER
        if common.SOCKS5_ENABLE:
            info += 'SOCKS5 Listen      : %s\n' % common.PAAS_LISTEN
            info += 'SOCKS5 FetchServer : %s\n' % common.SOCKS5_FETCHSERVER
        if common.PAC_ENABLE:
            info += 'Pac Server        : http://%s:%d/%s\n' % (self.PAC_IP,self.PAC_PORT,self.PAC_FILE)
        if common.CRLF_ENABLE:
            #http://www.acunetix.com/websitesecurity/crlf-injection.htm
            info += 'CRLF Injection    : %s\n' % '|'.join(self.CRLF_SITES)
        info += '------------------------------------------------------\n'
        return info

http   = Http()
common = Common()

def encode_request(headers, **kwargs):
    if hasattr(headers, 'items'):
        headers = headers.items()
    data = ''.join('%s: %s\r\n' % (k, v) for k, v in headers) + ''.join('X-Goa-%s: %s\r\n' % (k.title(), v) for k, v in kwargs.iteritems())
    return base64.b64encode(zlib.compress(data)).rstrip()

def decode_request(request):
    data     = zlib.decompress(base64.b64decode(request))
    headers  = {}
    kwargs   = {}
    for line in data.splitlines():
        keyword, _, value = line.partition(':')
        if keyword.startswith('X-Goa-'):
            kwargs[keyword[6:].lower()] = value.strip()
        else:
            headers[keyword.title()] = value.strip()
    return headers, kwargs

def pack_request(method, url, headers, payload, fetchhost, **kwargs):
    content_length = int(headers.get('Content-Length',0))
    request_kwargs = {'method':method, 'url':url}
    request_kwargs.update(kwargs)
    request_headers = {'Host':fetchhost, 'Cookie':encode_request(headers, **request_kwargs), 'Content-Length':str(content_length)}
    if not isinstance(payload, str):
        payload = payload.read(content_length)
    return 'POST', request_headers, payload

def rangefetch(wfile, response_headers, response_rfile, method, url, headers, payload, rangesize, fetchhost, fetchserver, password):
    content_range  = response_headers['Content-Range']
    content_length = response_headers['Content-Length']
    start, end, length = map(int, re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3))
    if start == 0:
        response_status = 200
        response_headers['Content-Length'] = str(length)
    else:
        response_status = 206
        if not headers.get('Range'):
            response_headers['Content-Range']  = 'bytes %s-%s/%s' % (start, length-1, length)
            response_headers['Content-Length'] = str(length-start)

    logging.info('>>>>>>>>>>>>>>> Range Fetch started(%r) %d-%d', url, start, end)
    http.copy_response(response_status, response_headers, wfile.write)
    http.copy_body(response_rfile, response_headers, wfile.write)
    response_rfile.close()

    current_length = end+1
    content_length = length
    logging.info('>>>>>>>>>>>>>>> Range Fetch next(%r) %d-%d', url, current_length, content_length)
    while current_length < content_length:
        headers['Range'] = 'bytes=%d-%d' % (current_length, min(current_length+rangesize-1, content_length-1))
        retry = 8
        while retry > 0:
            request_method, request_headers, request_payload = pack_request(method, url, headers, payload, fetchhost, password=password)
            code, response_headers, response_rfile = http.request(request_method, fetchserver, request_payload, request_headers)
            if 'Set-Cookie' not in response_headers:
                logging.error('Range Fetch %r return %s', url, code)
                time.sleep(5)
                continue
            response_headers, response_kwargs = decode_request(response_headers['Set-Cookie'])
            code = int(response_kwargs['status'])
            if 200 <= code < 300:
                break
            elif 300 <= code < 400:
                url = response_headers['Location']
                logging.info('Range Fetch Redirect(%r)', url)
                response_rfile.close()
                continue
            else:
                logging.error('Range Fetch %r return %s', url, code)
                response_rfile.close()
                time.sleep(5)
                continue

        content_range = response_headers.get('Content-Range')
        if not content_range:
            logging.error('Range Fetch "%s %s" failed: response_kwargs=%s response_headers=%s', method, url, response_kwargs, response_headers)
            return

        logging.info('>>>>>>>>>>>>>>> %s %d', content_range, content_length)
        while 1:
            data = response_rfile.read(8192)
            if not data or current_length >= content_length:
                response_rfile.close()
                break
            current_length += len(data)
            wfile.write(data)
    logging.info('>>>>>>>>>>>>>>> Range Fetch ended(%r)', url)

def gaeproxy_application(sock, address, rfile, method, path, version, headers, server, ls={'setuplock':LockType()}):
    if 'setup' not in ls:
        if not common.PROXY_ENABLE and common.GAE_PROFILE != 'google_ipv6':
            logging.info('resolve common.GOOGLE_HOSTS domian=%r to iplist', common.GOOGLE_HOSTS)
            if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                with ls['setuplock']:
                    if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                        google_iplist = [host for host in common.GOOGLE_HOSTS if re.match(r'\d+\.\d+\.\d+\.\d+', host)]
                        google_hosts = [host for host in common.GOOGLE_HOSTS if not re.match(r'\d+\.\d+\.\d+\.\d+', host)]
                        google_hosts_iplist = [[x[-1][0] for x in socket.getaddrinfo(host, 80)] for host in google_hosts]
                        common.GOOGLE_HOSTS = tuple(x for x in set(sum(google_hosts_iplist, google_iplist)) if ':' not in x)
                        if len(common.GOOGLE_HOSTS) == 0:
                            logging.error('resolve %s domian return empty! please use ip list to replace domain list!', common.GAE_PROFILE)
                            sys.exit(-1)
            http.dns[common.GAE_FETCHHOST] = common.GOOGLE_HOSTS
            logging.info('resolve common.GOOGLE_HOSTS domian to iplist=%r', common.GOOGLE_HOSTS)
        ls['setup'] = True

    if common.USERAGENT_ENABLE:
        headers['User-Agent'] = common.USERAGENT_STRING

    remote_addr, remote_port = address

    __realsock = None
    __realrfile = None
    if method == 'CONNECT':
        host, _, port = path.rpartition(':')
        port = int(port)
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            logging.info('%s:%s - "%s %s:%d HTTP/1.1" - -' % (remote_addr, remote_port, method, host, port))
            http_headers = ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems())
            if not common.PROXY_ENABLE:
                remote = http.create_connection((host, port), 8)
            else:
                remote = socket.create_connection((host, int(port)))
                remote.send('CONNECT %s:%s\r\n%s\r\n' % (host, port, http_headers))
            if not remote:
                logging.error('Connect remote host(%r) failed', host)
                return
            sock.send('HTTP/1.1 200 OK\r\n\r\n')
            http.forward_socket(sock, remote)
            return
        else:
            keyfile, certfile = CertUtil.get_cert(host)
            logging.info('%s:%s - "%s %s:%d HTTP/1.1" - -' % (remote_addr, remote_port, method, host, port))
            sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
            __realsock = sock
            __realrfile = rfile
            try:
                sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True)
            except Exception as e:
                logging.exception('ssl.wrap_socket(__realsock=%r) failed: %s', __realsock, e)
                sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
            rfile = sock.makefile('rb', 8192)
            method, path, version, headers = server.parse_request(rfile)
            if path[0] == '/' and host:
                path = 'https://%s%s' % (headers['Host'], path)

    host = headers.get('Host', '')
    if path[0] == '/' and host:
        path = 'http://%s%s' % (host, path)

    need_direct = False
    if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
        if host in common.GOOGLE_FORCEHTTPS:
            sock.sendall('HTTP/1.1 301\r\nLocation: %s\r\n\r\n' % path.replace('http://', 'https://'))
            return
        else:
            http.dns[host] = common.GOOGLE_HOSTS
            need_direct = True
    elif common.CRLF_ENABLE and host.endswith(common.CRLF_SITES):
        if host not in http.dns:
            logging.info('crlf dns_resolve(host=%r, dnsservers=%r)', host, common.CRLF_DNSSERVER)
            http.dns[host] = set(http.dns_resolve(host, common.CRLF_DNSSERVER))
            logging.info('crlf dns_resolve(host=%r) return %s', host, list(http.dns[host]))
        http.crlf = 1
        need_direct = True

    if need_direct:
        try:
            logging.info('%s:%s - "%s %s HTTP/1.1" - -' % (remote_addr, remote_port, method, path))
            content_length = int(headers.get('Content-Length', 0))
            payload = rfile.read(content_length) if content_length else None
            response_code, response_headers, response_rfile = http.request(method, path, payload, headers)
            wfile = sock.makefile('wb', 0)
            http.copy_response(response_code, response_headers, wfile.write)
            http.copy_body(response_rfile, response_headers, wfile.write)
            response_rfile.close()
        except socket.error as e:
            if e[0] not in (10053, errno.EPIPE):
                raise
        except Exception as e:
            logging.warn('gaeproxy_appliaction direct(%s) Error', host)
            raise
        finally:
            rfile.close()
            sock.close()
            if __realrfile:
                __realrfile.close()
            if __realsock:
                __realsock.close()
    else:
        try:
            request_method, request_headers, request_payload = pack_request(method, path, headers, rfile, common.GAE_FETCHHOST, password=common.GAE_PASSWORD, fetchmaxsize=common.GAE_RANGESIZE)
            try:
                code, response_headers, response_rfile = http.request(request_method, common.GAE_FETCHSERVER, data=request_payload or None, headers=request_headers)
            except socket.error as e:
                if e[0] in (11004, 10051, 10054, 10060, 'timed out', 'empty line'):
                    # connection reset or timeout, switch to https
                    common.GOOGLE_MODE = 'https'
                    common.build_gae_fetchserver()
                else:
                    raise

            # gateway error, switch to https mode
            if code in (400, 504) or (code==502 and common.GAE_PROFILE=='google_cn'):
                common.GOOGLE_MODE = 'https'
                common.build_gae_fetchserver()
            # appid over qouta, switch to next appid
            if code == 503:
                common.GAE_APPIDS.append(common.GAE_APPIDS.pop(0))
                common.build_gae_fetchserver()
                http.dns[common.GAE_FETCHHOST] = common.GOOGLE_HOSTS
            # bad request, disable CRLF injection
            if code in (400, 405):
                http.crlf = 0

            wfile = sock.makefile('wb', 0)

            if 'Set-Cookie' not in response_headers:
                logging.info('%s:%s - "%s %s HTTP/1.1" %s -' % (remote_addr, remote_port, method, path, code))
                http.copy_response(code, response_headers, wfile.write)
                http.copy_body(response_rfile, response_headers, wfile.write)
                response_rfile.close()
                return

            response_headers, response_kwargs = decode_request(response_headers['Set-Cookie'])
            code = int(response_kwargs['status'])
            logging.info('%s:%s - "%s %s HTTP/1.1" %s -' % (remote_addr, remote_port, method, path, code))

            if code == 206:
                rangefetch(wfile, response_headers, response_rfile, method, path, headers, request_payload, common.GAE_RANGESIZE, common.GAE_FETCHHOST, common.GAE_FETCHSERVER, common.GAE_PASSWORD)
                return
            http.copy_response(code, response_headers, wfile.write)
            http.copy_body(response_rfile, response_headers, wfile.write)
            response_rfile.close()
        except socket.error as e:
            # Connection closed before proxy return
            if e[0] not in (10053, errno.EPIPE):
                raise
        finally:
            rfile.close()
            sock.close()
            if __realrfile:
                __realrfile.close()
            if __realsock:
                __realsock.close()

def paasproxy_application(sock, address, rfile, method, path, version, headers, server, ls={'setuplock':LockType()}):
    if 'setup' not in ls:
        if not common.PROXY_ENABLE and common.GAE_PROFILE != 'google_ipv6':
            logging.info('resolve common.PAAS_FETCHHOST domian=%r to iplist', common.PAAS_FETCHHOST)
            with ls['setuplock']:
                paas_fethhost_iplist = [x[-1][0] for x in socket.getaddrinfo(common.PAAS_FETCHHOST, 80)]
                if len(common.paas_fethhost_iplist) == 0:
                    logging.error('resolve %s domian return empty! please use ip list to replace domain list!', common.GAE_PROFILE)
                    sys.exit(-1)
                http.dns[common.PAAS_FETCHHOST] = paas_fethhost_iplist
                logging.info('resolve common.PAAS_FETCHHOST domian to iplist=%r', common.PAAS_FETCHHOST)
        ls['setup'] = True

    if common.USERAGENT_ENABLE:
        headers['User-Agent'] = common.USERAGENT_STRING

    remote_addr, remote_port = address

    if method == 'CONNECT':
        host, _, port = path.rpartition(':')
        port = int(port)
        keyfile, certfile = CertUtil.get_cert(host)
        logging.info('%s:%s - "%s:%d HTTP/1.1" - -' % (address[0], address[1], host, port))
        sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
        __realsock = sock
        __realrfile = rfile
        try:
            sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True)
        except Exception as e:
            logging.exception('ssl.wrap_socket(__realsock=%r) failed: %s', __realsock, e)
            sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
        rfile = sock.makefile('rb', 8192)
        method, path, version, headers = server.parse_request(rfile)
        if path[0] == '/' and host:
            path = 'https://%s%s' % (headers['Host'], path)

    host = headers.get('Host', '')
    if path[0] == '/' and host:
        path = 'http://%s%s' % (host, path)

    logging.info('%s:%s - "%s %s HTTP/1.1" - -' % (remote_addr, remote_port, method, path))
    try:
        request_method, request_headers, request_payload = pack_request(method, path, headers, rfile, common.GAE_FETCHHOST, password=common.GAE_PASSWORD, fetchmaxsize=common.GAE_RANGESIZE)
        try:
            code, response_headers, response_rfile = http.request(request_method, common.GAE_FETCHSERVER, data=request_payload or None, headers=request_headers)
        except socket.error as e:
            if e.reason[0] in (11004, 10051, 10060, 'timed out', 10054):
                # connection reset or timeout, switch to https
                common.GOOGLE_MODE = 'https'
                common.build_gae_fetchserver()
            else:
                raise
        except Exception as e:
            logging.exception('error: %s', e)
            raise

        if code in (400, 405):
            http.crlf = 0

        wfile = sock.makefile('wb', 0)
        http.copy_response(code, response_headers, wfile.write)
        http.copy_body(response_rfile, response_headers, wfile.write)
        response_rfile.close()

    except socket.error as e:
        # Connection closed before proxy return
        if e[0] not in (10053, errno.EPIPE):
            raise

def socks5proxy_application(sock, address, rfile, method, path, version, headers, server, ls={'setuplock':LockType()}):
    if 'setup' not in ls:
        if not common.PROXY_ENABLE and common.GAE_PROFILE != 'google_ipv6':
            socks5_fetchhost = urlparse.urlparse(common.SOCKS5_FETCHSERVER).netloc
            logging.info('resolve common.SOCKS5_FETCHSERVER domian=%r to iplist', socks5_fetchhost)
            with ls['setuplock']:
                socks5_fethhost_iplist = [x[-1][0] for x in socket.getaddrinfo(socks5_fetchhost, 80)]
                if len(socks5_fethhost_iplist) == 0:
                    logging.error('resolve %s domian return empty! please use ip list to replace domain list!', socks5_fetchhost)
                    sys.exit(-1)
                http.dns[socks5_fetchhost] = socks5_fethhost_iplist
                logging.info('resolve common.PAAS_FETCHHOST domian to iplist=%r', common.PAAS_FETCHHOST)
        ls['setup'] = True

    #TODO

def pacserver_application(sock, address, rfile, method, path, version, headers, server):
    wfile = sock.makefile('wb', 0)
    filename = os.path.join(os.path.dirname(__file__), common.PAC_FILE)
    if path != '/'+common.PAC_FILE or not os.path.isfile(filename):
        return self.send_error(404, 'Not Found')
    with open(filename, 'rb') as fp:
        data = fp.read()
        wfile.write('HTTP/1.1 200\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n')
        wfile.write(data)
        wfile.close()
    sock.close()

def gaeproxy_withpac_application(sock, address, rfile, method, path, version, headers, server, ls={'setuplock':LockType()}):
    if path[0] == '/' and path[-4:] == '.pac':
        return pacserver_application(sock, address, rfile, method, path, version, headers, server)
    else:
        return gaeproxy_application(sock, address, rfile, method, path, version, headers, server, ls)

def try_show_love():
    """If you hate this funtion, please go back to gappproxy/wallproxy"""
    if ctypes and os.name == 'nt' and common.LOVE_ENABLE:
        SetConsoleTitleW = ctypes.windll.kernel32.SetConsoleTitleW
        GetConsoleTitleW = ctypes.windll.kernel32.GetConsoleTitleW
        if common.LOVE_TIMESTAMP.strip():
            common.LOVE_TIMESTAMP = int(common.LOVE_TIMESTAMP)
        else:
            common.LOVE_TIMESTAMP = int(time.time())
            with open(__config__, 'w') as fp:
                common.CONFIG.set('love', 'timestamp', int(time.time()))
                common.CONFIG.write(fp)
        if time.time() - common.LOVE_TIMESTAMP > 86400 and random.randint(1,10) > 5:
            title = ctypes.create_unicode_buffer(1024)
            GetConsoleTitleW(ctypes.byref(title), len(title)-1)
            SetConsoleTitleW(u'%s %s' % (title.value, random.choice(common.LOVE_TIP)))
            with open(__config__, 'w') as fp:
                common.CONFIG.set('love', 'timestamp', int(time.time()))
                common.CONFIG.write(fp)

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    global logging
    if logging is None:
        sys.modules['logging'] = logging = SimpleLogging()
    logging.basicConfig(level=logging.DEBUG if common.GAE_DEBUGLEVEL else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    if ctypes and os.name == 'nt':
        ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)
        if not common.LOVE_TIMESTAMP.strip():
            sys.stdout.write('Double click addto-startup.vbs could add goagent to autorun programs. :)\n')
        try_show_love()
        if not common.LISTEN_VISIBLE:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    if common.GAE_APPIDS[0] == 'goagent' and not common.CRLF_ENABLE:
        logging.critical('please edit %s to add your appid to [gae] !', __config__)
        sys.exit(-1)
    CertUtil.check_ca()
    sys.stdout.write(common.info())

    if common.PAAS_ENABLE:
        server = SimpleHTTPServer(common.PAAS_LISTEN, paasproxy_application)
        server.start()

    if common.SOCKS5_ENABLE:
        server = SimpleHTTPServer(common.SOCKS5_LISTEN, socks5proxy_application)
        server.start()

    if common.PAC_ENABLE and common.PAC_PORT != common.LISTEN_PORT:
        server = SimpleHTTPServer((common.PAC_IP, common.PAC_PORT), pacserver_application)
        server.start()

    if common.PAC_ENABLE and common.PAC_PORT == common.LISTEN_PORT:
        server = SimpleHTTPServer((common.LISTEN_IP, common.LISTEN_PORT), gaeproxy_withpac_application, spawn=1024)
    else:
        server = SimpleHTTPServer((common.LISTEN_IP, common.LISTEN_PORT), gaeproxy_application, spawn=1024)
    server.serve_forever()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
