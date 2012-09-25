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
import re
import time
import errno
import binascii
import itertools
import zlib
import struct
import random
import hashlib
import fnmatch
import base64
import urlparse
import thread
import threading
import socket
import ssl
import select
import BaseHTTPServer
import SocketServer
import ConfigParser
import traceback
import collections
import Queue
import cStringIO
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

    ca_lock = threading.Lock()

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
        self.__write('%s - - [%s] %s\n' % (level, time.ctime()[4:-5], fmt%args))
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

class SimpleMessageClass(object):

    def __init__(self, fp, seekable = 0):
        self.dict = dict = {}
        self.headers = headers = []
        readline = getattr(fp, 'readline', None)
        headers_append = headers.append
        if readline:
            while 1:
                line = readline(8192)
                if not line or line == '\r\n':
                    break
                key, _, value = line.partition(':')
                if value:
                    headers_append(line)
                    dict[key.title()] = value.strip()
        else:
            for key, value in fp:
                key = key.title()
                dict[key] = value
                headers_append('%s: %s\r\n' % (key, value))

    def getheader(self, name, default=None):
        return self.dict.get(name.title(), default)

    def getheaders(self, name, default=None):
        return [self.getheader(name, default)]

    def addheader(self, key, value):
        self[key] = value

    def get(self, name, default=None):
        return self.dict.get(name.title(), default)

    def iteritems(self):
        return self.dict.iteritems()

    def iterkeys(self):
        return self.dict.iterkeys()

    def itervalues(self):
        return self.dict.itervalues()

    def keys(self):
        return self.dict.keys()

    def values(self):
        return self.dict.values()

    def items(self):
        return self.dict.items()

    def __getitem__(self, name):
        return self.dict[name.title()]

    def __setitem__(self, name, value):
        name = name.title()
        self.dict[name] = value
        headers = self.headers
        try:
            i = (i for i, line in enumerate(headers) if line.partition(':')[0].title() == name).next()
            headers[i] = '%s: %s\r\n' % (name, value)
        except StopIteration:
            headers.append('%s: %s\r\n' % (name, value))

    def __delitem__(self, name):
        name = name.title()
        del self.dict[name]
        headers = self.headers
        for i in reversed([i for i, line in enumerate(headers) if line.partition(':')[0].title() == name]):
            del headers[i]

    def __contains__(self, name):
        return name.title() in self.dict

    def __len__(self):
        return len(self.dict)

    def __iter__(self):
        return iter(self.dict)

    def __str__(self):
        return ''.join(self.headers)

class Http(object):
    """Http Request Class with connection pool support"""

    protocol_version = 'HTTP/1.1'

    def __init__(self, max_window=64, max_retry=2, max_timeout=30):
        self.max_window = max_window
        self.max_retry = max_retry
        self.max_timeout = max_timeout
        self.window = 1
        self.timeout = max_timeout // 2
        self.pool = collections.defaultdict(dict)
        self.dns = collections.defaultdict(set)
        self.crlf = 0
        self.__slowsocks_list = []

    def __slowsocks_gcthread(self):
        slowsocks_list = self.__slowsocks_list
        while 1:
            if not slowsocks_list:
                time.sleep(1)
                continue
            try:
                slowsocks_list.pop(0).close()
            except Exception as e:
                pass

    def _dns_resolve(self, host, dnsserver=''):
        iplist = self.dns[host]
        if not iplist:
            if not dnsservers:
                iplist.update([x[-1][0] for x in socket.getaddrinfo(host, 80)])
            else:
                index = os.urandom(2)
                hoststr = ''.join(chr(len(x))+x for x in host.split('.'))
                data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (index, hoststr)
                data = struct.pack('!H', len(data)) + data
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET if ':' not in dnsserver else socket.AF_INET6)
                    sock.connect((dnsserver, 53))
                    sock.sendall(data)
                    rfile = sock.makefile('rb')
                    size = struct.unpack('!H', rfile.read(2))[0]
                    data = rfile.read(size)
                    iplist.update('.'.join(str(ord(x)) for x in s) for s in re.findall('\xC0.\x00\x01\x00\x01.{6}(.{4})', data))
                    logging.info('dns_resolve(host=%r) return %s', host, iplist)
                except socket.error:
                    logging.exception('dns_resolve(host=%r) fail', host)
                finally:
                    if sock:
                        sock.close()
        return iplist

    def create_connection(self, (host, port), timeout=None, source_address=None, sslwrap=False):
        logging.debug('HTTPConnection.create_connection connect (%r, %r)', host, port)
        for i in xrange(self.max_retry):
            try:
                iplist = self._dns_resolve(host)
                window = self.window
                if len(iplist) > window:
                    iplist = random.sample(iplist, window)
                sock  = None
                socks = []
                for ip in iplist:
                    sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
                    sock.setblocking(0)
                    sock.connect_ex((ip, port))
                    socks.append(sock)
                _, outs, _ = select.select([], socks, [], self.timeout)
                if outs:
                    sock = outs.pop(0)
                    sock.setblocking(1)
                    socks.remove(sock)
                    self.__slowsocks_list += socks
                    if sslwrap:
                        sock = ssl.wrap_socket(sock)
                    return sock
            except Exception as e:
                logging.error('%s', e)

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

        sslwrap = scheme == 'https'

        for i in xrange(self.max_retry):
            try:
                sock = self.create_connection((host, port), self.timeout, sslwrap=sslwrap)
                if sock:
                    return self._request(sock, method, path, self.protocol_version, headers, data)
            except Exception as e:
                logging.warn('Http.request failed:%s', e)
                if sock:
                    sock.close()
                continue

    def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, idlecall=None):
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

    def copy_response(self, code, headers, write=None):
        need_return = False
        if write is None:
            output = cStringIO.StringIO()
            write = output.write
            need_return = True
        write('HTTP/1.1 %s\r\n' % code)
        for keyword, value in headers.iteritems():
            if keyword != 'Set-Cookie':
                write('%s: %s\r\n' % (keyword, value))
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
                write(''.join('Set-Cookie: %s\r\n' % x for x in cookies))
        write('\r\n')
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

http = Http()

class Common(object):
    """global config object"""

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
        self.GAE_RANGESIZE        = self.CONFIG.get('gae', 'rangesize') if self.CONFIG.has_option('gae', 'rangesize') else 4194304
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
            self.CRLF_DNS             = self.CONFIG.get('crlf', 'dns')
            self.CRLF_SITES           = tuple(self.CONFIG.get('crlf', 'sites').split('|'))
        else:
            self.CRLF_ENABLE          = 0

        self.USERAGENT_ENABLE     = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING     = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE          = self.CONFIG.getint('love','enable')
        self.LOVE_TIMESTAMP       = self.CONFIG.get('love', 'timestamp')
        self.LOVE_TIP             = [re.sub(r'(?i)\\u([0-9a-f]{4})', lambda m:unichr(int(m.group(1),16)), x) for x in self.CONFIG.get('love','tip').split('|')]

        self.HOSTS                = dict((k, set(v.split('|')) if v else set()) for k, v in self.CONFIG.items('hosts'))

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

    def install_opener(self):
        """install Http opener"""
        if self.CRLF_ENABLE:
            self.http.crlf = 1
        http.dns.update(common.HOSTS)

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version   : %s (python/%s pyopenssl/%s)\n' % (__version__, sys.version.partition(' ')[0], (OpenSSL.version.__version__ if OpenSSL else 'Disabled'))
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

class GAEProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    MessageClass = SimpleMessageClass
    setup_lock = threading.Lock()
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        host, port = self.client_address[:2]
        sys.stdout.write("%s:%d - - [%s] %s\n" % (host, port, time.ctime()[4:-5], fmt%args))

    def setup(self):
        if not common.PROXY_ENABLE and common.GAE_PROFILE != 'google_ipv6':
            logging.info('resolve common.GOOGLE_HOSTS domian=%r to iplist', common.GOOGLE_HOSTS)
            if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                with self.__class__.setup_lock:
                    if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                        google_iplist = [host for host in common.GOOGLE_HOSTS if re.match(r'\d+\.\d+\.\d+\.\d+', host)]
                        google_hosts = [host for host in common.GOOGLE_HOSTS if not re.match(r'\d+\.\d+\.\d+\.\d+', host)]
                        try:
                            google_hosts_iplist = [[x[-1][0] for x in socket.getaddrinfo(host, 80)] for host in google_hosts]
                            need_remote_dns = google_hosts and any(len(iplist)==1 for iplist in google_hosts_iplist)
                        except socket.gaierror:
                            need_remote_dns = True
                        if need_remote_dns:
                            logging.warning('OOOPS, there are some mistake in socket.getaddrinfo, try remote dns_resolve')
                            google_hosts_iplist = [list(dns_resolve(host)) for host in google_hosts]
                        common.GOOGLE_HOSTS = tuple(set(sum(google_hosts_iplist, google_iplist)))
                        if len(common.GOOGLE_HOSTS) == 0:
                            logging.error('resolve %s domian return empty! please use ip list to replace domain list!', common.GAE_PROFILE)
                            sys.exit(-1)
                        common.GOOGLE_HOSTS = tuple(x for x in common.GOOGLE_HOSTS if ':' not in x)
                        logging.info('resolve common.GOOGLE_HOSTS domian to iplist=%r', common.GOOGLE_HOSTS)
        http.dns[common.GAE_FETCHHOST] = common.GOOGLE_HOSTS
        GAEProxyHandler.do_GET     = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_POST    = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_PUT     = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_DELETE  = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_OPTIONS = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_HEAD    = GAEProxyHandler.do_METHOD
        GAEProxyHandler.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(':')
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            http.dns[host] = common.GOOGLE_HOSTS
            return self.do_CONNECT_Direct()
        elif host in http.dns:
            return self.do_CONNECT_Direct()
        elif common.CRLF_ENABLE and host.endswith(common.CRLF_SITES):
            return self.do_CONNECT_Direct()
        else:
            return self.do_CONNECT_Tunnel()

    def do_CONNECT_Direct(self):
        try:
            logging.debug('GAEProxyHandler.do_CONNECT_Directt %s' % self.path)
            host, _, port = self.path.rpartition(':')
            port = int(port)
            if not common.PROXY_ENABLE:
                sock = http.create_connection((host, port))
                self.wfile.write('%s 200 Tunnel established\r\n\r\n' % self.protocol_version)
                self.log_request(200)
            else:
                #TODO
                pass
            http.forward_socket(self.connection, sock)
        except Exception:
            logging.exception('GAEProxyHandler.do_CONNECT_Direct Error')
        finally:
            try:
                sock.close()
                del sock
            except:
                pass

    def do_CONNECT_Tunnel(self):
        # for ssl proxy
        host, _, port = self.path.rpartition(':')
        keyfile, certfile = CertUtil.get_cert(host)
        self.log_request(200)
        self.wfile.write('%s 200 OK\r\n\r\n' % self.protocol_version)
        try:
            self._realpath = self.path
            self._realrfile = self.rfile
            self._realwfile = self.wfile
            self._realconnection = self.connection
            try:
                self.connection = ssl.wrap_socket(self.connection, certfile=certfile, keyfile=keyfile, server_side=True)
            except Exception as e:
                logging.exception('ssl.wrap_socket(self.connection=%r) failed: %s', self.connection, e)
                self.connection = ssl.wrap_socket(self.connection, certfile=certfile, keyfile=keyfile, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
            self.rfile = self.connection.makefile('rb', self.rbufsize)
            self.wfile = self.connection.makefile('wb', self.wbufsize)
            self.raw_requestline = self.rfile.readline(8192)
            if self.raw_requestline == '':
                return
            self.parse_request()
            if self.path[0] == '/':
                if 'Host' in self.headers:
                    self.path = 'https://%s:%s%s' % (self.headers['Host'].partition(':')[0], port or 443, self.path)
                else:
                    self.path = 'https://%s%s' % (self._realpath, self.path)
                self.requestline = '%s %s %s' % (self.command, self.path, self.protocol_version)
            self.do_METHOD_Tunnel()
        except socket.error:
            logging.exception('do_CONNECT_Tunnel socket.error')
        finally:
            try:
                self.connection.shutdown(socket.SHUT_WR)
            except socket.error:
                pass
            self.rfile = self._realrfile
            self.wfile = self._realwfile
            self.connection = self._realconnection

    def do_METHOD(self):
        host = self.headers['Host']
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            if host in common.GOOGLE_FORCEHTTPS:
                http.copy_response(301, {'Location':self.path.replace('http://', 'https://')}, self.wfile)
                return
            http.dns[host] = common.GOOGLE_HOSTS
            return self.do_METHOD_Direct()
        elif host in http.dns:
            return self.do_METHOD_Direct()
        elif common.CRLF_ENABLE and host.endswith(common.CRLF_SITES):
            if host not in http.dns:
                logging.info('crlf dns_resolve(host=%r, dnsserver=%r)', host, common.CRLF_DNS)
                http.dns[host] = http.dns_resolve(host, common.CRLF_DNS)
            return self.do_METHOD_Direct()
        else:
            return self.do_METHOD_Tunnel()

    def do_METHOD_Direct(self):
        try:
            self.log_request()

            content_length = int(self.headers.get('Content-Length', 0))
            payload = self.rfile.read(content_length) if content_length else None

            self.headers['Connection'] = 'close'
            code, headers, body = http.request(self.command, self.path, payload, dict(self.headers))
            http.copy_response(code, headers, self.wfile.write)
            http.copy_body(body, headers, self.wfile.write)
        except Exception:
            logging.exception('GAEProxyHandler.do_GET Error')

    def rangefetch(self, method, url, headers, payload, range_maxsize, current_length, content_length):
        assert range_maxsize > 0, 'range_maxsize > 0 failed!'
        while current_length < content_length:
            headers['Range'] = 'bytes=%d-%d' % (current_length, min(current_length+range_maxsize-1, content_length-1))
            request_method, request_headers, payload = pack_request(method, url, headers, payload, common.GAE_FETCHHOST, password=common.GAE_PASSWORD, fetchmaxsize=common.GAE_RANGESIZE)
            request  = urllib2.Request(common.GAE_FETCHSERVER, data=payload, headers=request_headers)
            request.get_method = lambda: request_method

            for i in xrange(3):
                try:
                    response = urllib2.urlopen(request)
                except urllib2.HTTPError as http_error:
                    response = http_error
                except urllib2.URLError as url_error:
                    raise

                if 'Set-Cookie' not in response.headers:
                    logging.error('rangefetch %r return %s', url, response.code)
                    time.sleep(2**(i+1))
                    continue
                response_headers, response_kwargs = decode_request(response.headers['Set-Cookie'])
                response_status = int(response_kwargs['status'])
                if 200 <= response_status < 400:
                    break
                else:
                    logging.error('rangefetch %r return %s', url, response_status)
                    time.sleep(2**(i+1))
                    continue

            if 300 < response_status < 400:
                response_location = dict(response_headers).get('Location')
                logging.info('Range Fetch Redirect(%r)', response_location)
                if response_location:
                    return self.rangefetch(method, response_location, headers, payload, range_maxsize, current_length, content_length)

            content_range = dict(response_headers).get('Content-Range')
            if not content_range:
                logging.error('rangefetch "%s %s" failed: response_kwargs=%s response_headers=%s', method, url, response_kwargs, response_headers)
                return

            logging.info('>>>>>>>>>>>>>>> %s %d', content_range, content_length)
            while 1:
                data = response.read(8192)
                if not data or current_length >= content_length:
                    response.close()
                    break
                current_length += len(data)
                self.wfile.write(data)

    def do_METHOD_Tunnel(self):
        host = self.headers.get('Host') or urlparse.urlparse(self.path).netloc.partition(':')[0]
        if self.path[0] == '/':
            self.path = 'http://%s%s' % (host, self.path)

        if common.USERAGENT_ENABLE:
            self.headers['User-Agent'] = common.USERAGENT_STRING

        try:
            method, headers, payload = pack_request(self.command, self.path, self.headers, self.rfile, common.GAE_FETCHHOST, password=common.GAE_PASSWORD, fetchmaxsize=common.GAE_RANGESIZE)

            try:
                code, headers, body = http.request(method, common.GAE_FETCHSERVER, payload, headers)
                # gateway error, switch to https mode
                if code in (400, 504) or (code==502 and common.GAE_PROFILE=='google_cn'):
                    common.GOOGLE_MODE = 'https'
                    common.build_gae_fetchserver()
                    # appid over qouta, switch to next appid
                if code == 503:
                    common.GAE_APPIDS.append(common.GAE_APPIDS.pop(0))
                    common.build_gae_fetchserver()
                    # bad request, disable CRLF injection
                if code in (400, 405):
                    http.crlf = 0
            except socket.error as e:
                if e[0] in (11004, 10051, 10054, 10060, 'timed out', ):
                    # connection reset or timeout, switch to https
                    common.GOOGLE_MODE = 'https'
                    common.build_gae_fetchserver()
                raise

            if 'Set-Cookie' not in headers:
                http.copy_response(code, headers, self.wfile.write)
                http.copy_body(body, headers, self.wfile.write)
                return

            response_headers, response_kwargs = decode_request(headers['Set-Cookie'])
            response_status = int(response_kwargs['status'])

            if response_status != 206:
                http.copy_response(response_status, response_headers, self.wfile.write)
                http.copy_body(body, response_headers, self.wfile.write)
            else:
                response_headers_towrite = []
                for keyword, value in headers:
                    if keyword == 'Content-Range':
                        content_range = value
                    elif keyword == 'Content-Length':
                        content_length = value
                    else:
                        response_headers_towrite.append((keyword, value))
                start, end, length = map(int, re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3))
                if start == 0:
                    response_status = 200
                    response_headers_towrite += [('Content-Length', str(length))]
                else:
                    response_status = 206
                    if self.headers.get('Range'):
                        response_headers_towrite += [('Content-Range', content_range), ('Content-Length', content_length)]
                    else:
                        response_headers_towrite += [('Content-Range', 'bytes %s-%s/%s' % (start, length-1, length)), ('Content-Length', str(length-start))]

                self.start_response(response_status, response_headers_towrite)

                range_maxsize = 0
                while 1:
                    data = response.read(8192)
                    if not data:
                        response.close()
                        break
                    range_maxsize += len(data)
                    self.wfile.write(data)

                if range_maxsize:
                    logging.info('>>>>>>>>>>>>>>> Range Fetch started(%r) %d-%d', host, end+1, length)
                    self.rangefetch(self.command, self.path, self.headers, payload, range_maxsize, end+1, length)
                    logging.info('>>>>>>>>>>>>>>> Range Fetch ended(%r)', host)
                return
        except socket.error as e:
            # Connection closed before proxy return
            if e[0] in (10053, errno.EPIPE):
                return

class PAASProxyHandler(GAEProxyHandler):

    def setup(self):
        host = common.PAAS_FETCHHOST
        if host not in common.HOSTS:
            logging.info('resolve host domian=%r to iplist', host)
            with self.__class__.setup_lock:
                if host not in common.HOSTS:
                    common.HOSTS[host] = tuple(x[-1][0] for x in socket.getaddrinfo(host, 80))
                    logging.info('resolve host domian to iplist=%r', common.HOSTS[host])
        PAASProxyHandler.do_GET     = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_POST    = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_PUT     = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_DELETE  = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_OPTIONS = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_HEAD    = PAASProxyHandler.do_METHOD
        PAASProxyHandler.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def do_METHOD(self):
        host = self.headers.get('Host') or urlparse.urlparse(self.path).netloc.partition(':')[0]
        if self.path[0] == '/':
            self.path = 'http://%s%s' % (host, self.path)

        if common.USERAGENT_ENABLE:
            self.headers['User-Agent'] = common.USERAGENT_STRING

        try:
            method, headers, payload = pack_request(self.command, self.path, self.headers, self.rfile, common.PAAS_FETCHHOST, password=common.PAAS_PASSWORD)
            request  = urllib2.Request(common.PAAS_FETCHSERVER, data=payload, headers=headers)
            request.get_method = lambda: method

            try:
                response = urllib2.urlopen(request)
            except urllib2.HTTPError as http_error:
                response = http_error
                if response.code in (400, 405):
                    httplib.HTTPConnection.putrequest = _httplib_HTTPConnection_putrequest
            except urllib2.URLError as url_error:
                raise

            headers = httplib_normalize_headers(response.headers.items())
            self.start_response(response.code, headers)

            while 1:
                data = response.read(8192)
                if not data:
                    response.close()
                    break
                self.wfile.write(data)
        except httplib.HTTPException as e:
            raise
        except socket.error as e:
            # Connection closed before proxy return
            if e[0] in (10053, errno.EPIPE):
                return

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(':')
        keyfile, certfile = CertUtil.get_cert(host)
        self.log_request(200)
        self.connection.sendall('%s 200 OK\r\n\r\n' % self.protocol_version)
        try:
            self._realpath = self.path
            self._realrfile = self.rfile
            self._realwfile = self.wfile
            self._realconnection = self.connection
            try:
                self.connection = ssl.wrap_socket(self.connection, certfile=certfile, keyfile=keyfile, server_side=True)
            except Exception as e:
                logging.exception('ssl.wrap_socket(self.connection=%r) failed: %s', self.connection, e)
                self.connection = ssl.wrap_socket(self.connection, certfile=certfile, keyfile=keyfile, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
            self.rfile = self.connection.makefile('rb', self.rbufsize)
            self.wfile = self.connection.makefile('wb', self.wbufsize)
            self.raw_requestline = self.rfile.readline(8192)
            if self.raw_requestline == '':
                return
            self.parse_request()
            if self.path[0] == '/':
                if 'Host' in self.headers:
                    self.path = 'https://%s:%s%s' % (self.headers['Host'].partition(':')[0], port or 443, self.path)
                else:
                    self.path = 'https://%s%s' % (self._realpath, self.path)
                self.requestline = '%s %s %s' % (self.command, self.path, self.protocol_version)
            self.do_METHOD()
        except socket.error as e:
            logging.exception('PAASProxyHandler.do_CONNECT socket.error %s', e)
        finally:
            try:
                self.connection.shutdown(socket.SHUT_WR)
            except socket.error:
                pass
            self.rfile = self._realrfile
            self.wfile = self._realwfile
            self.connection = self._realconnection

class Sock5ProxyHandler(SocketServer.StreamRequestHandler):

    setup_lock = threading.Lock()

    def log_message(self, fmt, *args):
        host, port = self.client_address[:2]
        sys.stdout.write("%s:%d - - [%s] %s\n" % (host, port, time.ctime()[4:-5], fmt%args))

    def connect_paas(self, socks5_fetchserver):
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(socks5_fetchserver)
        if re.search(r':\d+$', netloc):
            host, _, port = netloc.rpartition(':')
            port = int(port)
        else:
            host = netloc
            port = {'https':443,'http':80}.get(scheme, 80)
        sock = socket.create_connection((host, port))
        if scheme == 'https':
            sock = ssl.wrap_socket(sock)
        sock.sendall('PUT /socks5 HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n' % host)
        return sock

    def handle(self):
        try:
            socks5_fetchserver = common.SOCKS5_FETCHSERVER
            self.log_message('Connect to socks5_server=%r', socks5_fetchserver)
            sock = self.connect_paas(socks5_fetchserver)
            socket_forward(self.connection, sock)
        except Exception, e:
            logging.exception('Sock5ProxyHandler.handle client_address=%r failed:%s', self.client_address[:2], e)

    def setup(self):
        fetchhost = re.sub(r':\d+$', '', urlparse.urlparse(common.SOCKS5_FETCHSERVER).netloc)
        if not common.PROXY_ENABLE:
            logging.info('resolve socks5 fetchhost=%r to iplist', fetchhost)
            if fetchhost not in common.HOSTS:
                with Sock5ProxyHandler.setup_lock:
                    if fetchhost not in common.HOSTS:
                        common.HOSTS[fetchhost] = tuple(x[-1][0] for x in socket.getaddrinfo(fetchhost, 80))
                        logging.info('resolve socks5 fetchhost=%r to iplist=%r', fetchhost, common.HOSTS[fetchhost])
        Sock5ProxyHandler.setup = SocketServer.StreamRequestHandler.setup
        SocketServer.StreamRequestHandler.setup(self)

class PacServerHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_GET(self):
        filename = os.path.join(os.path.dirname(__file__), common.PAC_FILE)
        if self.path != '/'+common.PAC_FILE or not os.path.isfile(filename):
            return self.send_error(404, 'Not Found')
        with open(filename, 'rb') as fp:
            data = fp.read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-ns-proxy-autoconfig')
            self.end_headers()
            self.wfile.write(data)
            self.wfile.close()

class ProxyAndPacHandler(GAEProxyHandler, PacServerHandler):
    def do_GET(self):
        if self.path == '/'+common.PAC_FILE:
            PacServerHandler.do_GET(self)
        else:
            GAEProxyHandler.do_METHOD(self)

class LocalProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

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
    logging.basicConfig(level=logging.DEBUG if common.GAE_DEBUGLEVEL else logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
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
    common.install_opener()
    sys.stdout.write(common.info())

    LocalProxyServer.address_family = (socket.AF_INET, socket.AF_INET6)[':' in common.LISTEN_IP]

    if common.PAAS_ENABLE:
        host, _, port = common.PAAS_LISTEN.rpartition(':')
        httpd = LocalProxyServer((host, int(port)), PAASProxyHandler)
        thread.start_new_thread(httpd.serve_forever, ())

    if common.SOCKS5_ENABLE:
        host, _, port = common.SOCKS5_LISTEN.rpartition(':')
        httpd = LocalProxyServer((host, int(port)), Sock5ProxyHandler)
        thread.start_new_thread(httpd.serve_forever, ())

    if common.PAC_ENABLE and common.PAC_PORT != common.LISTEN_PORT:
        httpd = LocalProxyServer((common.PAC_IP,common.PAC_PORT),PacServerHandler)
        thread.start_new_thread(httpd.serve_forever,())

    if common.PAC_ENABLE and common.PAC_PORT == common.LISTEN_PORT:
        httpd = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), ProxyAndPacHandler)
    else:
        httpd = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), GAEProxyHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
