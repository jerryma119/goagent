@"%~dp0python27.exe" -x "%~dpnx0" && exit /b 0 || (pause && exit /b -1)

PARENT_PROXY = '10.64.1.63'
PARENT_PROXY_PORT = '8080'
USER = 'username_to_use'
PASSWORD = 'your_nt_password'
NT_DOMAIN = 'your_domain'


conf = {'GENERAL': {'PARENT_PROXY': PARENT_PROXY,
                    'PARENT_PROXY_PORT': PARENT_PROXY_PORT,
                    'LISTEN_PORT': '5865',
                    'ALLOW_EXTERNAL_CLIENTS': '0',
                    'DIRECT_CONNECT_IF_POSSIBLE': '0',
                    'FRIENDLY_IPS': '',
                    'HOSTS_TO_BYPASS_PARENT_PROXY': '',
                    'MAX_CONNECTION_BACKLOG': '5',
                    'PARENT_PROXY_TIMEOUT': '15',
                    'URL_LOG': '0',
                    'VERSION': '1.0'},
        'NTLM_AUTH': {'USER': USER,
                      'PASSWORD': PASSWORD,
                      'NT_DOMAIN': NT_DOMAIN,
                      'COMPLEX_PASSWORD_INPUT': '1',
                      'LM_HASHED_PW': '',
                      'LM_PART': '1',
                      'NT_HASHED_PW': '',
                      'NT_HOSTNAME': '',
                      'NT_PART': '0',
                      'NTLM_FLAGS': '06820000',
                      'NTLM_TO_BASIC': '0',},
        'CLIENT_HEADER': {'ACCEPT': 'image/gif, image/jpeg, */*',
                          'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)'},
        'DEBUG': {'AUTH_DEBUG': '0',
                  'BIN_DEBUG': '0',
                  'DEBUG': '0',
                  'SCR_DEBUG': '0'},}

#--------------------------------------------------------------
print 'NTLM authorization Proxy Server v%s' % conf['GENERAL']['VERSION']
print 'Copyright (C) 2001-2009 by Dmitry Rozmanov, Darryl Dixon, and others.'

if conf['NTLM_AUTH']['NTLM_TO_BASIC'] == '0' and conf['NTLM_AUTH']['USER'] == 'username_to_use':
    print
    print 'PLEASE SET username/password in %r' % __file__
    __import__('sys').exit(-1)

try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all()
except ImportError:
    sys.stderr.write('\033[31m  Warning: Please update gevent to the latest 1.0 version!\033[0m\n')

import sys
sys.path += ['python27.zip']
import ntlmaps
config = ntlmaps.config_affairs.arrange(conf)
serv = ntlmaps.server.AuthProxyServer(config)
serv.run()
