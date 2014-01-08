@"%~dp0python27.exe" -x "%~dpnx0" && exit /b 0 || exit /b -1

conf = {'GENERAL': {'PARENT_PROXY': 'YOUR_PARENTPROXY',
                    'PARENT_PROXY_PORT': '8080',
                    'LISTEN_PORT': '5865',
                    'ALLOW_EXTERNAL_CLIENTS': '0',
                    'DIRECT_CONNECT_IF_POSSIBLE': '0',
                    'FRIENDLY_IPS': '',
                    'HOSTS_TO_BYPASS_PARENT_PROXY': '',
                    'MAX_CONNECTION_BACKLOG': '5',
                    'PARENT_PROXY_TIMEOUT': '15',
                    'URL_LOG': '0'},
        'NTLM_AUTH': {'USER': 'username_to_use',
                      'PASSWORD': 'your_nt_password',
                      'NT_DOMAIN': 'your_domain',
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

import sys
import os
import ntlmaps

#--------------------------------------------------------------
print 'NTLM authorization Proxy Server v1.0'
print 'Copyright (C) 2001-2009 by Dmitry Rozmanov, Darryl Dixon, and others.'

config = ntlmaps.config_affairs.arrange(conf)
serv = ntlmaps.server.AuthProxyServer(config)
serv.run()
