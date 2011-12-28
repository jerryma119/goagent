#!/usr/bin/env python
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

__version__ = '1.0'
__author__ = "phus.lu@gmail.com"

import sys, os, re, time
sys.path.extend(['.', 'appcfg.zip'])

def upload(dirname, appid):
    assert isinstance(dirname, basestring) and isinstance(appid, basestring)
    filename = os.path.join(dirname, 'app.yaml')
    assert os.path.isfile(filename)
    with open(filename, 'rb') as fp:
        yaml = fp.read()
    yaml=re.sub(r'application:\s*\S+', 'application: '+appid, yaml)
    with open(filename, 'wb') as fp:
        fp.write(yaml)
    import google.appengine.tools.appengine_rpc
    import google.appengine.tools.appcfg
    google.appengine.tools.appengine_rpc.HttpRpcServer.DEFAULT_COOKIE_FILE_PATH = './.appcfg_cookies'
    google.appengine.tools.appcfg.main(['appcfg', 'rollback', dirname])
    google.appengine.tools.appcfg.main(['appcfg', 'update', dirname])

def main():
    appids = raw_input('APPID:')
    if not re.match(r'[0-9a-zA-Z\-|]+', appids):
        print('appid Wrong Format, please login http://appengine.google.com to view the correct appid!')
        sys.exit(-1)
    for appid in appids.split('|'):
        upload(os.environ.get('uploaddir', 'golang').strip(), appid)

if __name__ == '__main__':
   try:
       main()
   except KeyboardInterrupt:
       pass