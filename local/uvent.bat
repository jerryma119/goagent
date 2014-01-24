@set GEVENT_LOOP=uvent.loop.UVLoop
@set GEVENT_RESOLVER=gevent.resolver_thread.Resolver
@set GOAGENT_LISTEN_VISIBLE=1
@start "GoAgent" "%~dp0python27.exe" "%~dp0..\local\proxy.py"
