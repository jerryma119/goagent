#!/bin/bash
# Works on Unix-like system, such as OSX, Archlinux, Ubuntu, etc.
# This shell has no dependency.
# Usage:
#   ./proxy.sh
#   ./proxy.sh stop
#   ./proxy.sh restart
# The default argument is `start`.

# Get goagent path.
base_dir=$(dirname $0)

# Goagent absolute path.
goa_path=$base_dir/proxy.py

# For stopping the porcess.
pid_path=$base_dir/.pid

start() {
	# Execute with nohup.
	nohup python $goa_path > /dev/null 2>&1 &
	echo $! > $pid_path
	echo Started.
}

stop() {
	kill -9 `cat $pid_path`
	echo Stopped.
}

case $1 in
	'' | 'start' )
		start
		;;

	'stop' )
		stop
		;;

	'restart' )
		stop
		start
		;;
esac
