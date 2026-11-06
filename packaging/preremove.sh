#!/bin/sh
set -e
# Stop on removal, not on upgrade (deb: "remove", rpm: 0, apk: always).
case "$1" in
	remove|0|"")
		if [ -d /run/systemd/system ]; then
			systemctl disable --now segredium >/dev/null 2>&1 || true
		elif command -v rc-service >/dev/null 2>&1; then
			rc-service segredium stop >/dev/null 2>&1 || true
		fi
		;;
esac
