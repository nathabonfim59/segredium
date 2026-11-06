#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
cat <<'MSG'
segredium installed. Next steps:
  1. start it:  systemctl enable --now segredium   (OpenRC: rc-update add segredium && rc-service segredium start)
  2. route it:  echo '127.0.0.1 secretsmanager.us-east-1.amazonaws.com' >> /etc/hosts
  3. trust it:  segredium ca export > segredium-ca.pem   (then see: segredium ca install-hint)
MSG
