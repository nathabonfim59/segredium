# Alpine

The `.apk` package installs the binary and an OpenRC script. It works on x86_64 and aarch64 and has no dependencies.

## Install

```sh
VERSION=0.1.0
BASE=https://github.com/nathabonfim59/segredium/releases/download/v$VERSION
ARCH=$(uname -m)                          # x86_64 or aarch64

wget "$BASE/segredium_${VERSION}_${ARCH}.apk"
wget "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS 2>&1 | grep "segredium_${VERSION}_${ARCH}.apk"

apk add --allow-untrusted "./segredium_${VERSION}_${ARCH}.apk"
```

`--allow-untrusted` is required because the package is not signed with a key that `apk` knows. BusyBox `sha256sum` has no `--ignore-missing`, so the command above checks the whole file and filters the output to the line you care about. The line should end in `OK`.

## Start the service

OpenRC is not installed in minimal containers. On a full Alpine system it already is. If `rc-service` is missing, run `apk add openrc` first, or start the binary yourself with `segredium serve -config /etc/segredium/segredium.yaml`.

```sh
rc-update add segredium default
rc-service segredium start
rc-service segredium status
```

`rc-update` starts the service at boot and `rc-service` starts it now. The script writes the log to `/var/log/segredium.log`:

```sh
tail -f /var/log/segredium.log
```

## Listen on loopback only

The default address is `:443`, which accepts connections from other machines. Segredium does not check request signatures yet, so most people should restrict it. OpenRC reads environment variables from `/etc/conf.d/segredium`:

```sh
echo 'export SEGREDIUM_HTTPS_ADDR=127.0.0.1:443' | sudo tee /etc/conf.d/segredium
rc-service segredium restart
```

You can also set `server.https_addr` in `/etc/segredium/segredium.yaml`. See [Configuration](../configuration).

## Trust store on Alpine

Alpine uses `update-ca-certificates` like Debian. [Route and trust](../setup) shows the commands. If you only install `ca-certificates` for the system store, programs that bundle their own certificates, such as botocore, still need `AWS_CA_BUNDLE`.

## Next

[Route the hostnames and trust the CA](../setup), then [run the first checks](./verify).
