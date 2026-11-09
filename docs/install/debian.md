# Debian and Ubuntu

The `.deb` package works on any Debian-based system with systemd, on amd64 and arm64. It has no dependencies.

## Install

```sh
VERSION=0.1.0
BASE=https://github.com/nathabonfim59/segredium/releases/download/v$VERSION
ARCH=$(dpkg --print-architecture)        # amd64 or arm64

curl -fsSLO "$BASE/segredium_${VERSION}_${ARCH}.deb"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS

sudo apt install "./segredium_${VERSION}_${ARCH}.deb"
```

The leading `./` makes `apt` read a local file. `sudo dpkg -i` works as well.

## Start the service

```sh
sudo systemctl enable --now segredium
systemctl status segredium
```

`enable` starts the service at boot and `--now` starts it immediately. The first start creates the CA in `/var/lib/segredium/ca` and the master key in `/var/lib/segredium/data/master.key`.

Logs go to the journal as JSON lines:

```sh
sudo journalctl -u segredium -f
```

You should see a line like `"msg":"listening","addr":"[::]:443","tls":true`.

## Listen on loopback only

The default address is `:443`, which accepts connections from other machines. Segredium does not check request signatures yet, so most people should restrict it. Create a drop-in and set the address through the environment:

```sh
sudo systemctl edit segredium
```

Add these lines in the editor, save, and restart the service:

```ini
[Service]
Environment=SEGREDIUM_HTTPS_ADDR=127.0.0.1:443
```

```sh
sudo systemctl restart segredium
```

Editing `/etc/segredium/segredium.yaml` and setting `server.https_addr` does the same. See [Configuration](../configuration).

## Next

[Route the hostnames and trust the CA](../setup), then [run the first checks](./verify).
