# Static binary

Use the tarball on a distribution without a package, or when you don't want files outside one directory. The binary is static, so it runs on any Linux kernel that Go supports. It needs no libraries.

The tarball holds three files: `segredium`, `LICENSE` and `README.md`. It has no service file and no configuration file. The server runs with its defaults and reads a configuration file only when you pass `-config`.

## Install

```sh
VERSION=0.1.0
BASE=https://github.com/nathabonfim59/segredium/releases/download/v$VERSION
case $(uname -m) in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; esac

curl -fsSLO "$BASE/segredium_${VERSION}_linux_${ARCH}.tar.gz"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS

tar -xzf "segredium_${VERSION}_linux_${ARCH}.tar.gz" segredium
sudo install -m 0755 segredium /usr/local/bin/segredium
segredium version
```

The last command prints `segredium 0.1.0`.

## Run it in a terminal

```sh
sudo segredium serve
```

The server stays in the foreground and logs JSON lines to standard error. Press Ctrl+C to stop it. The first start creates `/var/lib/segredium/ca` and `/var/lib/segredium/data`, both readable only by root.

To keep data somewhere else, set the paths before you start:

```sh
sudo env SEGREDIUM_STORAGE_PATH=/srv/segredium/data \
         SEGREDIUM_TLS_CA_DIR=/srv/segredium/ca \
         segredium serve
```

## Run it as a systemd service

Download the unit file from the same release tag and point it at the binary you installed:

```sh
sudo mkdir -p /etc/segredium
curl -fsSL "https://raw.githubusercontent.com/nathabonfim59/segredium/v$VERSION/packaging/segredium.service" \
  | sed 's|/usr/bin/segredium|/usr/local/bin/segredium|' \
  | sudo tee /etc/systemd/system/segredium.service >/dev/null
curl -fsSL "https://raw.githubusercontent.com/nathabonfim59/segredium/v$VERSION/packaging/segredium.yaml" \
  | sudo install -m 0600 /dev/stdin /etc/segredium/segredium.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now segredium
```

The unit passes `-config /etc/segredium/segredium.yaml`, so the file has to exist. The version in `$VERSION` must match a tag in the repository.

For OpenRC, copy `packaging/segredium.openrc` from the repository to `/etc/init.d/segredium` and run `chmod +x` on it.

## Next

[Route the hostnames and trust the CA](../setup), then [run the first checks](./verify).
