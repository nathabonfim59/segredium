# Fedora, RHEL and derivatives

The `.rpm` package works on Fedora, RHEL, Rocky Linux, AlmaLinux, CentOS Stream and openSUSE, on x86_64 and aarch64. It has no dependencies.

## Install

```sh
VERSION=0.1.0
BASE=https://github.com/nathabonfim59/segredium/releases/download/v$VERSION
ARCH=$(uname -m)                          # x86_64 or aarch64

curl -fsSLO "$BASE/segredium-${VERSION}-1.${ARCH}.rpm"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS

sudo dnf install "./segredium-${VERSION}-1.${ARCH}.rpm"
```

On systems without `dnf`, use `sudo rpm -i` with the same file. On openSUSE, use `sudo zypper --no-gpg-checks install ./segredium-...rpm`, because the package is not signed.

## Start the service

```sh
sudo systemctl enable --now segredium
systemctl status segredium
```

The first start creates the CA in `/var/lib/segredium/ca` and the master key in `/var/lib/segredium/data/master.key`. Read the log with:

```sh
sudo journalctl -u segredium -f
```

## Listen on loopback only

The default address is `:443`, which accepts connections from other machines. Segredium does not check request signatures yet, so most people should restrict it:

```sh
sudo systemctl edit segredium
```

```ini
[Service]
Environment=SEGREDIUM_HTTPS_ADDR=127.0.0.1:443
```

```sh
sudo systemctl restart segredium
```

## Firewall and SELinux

Clients reach segredium through the loopback interface, so `firewalld` needs no rule. If you leave the address at `:443` and want other machines to connect, open the port yourself with `firewall-cmd`.

The package ships no SELinux policy, and nothing in this documentation has been tested with SELinux in enforcing mode. If a denial shows up in `ausearch -m avc -ts recent`, please open an issue with the message.

## Next

[Route the hostnames and trust the CA](../setup), then [run the first checks](./verify).
