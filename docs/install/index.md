# Install

Installing segredium takes three steps. You install the server, point the AWS hostnames at it, and make your clients trust its certificate authority. This page covers the first step and helps you pick a method. [Route and trust](../setup) covers the other two.

::: warning Built for development and tests
Segredium is meant for development machines and test runs. Any local process can read the secrets it holds, and request signatures are not checked. Read [the limits](../security) before you use it anywhere else.
:::

## Requirements

- Linux on x86_64 (amd64) or aarch64 (arm64). The binary is static and needs no libraries.
- Root access. The server listens on port 443 and edits nothing outside its own directories, but you need root to bind that port and to change `/etc/hosts`.
- Port 443 free on the loopback interface. If something else uses it, see [Troubleshooting](./troubleshooting#address-already-in-use).
- About 12 MB of memory and a few MB of disk. Each secret is one small file under `/var/lib/segredium`.

There are no packages for macOS or Windows, and segredium is only tested on Linux. Owner mode needs Linux (see [Security](../security#owner-mode)).

## Pick a method

| You run | Use | Service manager |
|---|---|---|
| Debian, Ubuntu, Mint, Raspberry Pi OS | [the .deb package](./debian) | systemd |
| Fedora, RHEL, Rocky, Alma, openSUSE | [the .rpm package](./rpm) | systemd |
| Alpine | [the .apk package](./alpine) | OpenRC |
| Another distribution | [the static binary](./binary) | your choice |
| You want to change the code | [a source build](./source) | your choice |

## Find your architecture

```sh
uname -m
```

`x86_64` means amd64. `aarch64` means arm64. The file names below differ slightly per format, and each page shows both.

## Download and verify

Every release at [github.com/nathabonfim59/segredium/releases](https://github.com/nathabonfim59/segredium/releases) lists its packages and a `SHA256SUMS` file. The commands on each page use these variables:

```sh
VERSION=0.1.0
BASE=https://github.com/nathabonfim59/segredium/releases/download/v$VERSION
```

Download the package for your system, then download the checksum file and check it:

```sh
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
```

The command prints `OK` next to each file it found. It prints `FAILED` if a file differs from the release, and you should delete that file and download it again.

The packages are not signed. The checksums protect against a corrupted download. They do not protect against someone who can replace both files on the release page, so compare the checksum with the one in the release notes if that matters to you.

## What a package installs

| Path | Contents |
|---|---|
| `/usr/bin/segredium` | the server and its command line |
| `/etc/segredium/segredium.yaml` | configuration, mode 0600, every option commented out at its default |
| `/usr/lib/systemd/system/segredium.service` | systemd unit (deb and rpm) |
| `/etc/init.d/segredium` | OpenRC script (apk) |
| `/var/lib/segredium/` | data and CA, created with mode 0700 |
| `/usr/share/doc/segredium/` | license, README and these docs |

Installing does not start the service, does not edit `/etc/hosts` and does not add anything to a trust store. The install script prints the next steps and stops there.

## After the install

1. Start the service with the commands on your distribution's page.
2. [Route the AWS hostnames and trust the CA](../setup).
3. [Run the first checks](./verify).
