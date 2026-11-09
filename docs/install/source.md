# Build from source

Build from source if you want to change the code or run a commit that has no release.

## Requirements

- Go 1.27.3 or newer. The version is in `go.mod`, and `go version` shows yours.
- `git` and `make`.
- For packages only, the `nfpm` command is optional. `make packages` runs it through `go run` when it is not installed, which downloads it once.

The server has one dependency, `gopkg.in/yaml.v3`. The end-to-end tests have their own module in `e2e/sdkgo`, so the AWS SDK never enters the server binary.

## Build

```sh
git clone https://github.com/nathabonfim59/segredium.git
cd segredium
git checkout v0.1.0        # optional: build a release instead of main
make build
```

The result is `bin/segredium`. The build is static, strips debug information, and sets the version from the latest git tag. On a commit after a tag, the tag is still used, so check the real state with `git describe`.

```sh
./bin/segredium version
sudo install -m 0755 bin/segredium /usr/local/bin/segredium
```

Then follow [Static binary](./binary#run-it-in-a-terminal) to run it. The unit file and sample configuration are in the `packaging/` directory of the clone.

## Build your own packages

```sh
make packages
```

This cross-compiles for amd64 and arm64 and writes everything to `dist/`: a tarball, a `.deb`, a `.rpm` and an `.apk` for each architecture, plus `SHA256SUMS`. The package version comes from the latest git tag. Set `VERSION=1.2.3` on the command line to override it, and `ARCHES=amd64` to build one architecture.

## Run the tests

```sh
make check
```

This runs `gofmt`, `go vet` and `go test -race ./...`. The end-to-end suite, `make e2e`, changes `/etc/hosts` and the system trust store, so run it only on a disposable machine. [Development](https://github.com/nathabonfim59/segredium/blob/main/docs/development.md) describes both.
