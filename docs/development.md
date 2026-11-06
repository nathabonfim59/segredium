# Development

## Commands

```sh
make check          # gofmt + go vet + go test -race ./...
make build          # bin/segredium
make packages       # dist/: tar.gz, deb, rpm, apk for amd64 and arm64 (nfpm; version from the latest git tag)
go test ./internal/ops/ -run TestCreateSecret
go run ./cmd/segredium serve -config dev.yaml
```

For a quick local server without root, use plain HTTP and in-memory storage:

```sh
SEGREDIUM_HTTPS_ADDR_EMPTY=1 SEGREDIUM_HTTP_ADDR=127.0.0.1:4566 \
SEGREDIUM_STORAGE_BACKEND=memory go run ./cmd/segredium serve
```

## Layout

| Path | Contents |
|---|---|
| `cmd/segredium` | `main` → `internal/cli` (subcommand registry: `serve`, `ca`, `operations`, `version`) |
| `internal/api` | HTTP and protocol shell, operation registry (`api.Register`), region detection |
| `internal/apierr` | AWS error types |
| `internal/awsjson` | epoch-seconds timestamps, strict JSON decoding |
| `internal/model` | the stored secret shape |
| `internal/store` | `Store` interface, `storetest` conformance suite, `memstore`, `filestore` |
| `internal/sm` | shared service logic: dependencies, ARNs, secret resolution, validation, access checks |
| `internal/versions` | staging-label moves and version pruning |
| `internal/ops` | one file per API operation (`<snake_op>.go` + test) |
| `internal/purge` | recovery-window purge worker |
| `internal/ca` | built-in CA and on-demand leaf certificates |
| `internal/peercred` | caller UID from `/proc/net/tcp` (owner mode) |
| `internal/config` | YAML + `SEGREDIUM_*` configuration, one file per section |
| `internal/app` | wiring: store, TLS, workers, listeners |
| `packaging/` | nfpm config, systemd unit, OpenRC script, install scripts |
| `e2e/` | end-to-end tests with real AWS clients |

## Adding an operation

1. Create `internal/ops/<snake_op>.go` with `func init() { api.Register("<Op>", handler) }`.
2. Copy the member names and shapes from botocore's `service-2.json`. Use `awsjson.Time` for
   timestamps and pointers with `omitempty` for optional output.
3. Return `*apierr.Error` with AWS's exception name and message text.
4. Take time from `d.Now()` and randomness from `d.Rand`, never `time.Now()` or `math/rand`.
5. Pass `r.Region` to every store call, and check `d.CanAccess` for owner mode.
6. Write table tests through `api.TestCall(d, region, op, input)` using
   `sm.NewTestDeps(memstore.New(), sm.NewFakeClock(...))`. Assert the status, the exact `__type`
   and the output shape.

Each store backend must pass `storetest.Run`.

## Resource budget

Keeping RAM and CPU use low is a requirement:

- standard library only, unless there is a strong reason;
- no background goroutines beyond the purge timer;
- bounded caches;
- listing goes through `store.ListMeta`, so secret values are never copied to list.

Report idle and post-test RSS when a change could affect them. The current baseline is about
12 MB.

## End-to-end tests

Run on a disposable Linux VM as root, with Go, AWS CLI v2, boto3, curl and
`update-ca-certificates`:

```sh
make e2e                       # full run
bash e2e/run.sh --health-only  # TLS, routing and CA commands only
```

`e2e/run.sh`:

1. builds and starts the server on :443;
2. temporarily adds hosts entries for `us-east-1` and `us-west-2` and a system trust anchor;
3. runs `e2e/clients.py` (AWS CLI v2 and boto3) and `e2e/sdkgo` (aws-sdk-go-v2, a separate
   module so SDK dependencies never enter the server binary);
4. restarts the server to check persistence and deletion;
5. checks owner mode with two temporary Unix users;
6. prints idle and post-test RSS.

It restores `/etc/hosts` and the trust store on exit, and keeps logs under
`~/.cache/segredium/e2e.*`.

## Releasing

1. Update `CHANGELOG.md` (add a `## X.Y.Z` section) and commit.
2. Tag and push: `git tag -a vX.Y.Z -m "segredium X.Y.Z" && git push origin vX.Y.Z`.
3. `.github/workflows/release.yml` runs `make check` and `make packages`, then creates the GitHub
   release with everything in `dist/` (packages, tarballs, `SHA256SUMS`) and the changelog section
   as notes. To do it by hand, run `make packages` and publish `dist/`.

## CI

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests, on the `ubuntu-26.04`
runner image: `make check`, `make packages` (uploaded as an artifact) and the end-to-end suite.
