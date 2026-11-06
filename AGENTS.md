# segredium — contributor and agent guide

segredium is a self-hosted server with complete AWS Secrets Manager API compatibility (AWS JSON
1.1 protocol). Pointing `secretsmanager.<region>.amazonaws.com` at it via /etc/hosts (and
trusting its CA) must make unmodified AWS CLIs/SDKs/tools work exactly as against AWS.
Human-oriented docs: README.md and docs/.

## Commands
- `make check`: gofmt check + go vet + `go test -race ./...`.
- Focused test: `go test ./internal/ops/ -run TestCreateSecret`.
- `make build`; `make packages` (deb/rpm/apk via nfpm); `make e2e` (disposable VM, as root).
- `go run ./cmd/segredium serve -config x.yaml`; `go run ./cmd/segredium operations`.

## Layout
- `cmd/segredium` main → `internal/cli` (subcommand registry).
- `internal/api` HTTP/protocol shell + op registry + Authenticator/TLSProvider interfaces.
- `internal/apierr` error types. `internal/awsjson` timestamps/decoding.
- `internal/model` stored secret shape. `internal/store` Store interface, `storetest`
  conformance suite, `memstore`, `filestore`.
- `internal/sm` Deps, ARNs, `Resolve` (name / full ARN / partial ARN), `Validator`, access checks.
- `internal/ops` one file per API operation (`<snake_op>.go` + `<snake_op>_test.go`), each with
  `func init() { api.Register("<Op>", handler) }`.
- `internal/app` wiring (`wire_*.go` register stores, TLS providers and workers).
- `internal/config` one file per section, each with defaults(), applyEnv(), validate().
- `packaging/` nfpm config, systemd unit, OpenRC script, install scripts.

## Contracts that must not bend
- Changes to the shared contracts (api, apierr, awsjson, model, store, sm) need care: every op
  and backend depends on them. Keep them small and backward compatible.
- Wire format: exact AWS member names and shapes from botocore
  `secretsmanager/2017-10-17/service-2.json`; timestamps via `awsjson.Time` (epoch seconds);
  optional output members omitted when unset (`omitempty` + pointers); blobs are []byte (base64).
  Follow AWS documentation, not other emulators.
- Errors: return `*apierr.Error`; use AWS's exact exception names and, where AWS has a known
  message text, AWS's text. Unknown secret → `apierr.ResourceNotFound(sm.MsgNotFound)`.
- Store semantics in internal/store/store.go; every backend passes `storetest.Run`.
- Time comes from `d.Now()` (fake clock in tests), randomness from `d.Rand`. Never time.Now()
  or math/rand in ops.
- Region partitions everything: always pass `r.Region` to the store/Resolve.
- Never log or echo secret values (use `SensitiveLength` for validation).

## Resource budget
Minimal RAM/CPU is a requirement: stdlib first (new deps need a strong reason), bounded caches,
no background goroutines beyond the purge worker, list via `store.ListMeta` (no value copies).

## Style
- Go 1.27, gofmt, no global mutable state outside registries.
- Small focused functions; comments explain AWS behavior being matched (cite the doc/model).

## Tests
- Every op: table tests through `api.TestCall(d, region, op, input)` asserting status, exact
  `__type` and the JSON output shape. Use `sm.NewTestDeps(memstore.New(), sm.NewFakeClock(...))`.
- Test helpers in the shared ops package are prefixed with the op name (avoid collisions).
- A bug fix comes with a test that fails without the fix.
- Tests must reach the code they claim to test.
