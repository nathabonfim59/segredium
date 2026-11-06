# Configuration

`segredium serve -config FILE` (or `SEGREDIUM_CONFIG=FILE`) reads YAML. `SEGREDIUM_*`
environment variables are applied afterwards and take precedence. Without a file, the defaults
apply. The `ca` subcommands load the configuration the same way.

An empty environment variable counts as unset. To set a value to the empty string (for example,
to disable the HTTPS listener), set `<NAME>_EMPTY=1`, e.g. `SEGREDIUM_HTTPS_ADDR_EMPTY=1`.

```yaml
server:
  https_addr: ":443"            # TLS listener reached through /etc/hosts ("" disables)
  http_addr: ""                 # optional plain-HTTP listener for endpoint overrides
  account_id: "123456789012"    # 12 digits; used in every ARN
  default_region: us-east-1     # when neither SigV4 scope nor Host names a region
  log_level: info               # debug | info | warn | error
  access_mode: machine          # machine | owner (see security.md)

storage:
  backend: file                 # file | memory
  path: /var/lib/segredium/data
  key_file: ""                  # default: <path>/master.key
  purge_interval: 1h            # max time between sweeps for expired recovery windows

tls:
  mode: ca                      # ca (built-in CA) | files
  ca_dir: /var/lib/segredium/ca
  ca_common_name: segredium local CA
  ca_validity: 87600h           # root certificate lifetime
  cert_file: ""                 # tls.mode=files
  key_file: ""                  # tls.mode=files

auth:
  mode: none                    # signatures are accepted without verification
```

## Environment variables

| Variable | Key |
|---|---|
| `SEGREDIUM_CONFIG` | config file path |
| `SEGREDIUM_HTTPS_ADDR` | `server.https_addr` |
| `SEGREDIUM_HTTP_ADDR` | `server.http_addr` |
| `SEGREDIUM_ACCOUNT_ID` | `server.account_id` |
| `SEGREDIUM_DEFAULT_REGION` | `server.default_region` |
| `SEGREDIUM_LOG_LEVEL` | `server.log_level` |
| `SEGREDIUM_ACCESS_MODE` | `server.access_mode` |
| `SEGREDIUM_STORAGE_BACKEND` | `storage.backend` |
| `SEGREDIUM_STORAGE_PATH` | `storage.path` |
| `SEGREDIUM_STORAGE_KEY_FILE` | `storage.key_file` |
| `SEGREDIUM_STORAGE_PURGE_INTERVAL` | `storage.purge_interval` (Go duration, e.g. `15m`) |
| `SEGREDIUM_TLS_MODE` | `tls.mode` |
| `SEGREDIUM_TLS_CERT_FILE` | `tls.cert_file` |
| `SEGREDIUM_TLS_KEY_FILE` | `tls.key_file` |
| `SEGREDIUM_TLS_CA_DIR` | `tls.ca_dir` |
| `SEGREDIUM_TLS_CA_COMMON_NAME` | `tls.ca_common_name` |
| `SEGREDIUM_TLS_CA_VALIDITY` | `tls.ca_validity` |
| `SEGREDIUM_AUTH_MODE` | `auth.mode` |

Invalid values stop the server at startup with an error that names the key.

## Storage backends

- **`file`** (default): durable and encrypted. See [security.md](security.md#encryption-at-rest).
  Back up `storage.path` and the key file together. Without the key, the data cannot be read.
- **`memory`**: nothing is written to disk and every secret is lost on exit. This is useful for
  tests and CI.
