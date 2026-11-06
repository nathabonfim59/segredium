# Installation and client setup

## Build

segredium needs Go 1.27.3 or newer and has no cgo dependency.

```sh
make build        # CGO_ENABLED=0, stripped: bin/segredium
```

## Run

```sh
sudo ./bin/segredium serve                    # defaults
sudo ./bin/segredium serve -config /etc/segredium.yaml
```

Port 443 needs root or `CAP_NET_BIND_SERVICE`. The data and CA directories default to
`/var/lib/segredium/{data,ca}` and are created with owner-only permissions. Logs are JSON lines
on stderr. `SIGINT` and `SIGTERM` shut the server down gracefully.

A minimal systemd unit:

```ini
[Unit]
Description=segredium (AWS Secrets Manager compatible server)
After=network.target

[Service]
ExecStart=/usr/local/bin/segredium serve
Restart=on-failure
StateDirectory=segredium
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/segredium

[Install]
WantedBy=multi-user.target
```

Owner mode reads `/proc/net/tcp`, so don't set `ProcSubset=pid` or a private network namespace.

## Route the AWS hostnames

Add one hostname per region you use:

```
127.0.0.1 secretsmanager.us-east-1.amazonaws.com
127.0.0.1 secretsmanager.eu-west-1.amazonaws.com
```

The region is taken from the request's SigV4 credential scope, then from the `Host` header,
then from `server.default_region`. Each region keeps its own secrets, as in AWS.

FIPS and dual-stack hostnames (`secretsmanager-fips.<region>.amazonaws.com`,
`secretsmanager.<region>.api.aws`) work the same way if you add them to `/etc/hosts`.

## Trust the CA

The built-in CA signs short-lived (24 h) certificates on demand, only for Secrets Manager
hostnames and `localhost`. Export the root certificate (never the key):

```sh
sudo segredium ca export > segredium-ca.pem
segredium ca install-hint        # prints the commands below for your config
```

| Client | How to trust it |
|---|---|
| AWS CLI v2, boto3, all AWS SDKs | `AWS_CA_BUNDLE=/path/segredium-ca.pem` (or `ca_bundle` in `~/.aws/config`) |
| Go | `SSL_CERT_FILE=/path/segredium-ca.pem` or the system store |
| Node.js | `NODE_EXTRA_CA_CERTS=/path/segredium-ca.pem` |
| Java | `keytool -importcert -alias segredium -cacerts -file segredium-ca.pem` |
| Debian/Ubuntu system store | `cp segredium-ca.pem /usr/local/share/ca-certificates/segredium.crt && update-ca-certificates` |
| RHEL/Fedora system store | `cp segredium-ca.pem /etc/pki/ca-trust/source/anchors/ && update-ca-trust` |
| macOS | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain segredium-ca.pem` |

Clients that bundle their own trust store (such as botocore's certifi) ignore the system store, so
they still need `AWS_CA_BUNDLE`.

To use your own certificate instead, set `tls.mode: files` with `tls.cert_file` and
`tls.key_file`. The certificate must cover every hostname you route.

## Credentials

Any access key works, because signatures are not verified yet. Clients still need some credentials
to sign requests:

```sh
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local
```

## Without /etc/hosts

For clients that support endpoint overrides, a plain-HTTP listener can be enabled:

```sh
SEGREDIUM_HTTP_ADDR=127.0.0.1:4566 segredium serve
AWS_ENDPOINT_URL_SECRETS_MANAGER=http://127.0.0.1:4566 aws secretsmanager list-secrets
```

## Proxies

If `HTTPS_PROXY` is set, add the routed hostnames to `NO_PROXY` and `no_proxy`. Otherwise
requests go to the proxy, which resolves the real AWS endpoint.
