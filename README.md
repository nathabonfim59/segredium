# segredium

segredium is a small, self-hosted server that speaks the AWS Secrets Manager API. Point
`secretsmanager.<region>.amazonaws.com` at it in `/etc/hosts`, trust its CA, and unmodified AWS
tools (AWS CLI, boto3, the AWS SDKs) keep working without an endpoint override.

- **Drop-in:** the AWS JSON 1.1 protocol with AWS's member names, shapes, error types and messages.
  It is tested with AWS CLI v2, boto3 and aws-sdk-go-v2 against the real hostnames.
- **Small:** a single static Go binary with one dependency (`gopkg.in/yaml.v3`). Idle RSS is about
  12 MB, and there are no background goroutines except one purge timer.
- **Persistent:** every secret is stored as its own AES-256-GCM encrypted file, with a machine key
  that is generated automatically.
- **Local trust model:** the machine is the trust boundary, as with an IAM policy. An optional
  per-Unix-user mode limits each secret to the user who created it.

> [!WARNING]
> Request signatures are not verified yet (`auth.mode=none`). Run segredium on a trusted machine,
> listening on loopback only.

## Supported operations

`CreateSecret`, `GetSecretValue`, `PutSecretValue`, `DescribeSecret`, `ListSecrets`,
`UpdateSecret`, `DeleteSecret` and `RestoreSecret`, with:

- string and binary values;
- staging labels (`AWSCURRENT` / `AWSPREVIOUS` / custom) and token idempotency;
- ListSecrets filters, sorting and pagination;
- recovery windows with automatic purge.

Other operations return `UnknownOperationException`. See [docs/compatibility.md](docs/compatibility.md)
for details and the roadmap.

## Install

Download a package from the [releases page](../../releases): `.deb` (Debian, Ubuntu), `.rpm`
(Fedora, RHEL) or `.apk` (Alpine), for amd64 and arm64. Static `tar.gz` binaries are there too.

```sh
sudo dpkg -i segredium_<version>_amd64.deb              # Debian/Ubuntu
sudo rpm -i segredium-<version>-1.x86_64.rpm            # Fedora/RHEL
sudo apk add --allow-untrusted segredium_<version>_x86_64.apk   # Alpine
sudo systemctl enable --now segredium                   # Alpine/OpenRC: rc-update add segredium; rc-service segredium start
```

The package installs `/usr/bin/segredium`, a service unit (systemd or OpenRC) and
`/etc/segredium/segredium.yaml`. It doesn't touch `/etc/hosts` or trust stores; follow the steps
below. To build the packages yourself, run `make packages` (needs Go; fetches nfpm).

## Quickstart

Or build from source with Go 1.27.3 or newer:

```sh
make build                     # → bin/segredium
sudo ./bin/segredium serve     # HTTPS on :443, data in /var/lib/segredium  (installed package: use the service)
```

On first start the server creates a local CA in `/var/lib/segredium/ca` and a master key in
`/var/lib/segredium/data/master.key`. In another terminal, route the regions you use and trust the CA:

```sh
echo '127.0.0.1 secretsmanager.us-east-1.amazonaws.com secretsmanager.us-west-2.amazonaws.com' \
  | sudo tee -a /etc/hosts
sudo ./bin/segredium ca export > segredium-ca.pem
export AWS_CA_BUNDLE="$PWD/segredium-ca.pem"   # AWS CLI v2, boto3, AWS SDKs
export SSL_CERT_FILE="$PWD/segredium-ca.pem"   # Go's system pool
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_DEFAULT_REGION=us-east-1
```

Then use AWS as usual:

```sh
aws secretsmanager create-secret --name example --secret-string first
aws secretsmanager put-secret-value --secret-id example --secret-string second
aws secretsmanager get-secret-value --secret-id example --version-stage AWSPREVIOUS
aws secretsmanager list-secrets
aws secretsmanager delete-secret --secret-id example --recovery-window-in-days 7
aws secretsmanager restore-secret --secret-id example
```

```python
import boto3
print(boto3.client("secretsmanager").get_secret_value(SecretId="example")["SecretString"])
```

`segredium ca install-hint` prints how to trust the CA system-wide on Debian/Ubuntu,
RHEL/Fedora, macOS and Windows, and for Node.js and Java. If you use a proxy, add the service
hostnames to `NO_PROXY`.

## Documentation

- [Installation and client setup](docs/setup.md): building, running as a service, routing, and trusting the CA
- [Configuration](docs/configuration.md): every YAML key and `SEGREDIUM_*` variable
- [Security model](docs/security.md): trust boundary, encryption at rest, owner mode, CA
- [API compatibility](docs/compatibility.md): per-operation behavior and what is missing
- [Development](docs/development.md): layout, tests, end-to-end checks

## CLI

```
segredium serve [-config FILE]       run the server
segredium ca init|export|install-hint [-config FILE] [-dir DIR]
segredium operations                 list implemented API operations
segredium version
```

## License

[MIT](LICENSE)
