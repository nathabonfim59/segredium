# Troubleshooting

Start with the log. Under systemd, run `sudo journalctl -u segredium -n 50 --output cat`. Under OpenRC, run `tail -n 50 /var/log/segredium.log`. If you run the binary in a terminal, the log is its standard error. The log has one line per request, with the operation, the status and the duration. Segredium does not write secret values to it.

## Address already in use

The log shows `listen tcp :443: bind: address already in use`. Another program holds the port. Find it:

```sh
sudo ss -ltnp 'sport = :443'
```

Stop that program, or run segredium on another port. A client reaches AWS endpoints on 443 only, so a different port needs a plain-HTTP listener and an endpoint override instead. See [Without /etc/hosts](../setup#without-etc-hosts).

## Permission denied on port 443

The log shows `bind: permission denied`. A non-root process cannot bind a port below 1024. The packaged service runs as root. If you run the binary yourself, use `sudo`, or grant the capability:

```sh
sudo setcap cap_net_bind_service=+ep /usr/local/bin/segredium
```

## The server refuses to start

It stops with an error that names the cause, and it does not guess.

| Message mentions | Cause and fix |
|---|---|
| `must be a regular file accessible only to its owner (0600)` | The master key has loose permissions. Run `sudo chmod 600 /var/lib/segredium/data/master.key`. |
| `must contain exactly 32 bytes` | The master key file is truncated or was edited. Restore it from a backup. |
| `filestore: cannot load ...` or `decrypt secret` | A secret file is damaged, or the master key is not the one that wrote it. Restore both from a backup taken together. The server will not skip the file, because that would hide data loss. |
| `config:` and a key name | A value in `segredium.yaml` or an environment variable is invalid. The message names the key. |
| `tls.mode=ca` and a directory | The CA directory cannot be created or written. Check its parent and its owner. |

## Certificate errors

The client says it cannot verify the certificate. Typical wording:

- AWS CLI: `SSL validation failed ... certificate verify failed: unable to get local issuer certificate`
- boto3: `SSLError: ... CERTIFICATE_VERIFY_FAILED`
- Go: `x509: certificate signed by unknown authority`
- Node.js: `unable to verify the first certificate`

The client does not trust the CA. Each client finds its trust store differently, so a system-wide install does not cover all of them. Set the variable for your client:

| Client | Variable |
|---|---|
| AWS CLI, boto3, most AWS SDKs | `AWS_CA_BUNDLE` |
| Go | `SSL_CERT_FILE` |
| Node.js | `NODE_EXTRA_CA_CERTS` |

Java needs the certificate in its own trust store. [Route and trust](../setup#trust-the-ca) lists the commands. Check the variable is exported in the shell that runs the client, and that the path is absolute.

If the CA directory was recreated, the CA is a new one and every client needs the new certificate. Export it again with `segredium ca export`.

## The client reaches the real AWS

The error is `The security token included in the request is invalid` or `UnrecognizedClientException`, and the log of segredium shows no request. The hostname did not resolve to your machine. Check:

```sh
getent hosts secretsmanager.us-east-1.amazonaws.com
```

- No `127.0.0.1` in the answer means the `/etc/hosts` line is missing or has a typo. The line must name the exact region you use.
- A VPN or a DNS-over-HTTPS setting in the browser or runtime can bypass `/etc/hosts`.
- A proxy setting sends the request to the proxy, which resolves the real name. Add the hostnames to `NO_PROXY` and `no_proxy`.

Every region needs its own hosts entry. A client configured for `eu-west-1` ignores a line that names `us-east-1`.

## The client cannot connect

The error is `Could not connect to the endpoint URL` or `connection refused`. The name resolves to `127.0.0.1`, but nothing listens there.

- Check the service is running (step 1 of [First run and checks](./verify)).
- If you set `server.https_addr` to a different address, the hosts entry must point to that address. `/etc/hosts` holds addresses only, never ports, so the listener has to be on port 443.
- A container has its own loopback. Inside Docker, `127.0.0.1` is the container. Point the container's hosts entry at the host's address, and listen on that address instead of loopback.

## AccessDeniedException

This only happens in owner mode (`server.access_mode: owner`). A secret belongs to the Unix user whose process created it. Other users, except root, get `AccessDeniedException`, and the secret is missing from their `ListSecrets` output. Connections that segredium cannot trace to a local user are denied as well, which includes any connection through a proxy or from another machine. See [Owner mode](../security#owner-mode).

## UnknownOperationException

The client called an API that this release does not implement. `segredium operations` lists what is supported, and [API compatibility](../compatibility) lists what is missing. Terraform, for example, may call `GetResourcePolicy` on every refresh and fail on that.

## A secret I deleted still blocks the name

`DeleteSecret` without `ForceDeleteWithoutRecovery` schedules deletion, as AWS does. The name stays reserved until the recovery window ends, which is 30 days unless you chose 7 to 30. Restore it with `aws secretsmanager restore-secret`, or delete it for good:

```sh
aws secretsmanager delete-secret --secret-id NAME --force-delete-without-recovery
```

## Still stuck

Open an issue at [github.com/nathabonfim59/segredium/issues](https://github.com/nathabonfim59/segredium/issues). Include the output of `segredium version`, your distribution, the failing command, and the log lines around the failure. Remove any secret values and access keys first, although segredium's own log never contains values.
