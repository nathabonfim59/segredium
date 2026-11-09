# First run and checks

These checks start from the server and move toward the client. When one fails, fix it before you run the next, because each depends on the one before.

## 1. The server is running

```sh
systemctl status segredium            # OpenRC: rc-service segredium status
sudo ss -ltnp 'sport = :443'
```

`ss` should list `segredium` as the process listening on port 443. If you restricted the address, the line shows `127.0.0.1:443`.

The binary and its operations:

```sh
segredium version
segredium operations
```

`operations` prints the API calls this build supports, one per line.

## 2. The CA exists

```sh
sudo ls -l /var/lib/segredium/ca
```

You should see `ca.crt.pem` and `ca.key.pem`. Only root can read the key.

```sh
sudo segredium ca export > segredium-ca.pem
openssl x509 -in segredium-ca.pem -noout -subject -dates
```

The subject is `CN = segredium local CA` unless you changed `tls.ca_common_name`, and the certificate is valid for ten years by default.

## 3. TLS works with the CA

This request bypasses `/etc/hosts` by resolving the name itself, so it tests the server and the certificate without touching your system:

```sh
curl --resolve secretsmanager.us-east-1.amazonaws.com:443:127.0.0.1 \
     --cacert segredium-ca.pem \
     -s -X POST https://secretsmanager.us-east-1.amazonaws.com/ \
     -H 'X-Amz-Target: secretsmanager.ListSecrets' \
     -H 'Content-Type: application/x-amz-json-1.1' \
     -d '{}'
```

A fresh install returns `{"SecretList":[]}`. Without `--cacert`, curl fails with `self-signed certificate in certificate chain`. That proves the server uses its own CA and not a certificate from somewhere else.

## 4. Route the hostname

Add a line to `/etc/hosts` for each region you use:

```sh
echo '127.0.0.1 secretsmanager.us-east-1.amazonaws.com' | sudo tee -a /etc/hosts
getent hosts secretsmanager.us-east-1.amazonaws.com
```

`getent` should print `127.0.0.1`. If it prints a public address, something overrides `/etc/hosts`. Check the `hosts:` line in `/etc/nsswitch.conf`, and check whether a local DNS cache or VPN client rewrites names.

## 5. An AWS client works

Set the credentials and the CA bundle, then use the CLI with no endpoint option:

```sh
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local
export AWS_DEFAULT_REGION=us-east-1
export AWS_CA_BUNDLE="$PWD/segredium-ca.pem"

aws secretsmanager create-secret --name hello --secret-string world
aws secretsmanager get-secret-value --secret-id hello --query SecretString --output text
aws secretsmanager delete-secret --secret-id hello --force-delete-without-recovery
```

The second command prints `world`. If the first one fails with `ResourceExistsException`, a secret named `hello` already exists, and you can pick another name.

To confirm the request reached segredium and not AWS, look at the log:

```sh
sudo journalctl -u segredium -n 5 --output cat
```

Each request produces a line such as `"msg":"request","op":"GetSecretValue","status":200`.

## 6. Data survives a restart

```sh
aws secretsmanager create-secret --name persist-check --secret-string kept
sudo systemctl restart segredium
aws secretsmanager get-secret-value --secret-id persist-check --query SecretString --output text
aws secretsmanager delete-secret --secret-id persist-check --force-delete-without-recovery
```

The `get-secret-value` after the restart prints `kept`.

## Check memory use

```sh
ps -o rss= -p "$(pgrep -x segredium)"
```

The number is in KiB. An idle server uses about 12000.

When something fails, go to [Troubleshooting](./troubleshooting).
