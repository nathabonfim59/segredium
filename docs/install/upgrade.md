# Upgrade and remove

## Upgrade

Install the new package over the old one with the same command you used the first time. See the page for your distribution. The package manager replaces `/usr/bin/segredium` and leaves two things alone:

- `/etc/segredium/segredium.yaml`. The package marks it as a configuration file. If you changed it, your version stays. If the new release ships a different default and you never edited the file, the package manager may offer you the new one.
- `/var/lib/segredium`. Your secrets, the CA and the master key are never touched by an upgrade.

The running process is not restarted. Restart it to load the new binary:

```sh
sudo systemctl restart segredium     # OpenRC: rc-service segredium restart
segredium version
```

For a static binary, stop the service, run `sudo install -m 0755 segredium /usr/local/bin/segredium` with the new file, and start the service again.

Read the [changelog](https://github.com/nathabonfim59/segredium/blob/main/CHANGELOG.md) before you upgrade. It lists new operations and any change you have to act on.

### Back up before you upgrade

Stop the service so no write is in progress, then copy both directories. The data is unreadable without the master key, and the CA key is what keeps your clients' trust valid.

```sh
sudo systemctl stop segredium
sudo tar -czf segredium-backup.tar.gz -C /var/lib segredium
sudo systemctl start segredium
```

The archive holds the master key next to the data it encrypts. Keep it as private as the machine itself.

## Remove

Removing the package stops and disables the service, and deletes the binary and the unit file.

```sh
sudo apt remove segredium            # Debian, Ubuntu
sudo dnf remove segredium            # Fedora, RHEL
sudo apk del segredium               # Alpine
```

`apt remove` keeps `/etc/segredium/segredium.yaml`, and `apt purge segredium` deletes it. `dnf remove` and `apk del` handle a modified configuration file by their own rules, so check `/etc/segredium` afterward.

None of them delete `/var/lib/segredium`. That is on purpose, because the directory holds your secrets. To delete it:

```sh
sudo rm -rf /var/lib/segredium
```

This is permanent. The master key lives in that directory, so deleting it makes any copy of the data files unreadable.

## Undo the client changes

Removing the package does not undo what you did in [Route and trust](../setup). Until you undo it, your AWS clients still resolve the Secrets Manager hostnames to `127.0.0.1` and fail to connect.

1. Delete the `secretsmanager.*` lines you added to `/etc/hosts`.
2. Remove the CA from every trust store you added it to. On Debian and Ubuntu, that is `sudo rm /usr/local/share/ca-certificates/segredium.crt` followed by `sudo update-ca-certificates --fresh`. On Fedora, remove the file from `/etc/pki/ca-trust/source/anchors/` and run `sudo update-ca-trust`. On macOS, delete the certificate in Keychain Access.
3. Unset `AWS_CA_BUNDLE` and `SSL_CERT_FILE` in your shell profile, and delete any `ca_bundle` line in `~/.aws/config`.
4. Delete `segredium-ca.pem` and any Java trust store entry (`keytool -delete -alias segredium -cacerts`).

Leaving the CA trusted after the key is gone is harmless. Leaving it trusted while the key still exists on a machine you no longer control is not, so remove it.
