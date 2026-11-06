# Security model

## Trust boundary

The machine is the trust boundary. In the default `server.access_mode: machine`, any process
that can reach the listener may read and change every secret, much like a role whose IAM policy
grants `secretsmanager:*`. There is no passphrase or unlock step, so the server can start
unattended.

Request signatures are **not verified** yet (`auth.mode: none`): the access key is only used to
read the region from the SigV4 scope. Therefore:

- bind the listeners to loopback when other hosts can reach the machine
  (`https_addr: "127.0.0.1:443"`);
- don't expose segredium to a network you don't fully trust.

## Owner mode

`server.access_mode: owner` (`SEGREDIUM_ACCESS_MODE=owner`) limits each secret to the Unix user
that created it, and to root.

- On Linux, the caller's UID is found when a loopback TCP connection is accepted, by matching the
  socket in `/proc/net/tcp` / `/proc/net/tcp6`. This is one read per connection, with no cache.
- `GetSecretValue`, `PutSecretValue`, `DescribeSecret`, `UpdateSecret`, `DeleteSecret` and
  `RestoreSecret` return `AccessDeniedException` to other users. `ListSecrets` silently leaves
  out their secrets.
- Callers whose UID can't be determined are denied: remote clients, non-Linux platforms, or
  connections through a proxy.
- The owner is recorded in both modes and persists. Secrets created while the UID was unknown are
  root-only in owner mode.

Owner mode protects users from each other on a shared machine. It does not protect against root,
or against anyone who can read the data directory and the key.

## Encryption at rest

With `storage.backend: file`:

- **Files:** each secret, with all its versions and metadata, is one file under `storage.path`
  (directory `0700`, files `0600`). Each file is named after the SHA-256 of region and ARN, so
  file names don't reveal secret names.
- **Encryption:** contents are encrypted with AES-256-GCM under a 32-byte master key, with a fresh
  random nonce per write. The file name is used as additional authenticated data, so a file can't
  be swapped in under another secret's name.
- **Master key:** it is generated from the OS CSPRNG on first start
  (`<path>/master.key`, `0600`). The server refuses to start if the key is readable by group or
  others.
- **Durable writes:**
  1. write a temporary file;
  2. `fsync` it;
  3. `rename` it into place;
  4. `fsync` the directory.

  A crash leaves either the old file or the new one. Leftover temporary files are ignored at
  startup.
- **Damaged files:** a corrupt or undecryptable file stops startup with an error. Secrets are
  never dropped silently.

Since the key lives on the same machine, the encryption protects backups, copied disks and stray
file reads. It does not protect against root on the running machine. To keep the key elsewhere,
point `storage.key_file` at another location, such as a separately mounted volume.

Secret values are never written to logs or included in validation error messages.

## Built-in CA

- **Root:** an ECDSA P-256 CA in `tls.ca_dir` (`ca.crt.pem`; `ca.key.pem`, mode `0600`). Distribute
  only the certificate.
- **Leaf certificates:** they are issued only for Secrets Manager endpoint hostnames
  (`secretsmanager[-fips].<region>.amazonaws.com`, `.api.aws`, and the China partition) and
  `localhost`. Other SNI names are refused, so the CA can't be used to impersonate other sites
  through segredium.
- **Lifetime:** leaves last 24 h and are renewed early. At most 64 are cached, in memory only.

Trusting the root lets anyone holding `ca.key.pem` impersonate any site to that client. Keep the
key root-only, and remove the CA from trust stores when you stop using segredium.
