# Changelog

## 0.1.0

First public release.

- AWS Secrets Manager API (AWS JSON 1.1): `CreateSecret`, `GetSecretValue`, `PutSecretValue`,
  `DescribeSecret`, `ListSecrets`, `UpdateSecret`, `DeleteSecret`, `RestoreSecret`.
- Works through `/etc/hosts` with a built-in CA; tested with AWS CLI v2, boto3 and aws-sdk-go-v2.
- Encrypted (AES-256-GCM) per-secret file storage; optional per-Unix-user access (`owner` mode).
- Recovery windows with automatic purge.
- Packages: `.deb`, `.rpm`, `.apk` (amd64, arm64) and static tarballs; systemd and OpenRC services.
- Not yet: signature verification, tagging, rotation, replication, resource policies,
  `BatchGetSecretValue`, `ListSecretVersionIds`, `UpdateSecretVersionStage`, `GetRandomPassword`.
