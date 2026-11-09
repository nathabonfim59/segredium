---
layout: home
hero:
  name: segredium
  text: Local AWS Secrets Manager for dev and tests
  tagline: Self-hostable and fully local. Add a line to /etc/hosts, trust the CA, and your AWS CLI and SDKs talk to segredium instead of AWS.
  actions:
    - theme: brand
      text: Install
      link: /install/
    - theme: alt
      text: How clients connect
      link: /setup
    - theme: alt
      text: GitHub
      link: https://github.com/nathabonfim59/segredium
features:
  - title: Same API
    details: AWS JSON 1.1 with the member names, error types and messages from the AWS service model. Tested with AWS CLI v2, boto3 and aws-sdk-go-v2.
  - title: No AWS account
    details: Runs offline and costs nothing per secret. One static Go binary uses about 12 MB of memory.
  - title: Encrypted on disk
    details: Each secret is an AES-256-GCM file. That protects a copied disk or a backup, not the machine itself.
  - title: Packages for four formats
    details: deb, rpm and apk for amd64 and arm64, plus a static tarball. Services for systemd and OpenRC.
---

::: warning Built for development and tests
If you run segredium anywhere else, know these limits.

| Limit | What it means |
|---|---|
| Access | Any process on the machine that can reach the port can read every secret, and root always can. [Owner mode](./security#owner-mode) limits each secret to the Unix user who created it. It does not stop root. |
| Key | The master key sits next to the data. The encryption protects a copied disk or a backup, not software that already runs on the host. |
| Auth | Request signatures are not checked. Any credentials work. |
| Gaps | Rotation, replication, resource policies and tagging are missing, so anything that depends on them will not behave like AWS. See [API compatibility](./compatibility). |
:::
