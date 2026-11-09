---
layout: home
hero:
  name: segredium
  text: AWS Secrets Manager on your own machine
  tagline: Add a line to /etc/hosts, trust the local CA, and your AWS CLI and SDKs talk to segredium instead of AWS. No endpoint overrides, no code changes.
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
  - title: Small
    details: One static Go binary. Idle memory is about 12 MB. There is one background worker, which purges secrets whose recovery window has ended.
  - title: Encrypted on disk
    details: Each secret is a separate AES-256-GCM file. The master key is created on first start and never leaves the machine.
  - title: Packages for four formats
    details: deb, rpm and apk for amd64 and arm64, plus a static tarball. Services for systemd and OpenRC.
---
