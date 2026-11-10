# Changelog

All notable changes to KeyGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [1.0.0] - 2026-11-10

### Added

- Local SSH inventory: private keys, public keys, certificates, `known_hosts`,
  `authorized_keys`, and SSH client configuration
- OpenSSH version, `ssh-agent` status, and local `sshd` status detection
- SHA256/MD5 key fingerprints, algorithm/bit-size parsing, encryption state,
  public/private key mismatch detection, and certificate expiry checks
- Ed25519, RSA, and ECDSA key generation with optional passphrase, comment,
  custom directory, `.pub` creation, permission hardening, and `ssh-add`
- Stable device fingerprint from Windows/registry identifiers, with component
  hashes, sensitive-value masking, and JSON export
- Security audit with severity levels, remediation guidance, and a 0–100 score
- Modern PySide6 UI with dark/light themes, search, filters, copy actions,
  toast notifications, and keyboard shortcuts
- Synthetic-data screenshot generator for documentation
- Unit and UI smoke tests
