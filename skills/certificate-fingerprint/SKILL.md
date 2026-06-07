---
name: certificate-fingerprint
description: This skill should be used when the user asks to "generate certificate fingerprint", "get SSL fingerprint", "show SHA-256 fingerprint", "get public key hash", "compare certificates", "verify certificate identity", "SSL pinning", "certificate pinning hash", or mentions SHA-1, SHA-256, MD5 hash of a certificate, or public key fingerprint. Provides certificate fingerprint generation and comparison via the cert-hacker CLI.
version: 1.0.0
---

# Certificate Fingerprint

Generate certificate fingerprints for identity verification and SSL pinning using `cert-hacker`.

## Prerequisites

The `cert-hacker` binary must be available. Auto-detect and build if missing:

```bash
if [ ! -f "./bin/cert-hacker" ]; then
  bash scripts/install.sh
fi
```

## Operations

### From Domain

```bash
./bin/cert-hacker fingerprint <domain> [--output json]
```

Connects to the domain and generates fingerprints for the leaf certificate.

### From File

```bash
./bin/cert-hacker fingerprint <file-path> [--output json]
```

Parses the local certificate file.

## Fingerprint Types

| Type | Algorithm | Use Case |
|------|-----------|----------|
| `sha256` | SHA-256 of DER-encoded certificate | Primary identification, most secure |
| `sha1` | SHA-1 of DER-encoded certificate | Legacy systems (deprecated) |
| `md5` | MD5 of DER-encoded certificate | Legacy comparison only (insecure) |
| `public_key_sha256` | SHA-256 of DER-encoded public key | **SSL Pinning** — survives cert renewal |

## SSL Pinning Guidance

When the user's use case involves SSL/TLS certificate pinning, always use `public_key_sha256`:

- Tied to the **public key**, not the full certificate
- Survives certificate renewal (same key pair = same fingerprint)
- Compatible with:
  - Android `Network Security Config`
  - iOS `Info.plist` (`NSAppTransportSecurity`)
  - HTTP `Public-Key-Pins` header
  - Native app certificate pinning libraries

## Presenting Results

Format fingerprint output clearly:

```
Certificate Fingerprints for google.com:
========================================
SHA-256              : 2d:8f:a1:b5:9a:60:f4:14:ad:1c:29:44:92:c7:8b:af:...
SHA-1                : ab:cd:ef:12:34:56:...
MD5                  : 12:34:56:78:...
PUBLIC_KEY_SHA256    : f3:89:91:45:af:58:8f:aa:e1:99:98:ef:47:6c:76:43:...
```

- Highlight `public_key_sha256` when SSL pinning is mentioned
- Warn that `md5` and `sha1` are deprecated for security purposes
- Use `--output json` for programmatic consumption
