---
name: certificate-generator
description: This skill should be used when the user asks to "generate a certificate", "create self-signed certificate", "make SSL certificate", "generate CA certificate", "create root CA", "generate test certificate", "create localhost certificate", "make HTTPS certificate for development", or mentions creating certificates for development, testing, local HTTPS, or internal use. Provides self-signed and CA certificate generation via the cert-hacker CLI.
version: 1.0.0
---

# Certificate Generator

Generate self-signed SSL/TLS certificates for development, testing, and internal use using `cert-hacker`.

## Prerequisites

The `cert-hacker` binary must be available. Auto-detect and build if missing:

```bash
if [ ! -f "./bin/cert-hacker" ]; then
  bash scripts/install.sh
fi
```

## Operation

```bash
./bin/cert-hacker generate --common-name <name> [options]
```

### Required Parameter

| Parameter | Description |
|-----------|-------------|
| `--common-name, -n` | Common Name (CN) for the certificate |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--organization` | (empty) | Organization name (O) |
| `--country` | (empty) | Country code, 2 letters (C) |
| `--province` | (empty) | Province or state (ST) |
| `--locality` | (empty) | City or locality (L) |
| `--dns-names` | (empty) | Comma-separated SAN DNS names |
| `--validity-days` | 365 | Certificate validity in days |
| `--key-size` | 2048 | RSA key size: 2048 or 4096 |
| `--is-ca` | false | Generate as CA certificate |
| `--output-cert` | `<cn>.pem` | Certificate output file path |
| `--output-key` | `<cn>-key.pem` | Private key output file path |

## Common Patterns

### Local Development

```bash
./bin/cert-hacker generate --common-name localhost
```

### Multi-Domain

```bash
./bin/cert-hacker generate \
  --common-name example.com \
  --dns-names "www.example.com,api.example.com"
```

### CA Root Certificate

```bash
./bin/cert-hacker generate \
  --common-name "My Root CA" \
  --is-ca --validity-days 3650 --key-size 4096
```

### Custom Output Paths

```bash
./bin/cert-hacker generate \
  --common-name myserver \
  --output-cert /etc/ssl/myserver.crt \
  --output-key /etc/ssl/myserver.key
```

## Post-Generation Steps

Always perform these steps after generating a certificate:

1. **Verify files exist** — check both `.pem` and `-key.pem`
2. **Check fingerprints**: `./bin/cert-hacker fingerprint <cert-file>`
3. **Parse and verify**: `./bin/cert-hacker parse <cert-file>`

## Security Warning

Always include when presenting generation results:

> ⚠️ **Self-signed certificates are for testing and development only.** Browsers and OS will show warnings. For production, use certificates from a trusted CA (Let's Encrypt, DigiCert, Cloudflare).

## Key Size Selection

| Size | Security | Speed | Use Case |
|------|----------|-------|----------|
| 2048 | Standard | Fast | General web servers |
| 4096 | High | Slower | CA certs, high-security |

## Validity Recommendations

| Use Case | Days |
|----------|------|
| Local development | 365 |
| Internal services | 365-730 |
| CA root certificate | 3650 (10 years) |
| Short-lived testing | 30-90 |

## Additional Resources

- **`references/generation-options.md`** — Complete parameter reference, output file formats, and certificate extensions
