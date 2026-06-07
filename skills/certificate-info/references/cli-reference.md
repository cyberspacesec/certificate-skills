# CLI Reference: Certificate Info Commands

## `cert-hacker info`

### Synopsis

```bash
cert-hacker info [domain:port | file] [domain2] [domain3]... [--output json|text]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| target | Yes | Domain name (with optional `:port`), or certificate file path |
| additional targets | No | Additional domains or files for batch processing |

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output, -o` | `text` | Output format: `text` or `json` |

### Domain Format

- `google.com` — default port 443
- `google.com:8443` — custom port
- Batch: `google.com baidu.com github.com`

### File Detection

Auto-detected by extension:
- `.pem`, `.crt`, `.cer` → certificate file
- Everything else → domain

### JSON Output Structure

```json
{
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "handshake_time": "224.944667ms",
  "peer_certificates": {
    "certificates": [
      {
        "subject": "CN=*.google.com",
        "issuer": "CN=WR2,O=Google Trust Services,C=US",
        "serial_number": "...",
        "not_before": "2025-09-08T08:34:53Z",
        "not_after": "2025-12-01T08:34:52Z",
        "dns_names": ["*.google.com", "google.com"],
        "ip_addresses": [],
        "public_key_algorithm": "RSA",
        "signature_algorithm": "SHA256-RSA",
        "key_usage": ["Digital Signature", "Key Encipherment"],
        "ext_key_usage": ["Server Authentication"],
        "is_ca": false,
        "version": 3,
        "fingerprints": {
          "sha256": "2d:8f:a1:b5:...",
          "sha1": "ab:cd:ef:...",
          "md5": "12:34:56:...",
          "public_key_sha256": "f3:89:91:45:..."
        }
      }
    ],
    "chain_length": 3,
    "is_valid": true,
    "trust_anchor": "GTS Root R1"
  }
}
```

## `cert-hacker parse`

### Synopsis

```bash
cert-hacker parse <certificate-file> [--output json|text]
```

### Supported Formats

- PEM (Base64-encoded, `-----BEGIN CERTIFICATE-----`)
- DER (binary, auto-detected)

## Batch Processing Output

```json
[
  {
    "target": "google.com",
    "ssl_info": { ... },
    "error": null
  },
  {
    "target": "invalid.example",
    "ssl_info": null,
    "error": "failed to connect: connection refused"
  }
]
```
