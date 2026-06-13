# TLS Scanner Output Reference

## Protocol Scan JSON Output

```json
{
  "target": "example.com",
  "protocols": [
    {
      "version": "TLS 1.3",
      "supported": true
    },
    {
      "version": "TLS 1.2",
      "supported": true
    },
    {
      "version": "TLS 1.1",
      "supported": false
    },
    {
      "version": "TLS 1.0",
      "supported": false
    }
  ],
  "summary": {
    "supported_versions": ["TLS 1.3", "TLS 1.2"],
    "unsupported_versions": ["TLS 1.1", "TLS 1.0"],
    "minimum_version": "TLS 1.2",
    "maximum_version": "TLS 1.3",
    "is_secure": true
  }
}
```

## Cipher Scan JSON Output

```json
{
  "target": "example.com",
  "tls_version": "1.2",
  "cipher_suites": [
    {
      "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
      "supported": true,
      "secure": true
    },
    {
      "cipher_suite": "ECDHE-RSA-3DES-EDE-CBC-SHA",
      "supported": true,
      "secure": false
    },
    {
      "cipher_suite": "RC4-SHA",
      "supported": false,
      "secure": false
    }
  ],
  "summary": {
    "total_tested": 30,
    "supported_count": 2,
    "secure_count": 1,
    "weak_count": 1,
    "weak_suites": ["ECDHE-RSA-3DES-EDE-CBC-SHA"],
    "is_secure": false
  }
}
```

## TLS Version Codes

| Version | Hex Code | Integer |
|---------|----------|---------|
| SSL 3.0 | 0x0300 | 768 |
| TLS 1.0 | 0x0301 | 769 |
| TLS 1.1 | 0x0302 | 770 |
| TLS 1.2 | 0x0303 | 771 |
| TLS 1.3 | 0x0304 | 772 |

## Common Cipher Suite Names

### TLS 1.3 Cipher Suites

| Name | Security |
|------|----------|
| `TLS_AES_128_GCM_SHA256` | ✅ Secure |
| `TLS_AES_256_GCM_SHA384` | ✅ Secure |
| `TLS_CHACHA20_POLY1305_SHA256` | ✅ Secure |

### TLS 1.2 Cipher Suites (Common)

| Name | Security |
|------|----------|
| `ECDHE-RSA-AES128-GCM-SHA256` | ✅ Secure |
| `ECDHE-RSA-AES256-GCM-SHA384` | ✅ Secure |
| `ECDHE-ECDSA-AES128-GCM-SHA256` | ✅ Secure |
| `ECDHE-ECDSA-AES256-GCM-SHA384` | ✅ Secure |
| `ECDHE-RSA-CHACHA20-POLY1305` | ✅ Secure |
| `AES128-GCM-SHA256` | ✅ Secure (no forward secrecy) |
| `AES256-GCM-SHA384` | ✅ Secure (no forward secrecy) |
| `ECDHE-RSA-3DES-EDE-CBC-SHA` | ⚠️ Weak (3DES/Sweet32) |
| `RC4-SHA` | ❌ Broken (RC4) |
| `NULL-SHA` | ❌ Broken (no encryption) |
| `EXP-RC4-MD5` | ❌ Broken (export-grade) |

## Compliance Requirements

### PCI-DSS

- Must NOT support TLS 1.0 or TLS 1.1
- Must use strong cipher suites (no RC4, DES, 3DES, NULL, EXPORT)
- `scan-protocols` should show only TLS 1.2+ supported

### NIST SP 800-52 Rev2

- TLS 1.2 or 1.3 required
- TLS 1.0/1.1 only acceptable for legacy with risk assessment

### HIPAA

- Follow NIST guidelines
- TLS 1.2+ with strong ciphers required
