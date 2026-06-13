# Validation Details Reference

## Certificate/Key Pair Validation

### What Gets Checked

1. **PEM Format Validation**
   - Certificate file must contain a valid `-----BEGIN CERTIFICATE-----` block
   - Key file must contain a valid `-----BEGIN PRIVATE KEY-----` (PKCS#8) or `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1) block
   - Base64 content must be correctly decodable

2. **Key Pair Match**
   - The public key embedded in the certificate is compared against the public key derived from the private key
   - Supports RSA, ECDSA, and Ed25519 key types
   - Comparison is done mathematically (not string matching) for reliability

### Error Messages and Troubleshooting

| Error | Cause | Resolution |
|-------|-------|------------|
| `failed to decode certificate PEM` | Invalid or missing PEM block in cert file | Check file path and format |
| `failed to decode private key PEM` | Invalid or missing PEM block in key file | Check file path and format |
| `public key does not match private key` | Cert and key are from different key pairs | Ensure cert and key were generated together |
| `unsupported key type` | Key uses an algorithm not supported by the tool | Use RSA, ECDSA, or Ed25519 |

## Fingerprint Validation

### Validation Rules

1. **Hex Characters**: Only `0-9`, `a-f`, `A-F`, and `:` (colon separator) are allowed
2. **Length Check**: After removing colons, the hex string length must match the expected output size:

| Algorithm | Expected Hex Length | Expected Bytes |
|-----------|-------------------|----------------|
| MD5 | 32 characters | 16 bytes |
| SHA-1 | 40 characters | 20 bytes |
| SHA-256 | 64 characters | 32 bytes |

3. **Colon Format**: Colons are optional. If present, they should separate octet pairs (`ab:cd:ef`)

### Example Valid Fingerprints

**SHA-256** (64 hex chars):
```
2d8fa1b59a60f414ad1c294492c78baf3e5d6c1ae9g2b3c4d5e6f708192a3b4c
2d:8f:a1:b5:9a:60:f4:14:ad:1c:29:44:92:c7:8b:af:3e:5d:6c:1a:e9:g2:b3:c4:d5:e6:f7:08:19:2a:3b:4c
```

**SHA-1** (40 hex chars):
```
abcdef0123456789abcdef0123456789abcdef01
ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01
```

**MD5** (32 hex chars):
```
abcdef0123456789abcdef0123456789
ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89
```

### JSON Output

```json
{
  "fingerprint": "2d:8f:a1:b5:...",
  "hash_type": "sha256",
  "is_valid": true,
  "message": "Fingerprint is a valid sha256 hash"
}
```
