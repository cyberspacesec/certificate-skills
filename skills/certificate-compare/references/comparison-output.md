# Certificate Comparison Output Reference

## JSON Output Structure

```json
{
  "match": false,
  "match_details": {
    "sha256_match": true,
    "public_key_match": true,
    "subject_match": false,
    "issuer_match": true
  },
  "cert1_summary": {
    "subject": "CN=*.old.example.com",
    "issuer": "CN=R11,O=Let's Encrypt,C=US",
    "public_key_algorithm": "RSA",
    "key_size": 2048
  },
  "cert2_summary": {
    "subject": "CN=*.new.example.com",
    "issuer": "CN=R11,O=Let's Encrypt,C=US",
    "public_key_algorithm": "RSA",
    "key_size": 2048
  },
  "differences": [
    {
      "field": "Subject",
      "cert1_val": "CN=*.old.example.com",
      "cert2_val": "CN=*.new.example.com"
    },
    {
      "field": "Not After",
      "cert1_val": "2025-12-01 08:34:52 UTC",
      "cert2_val": "2026-03-15 12:00:00 UTC"
    }
  ]
}
```

## Match Logic

A certificate is considered a **match** when the SHA-256 fingerprints are identical. This means:

- Same subject, issuer, validity, extensions, and public key
- The certificates are byte-for-byte identical in their DER encoding

### Partial Match Scenarios

| Scenario | SHA-256 | Public Key | Subject | Interpretation |
|----------|---------|------------|---------|----------------|
| All match | ✅ | ✅ | ✅ | Identical certificates |
| Key matches, subject differs | ❌ | ✅ | ❌ | Same key, reissued cert (renewal) |
| Subject matches, key differs | ❌ | ❌ | ✅ | Same domain, new key pair (re-key) |
| All differ | ❌ | ❌ | ❌ | Completely different certificates |

## Certificate Rotation Verification Workflow

When verifying a certificate rotation:

1. **Compare old cert vs new cert** — check if the rotation happened
2. **If key matches** — same key pair was reused (common with automated renewal)
3. **If key differs** — new key pair generated (common with manual renewal)
4. **Verify the new cert** — use `cert-skills validate` to check cert/key pair
5. **Test the new cert** — use `cert-skills analyze` for security assessment
