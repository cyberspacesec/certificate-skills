---
name: certificate-analysis
description: This skill should be used when the user asks to "analyze SSL security", "check TLS security", "assess certificate security", "security score", "find SSL vulnerabilities", "check certificate expiry", "audit TLS configuration", "is this certificate secure", "rate my SSL", or mentions certificate security analysis, TLS hardening, cipher suite security, TLS best practices. Provides comprehensive SSL/TLS security analysis with 0-100 scoring via the cert-hacker CLI.
version: 1.0.0
---

# Certificate Security Analysis

Perform comprehensive security analysis of SSL/TLS connections with scoring and actionable recommendations using `cert-hacker`.

## Prerequisites

The `cert-hacker` binary must be available. Auto-detect and build if missing:

```bash
if [ ! -f "./bin/cert-hacker" ]; then
  bash scripts/install.sh
fi
```

## Operation

```bash
./bin/cert-hacker analyze <domain> [--output json]
```

- Default port: 443. Custom port: `example.com:8443`
- Use `--output json` for structured data

## Scoring System

Base score: 100. Deductions per issue found:

| Severity | Deduction | Icon |
|----------|-----------|------|
| Critical | -30 | 💀 |
| High | -20 | 🚨 |
| Medium | -10 | ⚠️ |
| Low | -5 | 🔸 |

### Score to Level

| Score | Level | Meaning |
|-------|-------|---------|
| 90-100 | Good | Follows best practices |
| 70-89 | Medium | Minor issues to address |
| 50-69 | High | Significant security concerns |
| 0-49 | Critical | Immediate remediation required |

## What Gets Checked

### Certificate Check

| Check | Severity | Trigger |
|-------|----------|---------|
| Certificate Expired | Critical | Past NotAfter date |
| Certificate Expiring Soon | High | ≤ 30 days until expiry |
| Weak Signature Algorithm | High | MD5 or SHA-1 |
| Self-Signed Certificate | Medium | Subject == Issuer |

### TLS Connection Check

| Check | Severity | Trigger |
|-------|----------|---------|
| Insecure TLS Version | High | TLS 1.0 or TLS 1.1 |
| Weak Cipher Suite | High | RC4, DES, 3DES, NULL, EXPORT |

### Expiration Status

| Status | Condition |
|--------|-----------|
| Expired | Past NotAfter |
| Critical | ≤ 7 days |
| Warning | ≤ 30 days |
| Good | > 30 days |

## Presenting Results

Always structure analysis results as:

1. **Overall score and level** — the big picture first
2. **Issues by severity** — Critical → High → Medium → Low
3. **Each issue**: what was found, why it matters, recommended fix
4. **Recommendations** — prioritized by impact

### Example Format

```
🔒 Security Analysis: google.com
Score: 85/100 — Good ✅

Issues:
  1. ⚠️ Self-Signed Certificate [Medium]
     The certificate is not signed by a trusted CA.
     Impact: Browsers show security warnings.
     Fix: Use a certificate from Let's Encrypt or a commercial CA.

Recommendations:
  1. Replace with a trusted CA certificate
  2. Continue monitoring expiration dates
```

## Common Recommendations

| Issue | Recommendation |
|-------|---------------|
| Expired/Expiring | Renew certificate immediately |
| Weak Signature | Upgrade to SHA-256 or higher |
| Self-Signed | Use trusted CA (Let's Encrypt, DigiCert) |
| Old TLS | Upgrade to TLS 1.2/1.3, disable older versions |
| Weak Cipher | Configure AES-GCM or ChaCha20-Poly1305 |

## Additional Resources

- **`references/scoring-system.md`** — Complete scoring methodology, all check criteria, and detailed TLS assessment tables
