# Security Scoring System Reference

## Scoring Methodology

Base score: 100 points. Deductions per discovered issue.

### Issue Severity and Deductions

| Severity | Deduction | Color | Icon |
|----------|-----------|-------|------|
| Critical | -30 | Red | 💀 |
| High | -20 | Orange | 🚨 |
| Medium | -10 | Yellow | ⚠️ |
| Low | -5 | Blue | 🔸 |

### Score to Level Mapping

| Range | Level | Action |
|-------|-------|--------|
| 90-100 | Good | Continue monitoring |
| 70-89 | Medium | Plan improvements |
| 50-69 | High | Prioritize fixes |
| 0-49 | Critical | Immediate action required |

## Certificate Checks (Detailed)

### Expiration Analysis

| Status | Days Until Expiry | Score Impact |
|--------|-------------------|--------------|
| Expired | < 0 | Critical (-30) |
| Critical | 0-7 | High (-20) |
| Warning | 8-30 | High (-20) |
| Good | > 30 | No deduction |

### Signature Algorithm Assessment

| Algorithm | Security | Score Impact |
|-----------|----------|--------------|
| SHA-256 with RSA | Secure | No deduction |
| SHA-384 with RSA | Secure | No deduction |
| ECDSA with SHA-256 | Secure | No deduction |
| SHA-1 with RSA | Weak | High (-20) |
| MD5 with RSA | Broken | High (-20) |

### Self-Signed Detection

Detected when `Subject == Issuer`. Impact: Medium (-10).

## TLS Checks (Detailed)

### TLS Version Assessment

| Version | Security | Score Impact |
|---------|----------|--------------|
| TLS 1.3 | Best | No deduction |
| TLS 1.2 | Secure | No deduction |
| TLS 1.1 | Insecure | High (-20) |
| TLS 1.0 | Insecure | High (-20) |
| SSL 3.0 | Broken | Critical (-30) |

### Cipher Suite Assessment

#### Secure (No Deduction)

- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- ECDHE-RSA-AES128-GCM-SHA256
- ECDHE-RSA-AES256-GCM-SHA384

#### Weak (High Deduction)

Any cipher containing: RC4, DES, 3DES, NULL, EXPORT

## Recommendation Logic

1. **Expired/Expiring** → "Renew immediately"
2. **Weak Signature** → "Upgrade to SHA-256+"
3. **Self-Signed** → "Use trusted CA"
4. **Old TLS** → "Upgrade to TLS 1.2/1.3, disable older versions"
5. **Weak Cipher** → "Configure AES-GCM or ChaCha20-Poly1305"
6. **No Issues** → "Continue monitoring expiration dates"
