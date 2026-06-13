---
name: distrusted-ca-checker
description: Detect certificates issued by known distrusted/compromised Certificate Authorities
tools:
  - cert_check_distrusted_ca
---

# Distrusted Ca Checker

> **TL;DR:** Detect certificates issued by known distrusted/compromised Certificate Authorities

## Capabilities

- DigiNotar (2011 CA compromise)
- WoSign/StartCom (mis-issuance)
- Symantec legacy (audit failures)
- CNNIC, TrustCor, DarkMatter detection
- 13 known distrusted CAs in database

## Usage

```
cert_check_distrusted_ca target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Whether chain contains distrusted CA
- Distrusted CA details (name, reason, date, severity)
- Chain position
- Fingerprint

## Workflow

1. Run `cert_check_distrusted_ca` on target
2. If distrusted CA found, review reason and severity
3. Check distrust date for timeline
4. Use `cert_scan_cert_security` for comprehensive scan

## Cyberspace Mapping Applications

- Detect infrastructure using untrusted certificates
- Find services still trusting compromised CAs
- Map CA trust relationships across organizations

## Limitations

- Database covers major public distrust events only
- Private/internal CAs are not evaluated

## Related Skills

- [[cert_verify_chain]] cert_verify_chain
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_policy]] cert_check_policy
