---
name: distrusted-ca-checker
description: Use when detecting certificates issued by known distrusted or compromised Certificate Authorities (DigiNotar, WoSign, StartCom, Symantec legacy, CNNIC, TrustCor, DarkMatter). Triggers on mentions of distrusted CA, compromised CA, untrusted certificate authority, or CA distrust check.
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

## AI Integration

### CLI (For AI Agents)

```bash
cert-skills check-distrusted-ca example.com                    # Text output
cert-skills check-distrusted-ca example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckDistrustedCA("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

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
