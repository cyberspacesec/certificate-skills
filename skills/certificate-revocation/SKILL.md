---
name: certificate-revocation
description: Use when checking certificate revocation status via OCSP (Online Certificate Status Protocol) and CRL (Certificate Revocation List). Triggers on mentions of cert revocation, OCSP check, CRL check, revoked certificate, or certificate revoked.
tools:
  - cert_check_revocation
---

# Certificate Revocation

> **TL;DR:** Check certificate revocation status via OCSP and CRL

## Capabilities

- OCSP (Online Certificate Status Protocol) checking
- CRL (Certificate Revocation List) verification
- Revocation reason identification
- Overall status determination (Good/Revoked/Unknown)

## Usage

```
cert_check_revocation target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- OCSP status (Good/Revoked/Unknown)
- CRL status
- Revocation reason if revoked
- OCSP responder URL
- CRL distribution points

## Workflow

1. Run `cert_check_revocation` on target
2. Check OCSP status first (real-time)
3. If Unknown, check CRL status
4. Review revocation reason if revoked

## References

- [Revocation methods](references/revocation-methods.md) - Read when comparing OCSP and CRL behavior or explaining soft-fail limitations.

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills check-revocation example.com                    # Text output
cert-skills check-revocation example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckRevocation("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Detect revoked certificates still deployed in the wild
- Track certificate revocation patterns
- Identify certificates revoked due to compromise

## Limitations

- OCSP may return Unknown for some certificates
- CRL files can be large
- Revocation checking is not 100% reliable (soft-fail problem)

## Related Skills

- [[cert_check_ocsp_must_staple]] cert_check_ocsp_must_staple
- [[cert_analyze_security]] cert_analyze_security
- [[cert_check_bundle]] cert_check_bundle
