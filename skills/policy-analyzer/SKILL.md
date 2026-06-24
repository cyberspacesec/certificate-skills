---
name: policy-analyzer
description: Use when analyzing certificate policy OIDs for DV/OV/EV classification and compliance checking. Triggers on mentions of certificate policy, DV OV EV, validation type, policy OID, or certificate classification.
tools:
  - cert_check_policy
  - cert_detect_ev
---

# Policy Analyzer

> **TL;DR:** Analyze certificate policy OIDs for DV/OV/EV classification and compliance

## Capabilities

- DV/OV/EV validation type determination
- Known OID database (DigiCert, Let's Encrypt, Sectigo, etc.)
- Unknown OID detection
- Missing Certificate Policies on public CA certs

## Usage

```
cert_check_policy target="example.com"
cert_detect_ev target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Validation type (DV/OV/EV/Unknown)
- Policy OID list with descriptions
- Compliance status
- Issues list

## Workflow

1. Run `cert_check_policy` on target
2. Review validation type
3. Check for unknown OIDs (private CA indicator)
4. Verify compliance (missing policies = BR violation)

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills check-policy example.com                    # Text output
cert-skills check-policy example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckPolicyAnalysis("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Classify certificate validation level across infrastructure
- Identify private/custom CAs through unknown OIDs
- Track DV/OV/EV adoption rates

## Limitations

- Policy OID database covers major CAs only
- Some CAs use custom OIDs not in database

## Related Skills

- [[cert_detect_ev]] cert_detect_ev
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
