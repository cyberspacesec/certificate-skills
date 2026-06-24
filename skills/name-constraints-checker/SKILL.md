---
name: name-constraints-checker
description: Use when checking CA certificate Name Constraints and verifying leaf certificate names comply with parent CA constraints. Triggers on mentions of name constraints, trust boundary, CA namespace restriction, or name constraint violation.
tools:
  - cert_check_name_constraints
---

# Name Constraints Checker

> **TL;DR:** Check CA name constraints and detect trust boundary violations

## Capabilities

- CA constraint extraction (permitted/excluded DNS, IP, email)
- Leaf name compliance verification
- Trust boundary violation detection
- Full chain constraint walking

## Usage

```
cert_check_name_constraints target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Whether constraints exist
- Constrained CAs with details
- Violation list
- Compliance status

## Workflow

1. Run `cert_check_name_constraints` on target
2. If constraints exist, review constrained CAs
3. Check for violations
4. Violations indicate trust boundary breaches

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills check-name-constraints example.com                    # Text output
cert-skills check-name-constraints example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckNameConstraints("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Detect over-permissive CAs with no constraints
- Find trust boundary violations in corporate sub-CA deployments
- Map CA constraint policies

## Limitations

- Only checks constraints in the presented chain
- Some CAs use constraints not in the certificate extension

## Related Skills

- [[cert_check_key_usage]] cert_check_key_usage
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_verify_chain]] cert_verify_chain
