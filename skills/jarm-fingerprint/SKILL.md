---
name: jarm-fingerprint
description: Use when generating JARM TLS server fingerprints for server identification, C2 infrastructure detection, and cyberspace mapping. Triggers on mentions of JARM, JARM fingerprint, JARM hash, C2 detection, or server fingerprinting.
tools:
  - cert_jarm
---

# Jarm Fingerprint

> **TL;DR:** Generate JARM TLS fingerprint for server identification and C2 detection

## Capabilities

- JARM fingerprint via 10 TLS Client Hello probes
- Server software identification
- C2 infrastructure detection
- Works with TLS 1.3 servers

## Usage

```
cert_jarm target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- JARM hash fingerprint
- Target domain and port

## Workflow

1. Run `cert_jarm` on target domain
2. Record JARM hash
3. Compare against known JARM databases (Cobalt Strike, Metasploit)
4. Combine with `cert_ja3` for comprehensive fingerprinting

## References

- [JARM probes](references/jarm-probes.md) - Read when explaining the 10-probe sequence, hash construction, or fingerprint interpretation.

## AI Integration

### CLI (For AI Agents)

```bash
cert-skills jarm example.com                    # Text output
cert-skills jarm example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.JARMScan("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Identify malicious infrastructure through JARM
- Detect Cobalt Strike, Metasploit, and other C2 frameworks
- Cluster servers with identical JARM hashes

## Limitations

- JARM requires 10 separate TLS connections
- CDN-fronted servers show CDN JARM, not origin

## Related Skills

- [[cert_ja3]] cert_ja3
- [[cert_scan_protocols]] cert_scan_protocols
- [[cert_scan_ciphers]] cert_scan_ciphers
