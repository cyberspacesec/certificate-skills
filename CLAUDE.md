# CLAUDE.md — AI Agent Integration Guide

This project provides **38 Skills** for AI agents to perform SSL/TLS certificate security analysis, cyberspace mapping, and PKI operations.

## Quick Integration

### Option 1: Skills-based (Recommended for most AI Agents)

AI agents can directly use cert-skills by:

1. **Install the binary**:
   ```bash
   # Auto-detect platform and install
   OS=$(uname -s | tr '[:upper:]' '[:lower:]') && ARCH=$(uname -m | sed 's/x86_64/x86_64/;s/aarch64/aarch64/;s/armv7l/arm/')
   curl -sL "https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.1_${OS}_${ARCH}.tar.gz" | tar xz
   sudo mv cert-skills /usr/local/bin/
   ```

2. **Or build from source**:
   ```bash
   git clone https://github.com/cyberspacesec/certificate-skills.git
   cd certificate-skills && go build -trimpath -ldflags "-s -w" -o cert-skills ./cmd/ && sudo mv cert-skills /usr/local/bin/
   ```

3. **Call CLI commands** — each Skill maps to one or more CLI commands. See [skills/](skills/) for full documentation.

### Option 2: MCP Server (For Claude Code)

```json
{
  "mcpServers": {
    "certificate-skills": {
      "command": "cert-skills-mcp",
      "args": []
    }
  }
}
```

### Option 3: Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.AnalyzeSecurity("example.com")
```

## Skill Categories

### Security Analysis (6 skills)
- `certificate-analysis` — Full security scoring (0-100)
- `cert-security-scanner` — 18 cert security checks (CERT-001 to CERT-018)
- `tls-vulnerability-scanner` — 11 TLS vulnerability scans
- `certificate-batch-analysis` — Multi-domain batch analysis
- `expiry-monitor` — Certificate expiration monitoring
- `distrusted-ca-checker` — Distrusted CA detection

### Certificate Operations (7 skills)
- `certificate-info` — Certificate and connection info
- `certificate-parse` — Parse local certificate files
- `certificate-download` — Download certificate chains
- `certificate-compare` — Compare two certificates
- `certificate-fingerprint` — Generate fingerprints (SHA-256/SHA-1/MD5/SPKI)
- `fingerprint-validator` — Validate fingerprint format
- `certificate-validate` — Validate cert-key pair matching

### PKI Operations (2 skills)
- `certificate-generator` — Generate self-signed certificates
- `certificate-csr` — Generate Certificate Signing Requests

### Cyberspace Mapping (8 skills)
- `certificate-transparency` — Search CT logs by domain
- `ct-subdomain-enumerator` — Enumerate subdomains via CT
- `ct-fingerprint-search` — Search CT logs by fingerprint
- `jarm-fingerprint` — JARM TLS fingerprint (C2 detection)
- `ja3-fingerprint` — JA3/JA3S TLS fingerprinting
- `trusted-domains-extractor` — Extract domains from certificate
- `hostname-verifier` — Hostname matching verification
- `ev-detector` — Extended Validation detection

### Protocol & Cipher Analysis (4 skills)
- `tls-scanner` — TLS protocol and cipher scanning
- `pfs-checker` — Perfect Forward Secrecy check
- `session-resumption-checker` — Session resumption check
- `wildcard-checker` — Wildcard certificate analysis

### Compliance Checks (8 skills)
- `ocsp-must-staple-checker` — OCSP Must-Staple (RFC 7633)
- `key-usage-checker` — Key usage compliance (RFC 5280)
- `serial-entropy-checker` — Serial number entropy
- `policy-analyzer` — DV/OV/EV classification
- `name-constraints-checker` — Name constraints check
- `bundle-checker` — Bundle completeness (AIA fetch)
- `sct-checker` — SCT compliance
- `caa-checker` — CAA record check

### Revocation & HSTS (2 skills)
- `certificate-revocation` — OCSP/CRL revocation check
- `hsts-checker` — HSTS status check

### Chain Verification (1 skill)
- `chain-verifier` — Certificate chain verification

## CLI Quick Reference

```
cert-skills analyze <domain>                     # Security score
cert-skills scan-cert-security <domain>          # 18 cert checks
cert-skills scan-vulns <domain>                  # 11 TLS vuln scans
cert-skills info <domain>                        # Certificate info
cert-skills search-ct <domain>                   # CT log search
cert-skills jarm <domain>                        # JARM fingerprint
cert-skills check-distrusted-ca <domain>         # Distrusted CA
cert-skills check-key-usage <domain>             # Key usage
cert-skills -o json <command> <domain>           # JSON output
```

## Output Format

All commands support `-o json` for machine-readable output:
```bash
cert-skills analyze example.com -o json
cert-skills scan-cert-security example.com -o json
```
