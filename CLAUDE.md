# CLAUDE.md — AI Agent Integration Guide

This project provides **45 Skills** for AI agents to perform SSL/TLS certificate security analysis, cyberspace mapping, and PKI operations.

## Quick Integration

### Option 1: Skills-based (Recommended for AI Agents)

Copy the skills into your project's `.claude/skills/` directory:

```bash
# One-click install — copy all 45 skills into your project
cp -r .claude/skills/ /your/project/.claude/skills/

# Or install from GitHub
git clone https://github.com/cyberspacesec/certificate-skills.git
cp -r certificate-skills/.claude/skills/ /your/project/.claude/skills/
```

Each skill is an **executable prompt** that tells your AI agent when to trigger, how to use the tool, and what to avoid. Skills are automatically discovered by Claude Code.

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

**Best experience: Use both Option 1 + Option 2.** Skills provide the prompt intelligence; MCP provides the tool execution.

### Option 3: CLI (For Humans & AI Agents)

```bash
# Install the binary
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.1_linux_x86_64.tar.gz | tar xz && sudo mv cert-skills /usr/local/bin/

# Use any skill via CLI
cert-skills analyze example.com -o json
cert-skills scan-cert-security example.com -o json
cert-skills search-ct example.com -o json
cert-skills jarm suspicious-server.com -o json
cert-skills sign-cert --ca-cert ca.pem --ca-key ca-key.pem -n server.local
cert-skills generate-intermediate-ca --parent-cert root.pem --parent-key root-key.pem -n "Sub CA"
cert-skills generate-crl --ca-cert ca.pem --ca-key ca-key.pem --serials 12345
```

### Option 4: Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.AnalyzeSecurity("example.com")
signResult, err := pkg.SignCertificate(pkg.SignCertRequest{...})
crlResult, err := pkg.GenerateCRL(pkg.CRLGenerateRequest{...})
```

## Skill Categories

### Security Analysis (6 skills)
- `certificate-analysis` — Full security scoring (0-100)
- `cert-security-scanner` — 18 cert security checks (CERT-001 to CERT-018)
- `tls-vulnerability-scanner` — 11 TLS vulnerability scans
- `certificate-batch-analysis` — Multi-domain batch analysis (supports CSV output)
- `expiry-monitor` — Certificate expiration monitoring (supports CSV output)
- `distrusted-ca-checker` — Distrusted CA detection

### Certificate Operations (7 skills)
- `certificate-info` — Certificate and connection info
- `certificate-parse` — Parse local certificate files
- `certificate-download` — Download certificate chains
- `certificate-compare` — Compare two certificates
- `certificate-fingerprint` — Generate fingerprints (SHA-256/SHA-1/MD5/SPKI)
- `fingerprint-validator` — Validate fingerprint format
- `certificate-validate` — Validate cert-key pair matching

### PKI Operations (5 skills)
- `certificate-generator` — Generate self-signed certificates (with CertSign+CRLSign for CA certs)
- `certificate-csr` — Generate Certificate Signing Requests
- `ca-signer` — Sign terminal/leaf certificates using a CA (server/client/both)
- `intermediate-ca-generator` — Generate intermediate CA certificates (multi-tier PKI)
- `cert-cloner` — Clone certificates with new keys (authorized security testing only)

### CRL Operations (2 skills)
- `crl-generator` — Generate Certificate Revocation Lists (RFC 5280 reason codes)
- `crl-parser` — Parse CRLs, verify signatures, check revocation status

### Cyberspace Mapping (10 skills)
- `certificate-transparency` — Search CT logs by domain
- `ct-subdomain-enumerator` — Enumerate subdomains via CT
- `ct-fingerprint-search` — Search CT logs by fingerprint
- `jarm-fingerprint` — JARM TLS fingerprint (C2 detection)
- `ja3-fingerprint` — JA3/JA3S TLS fingerprinting
- `trusted-domains-extractor` — Extract domains from certificate
- `hostname-verifier` — Hostname matching verification
- `ev-detector` — Extended Validation detection
- `domain-variants` — Generate domain variant certificates (phishing detection research)
- `certificate-change-detection` — Detect certificate changes from previous snapshots (renewal, key rotation, issuer change)

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
# Analysis
cert-skills analyze <domain>                     # Security score
cert-skills scan-cert-security <domain>          # 18 cert checks
cert-skills scan-vulns <domain>                  # 11 TLS vuln scans
cert-skills info <domain>                        # Certificate info
cert-skills batch-analyze -t <domains> -o csv    # Batch analysis (CSV)

# PKI Management
cert-skills generate -n "Root CA" --is-ca        # Generate root CA
cert-skills generate-intermediate-ca --parent-cert root.pem --parent-key root-key.pem -n "Sub CA"  # Intermediate CA
cert-skills sign-cert --ca-cert ca.pem --ca-key ca-key.pem -n server.local  # Sign certificate

# CRL Management
cert-skills generate-crl --ca-cert ca.pem --ca-key ca-key.pem --serials 12345  # Generate CRL
cert-skills parse-crl crl.pem                    # Parse CRL

# Security Testing
cert-skills clone-cert --source cert.pem         # Clone certificate
cert-skills domain-variants --domain example.com # Domain variants

# Cyberspace Mapping
cert-skills search-ct <domain>                   # CT log search
cert-skills jarm <domain>                        # JARM fingerprint
cert-skills detect-change <domain> --save        # Certificate change detection
cert-skills check-distrusted-ca <domain>         # Distrusted CA
cert-skills check-key-usage <domain>             # Key usage

# Output formats
cert-skills -o json <command> <domain>           # JSON output
cert-skills -o csv <command> <domain>            # CSV output (batch commands)
```

## Output Format

All commands support `-o json` for machine-readable output, and batch commands support `-o csv`:
```bash
cert-skills analyze example.com -o json
cert-skills batch-analyze -t google.com,github.com -o csv
cert-skills expiry-monitor -t google.com,github.com -o csv
```

## PKI Workflow Example

Complete workflow for building a multi-tier PKI:
```bash
# 1. Generate root CA
cert-skills generate --common-name "My Root CA" --is-ca --validity-days 3650 --key-size 4096

# 2. Generate intermediate CA
cert-skills generate-intermediate-ca \
  --parent-cert My-Root-CA.pem --parent-key My-Root-CA-key.pem \
  --common-name "My Intermediate CA" --validity-days 1825

# 3. Sign server certificate
cert-skills sign-cert \
  --ca-cert My-Intermediate-CA.pem --ca-key My-Intermediate-CA-key.pem \
  --common-name app.example.com --dns-names app.example.com,api.example.com

# 4. Generate CRL to revoke a certificate
cert-skills generate-crl \
  --ca-cert My-Intermediate-CA.pem --ca-key My-Intermediate-CA-key.pem \
  --serials 123456 --reasons key-compromise

# 5. Verify the chain
cert-skills verify-chain app.example.com
```
