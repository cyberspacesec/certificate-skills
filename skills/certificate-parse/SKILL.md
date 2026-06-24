---
name: certificate-parse
description: Use when parsing a local certificate file (PEM or DER format) to display detailed information including subject, issuer, validity, SANs, key usage, and fingerprints. Triggers on mentions of parse cert file, read PEM, inspect certificate file, or decode DER.
tools:
  - cert_parse
---

# Certificate Parse

> **TL;DR:** Parse local certificate files (PEM/DER) and display detailed information

## Capabilities

- PEM and DER format parsing
- Full certificate details extraction
- Chain parsing from PEM bundle
- Fingerprint generation

## Usage

```
cert_parse target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `file_path` | string (required) | Path to certificate file (.pem, .crt, .cer, .der) |

## Output

- Subject and issuer details
- Validity period
- SANs (DNS, IP)
- Key usage and extended key usage
- Fingerprints (SHA-256, SHA-1, MD5)

## Workflow

1. Download or obtain certificate file
2. Run `cert_parse` on the file
3. Review certificate details
4. Use `cert_fingerprint_file` for fingerprint extraction

## AI Integration

### CLI (For AI Agents)

```bash
cert-skills parse example.com                    # Text output
cert-skills parse example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.GetCertFromFile("cert.pem")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Batch parse certificates from CT log downloads
- Extract metadata from certificate collections
- Validate certificate files before deployment

## Limitations

- Local file access required
- Cannot parse password-protected PKCS#12 files

## Related Skills

- [[cert_info]] cert_info
- [[cert_fingerprint_file]] cert_fingerprint_file
- [[cert_download]] cert_download
