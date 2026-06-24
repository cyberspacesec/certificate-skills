---
name: certificate-download
description: Use when downloading SSL/TLS certificate chain from a remote domain and saving to PEM files. Triggers on mentions of download cert, save certificate, export SSL cert, or get certificate chain files.
tools:
  - cert_download
---

# Certificate Download

> **TL;DR:** Download SSL/TLS certificate chain from a remote domain and save to PEM files

## Capabilities

- Full certificate chain download
- Separate leaf and chain files
- Custom output directory
- PEM format output

## Usage

```
cert_download target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |
| `output_dir` | string | Output directory for saved files |

## Output

- Saved certificate PEM file paths
- Chain length
- Target domain

## Workflow

1. Run `cert_download` on target domain
2. Verify saved files exist
3. Use `cert_parse` to inspect downloaded certificate
4. Use `cert_fingerprint_file` on the saved file

## References

- [Download output](references/download-output.md) - Read when explaining saved PEM files, chain ordering, or downloaded artifact names.

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills download example.com                    # Text output
cert-skills download example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.DownloadCertsFromDomain("example.com", dir)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Collect certificates for offline analysis
- Build certificate databases for cyberspace mapping
- Archive certificates from discovered infrastructure

## Limitations

- Only downloads the chain the server presents
- Missing intermediates won't be fetched

## Related Skills

- [[cert_info]] cert_info
- [[cert_parse]] cert_parse
- [[cert_check_bundle]] cert_check_bundle
- [[cert_fingerprint_file]] cert_fingerprint_file
