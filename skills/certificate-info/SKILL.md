---
name: certificate-info
description: This skill should be used when the user asks to "check a certificate", "get certificate info", "view SSL certificate", "show TLS certificate details", "inspect certificate", "read certificate file", "parse certificate", "what certificate does this site use", or mentions certificate subject, issuer, validity period, SAN, DNS names, or certificate chain. Provides SSL/TLS certificate retrieval and parsing via the cert-hacker CLI.
version: 1.0.0
---

# Certificate Information

Retrieve and display detailed information about SSL/TLS certificates from domains or local files using `cert-hacker`.

## Prerequisites

The `cert-hacker` binary must be available. Auto-detect and build if missing:

```bash
# Check if binary exists
if [ ! -f "./bin/cert-hacker" ]; then
  echo "Building cert-hacker..."
  bash scripts/install.sh
fi
```

If Go is not installed, inform the user to install Go 1.23+ or download pre-built binaries.

## Operations

### From Domain

```bash
./bin/cert-hacker info <domain> [--output json]
```

- Default port: 443. Custom port: `example.com:8443`
- Batch: `./bin/cert-hacker info google.com baidu.com github.com`

### From File

```bash
./bin/cert-hacker parse <file-path> [--output json]
```

- Supported formats: `.pem`, `.crt`, `.cer`

### Output Decision

| User Request | Flag |
|-------------|------|
| Quick check | (no flag, text output) |
| Structured data, scripting, further processing | `--output json` |

## Presenting Results

When showing certificate info to the user, highlight:

1. **Identity**: Subject, Issuer (is it a trusted CA?)
2. **Validity**: NotBefore → NotAfter, days remaining
3. **Coverage**: DNS Names (SAN), does it cover all expected domains?
4. **Algorithms**: Signature and public key algorithms
5. **Key Usage**: What is this certificate authorized for?

### Text Output Example

```
SSL/TLS Connection Information:
===============================
TLS Version: TLS 1.3
Cipher Suite: TLS_AES_128_GCM_SHA256
Handshake Time: 224ms

Certificate Information:
========================
Subject: CN=*.google.com
Issuer: CN=WR2,O=Google Trust Services,C=US
Valid From: 2025-09-08
Valid To: 2025-12-01
DNS Names: *.google.com, *.youtube.com, google.com
```

## Decision Flow

1. User mentions a domain → `info <domain>`
2. User provides file path (`.pem`/`.crt`/`.cer`) → `parse <file>`
3. Multiple domains provided → batch `info domain1 domain2 ...`
4. User wants structured data → add `--output json`

## Additional Resources

- **`references/cli-reference.md`** — Complete CLI reference with all flags and JSON output format
