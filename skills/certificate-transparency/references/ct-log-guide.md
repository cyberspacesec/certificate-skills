# Certificate Transparency Log Guide

## CT Log Architecture

Certificate Transparency consists of three components:

1. **CT Logs** — Append-only, publicly-auditable ledgers of certificates
2. **CT Monitors** — Watch logs for suspicious certificates
3. **CT Auditors** — Verify log consistency and compliance

## How CT Search Works

This tool queries [crt.sh](https://crt.sh), a CT log aggregator operated by Sectigo (formerly Comodo CA).

### API Endpoint

```
GET https://crt.sh/?q=%25.<domain>&output=json
```

The `%25.` prefix searches for all certificates matching `*.<domain>` (wildcard subdomain match).

### Response Fields

| Field | Description |
|-------|-------------|
| `issuer_ca_id` | Identifier for the issuing CA |
| `issuer_name` | Distinguished Name of the issuer |
| `common_name` | Certificate Common Name (CN) |
| `name_value` | All SANs (newline-separated) |
| `not_before` | Certificate validity start |
| `not_after` | Certificate validity end |
| `serial_number` | Certificate serial number |
| `sha256` | SHA-256 fingerprint of the certificate |

## Advanced Search Patterns

### Exact Domain

```
crt.sh/?q=example.com
```

### Wildcard Subdomain

```
crt.sh/?q=%.example.com
```

### By Fingerprint

```
crt.sh/?q=<sha256-fingerprint>
```

### By Organization

```
crt.sh/?q=O=Example+Inc
```

## JSON Output Structure

```json
{
  "target": "example.com",
  "total_count": 47,
  "certificates": [
    {
      "common_name": "example.com",
      "name_value": "example.com\nwww.example.com",
      "issuer_name": "CN=R11,O=Let's Encrypt,C=US",
      "not_before": "2025-09-01",
      "not_after": "2025-12-01",
      "serial_number": "...",
      "fingerprint_sha256": "..."
    }
  ]
}
```

## Cyberspace Mapping Use Cases

### 1. Subdomain Enumeration

Extract all unique subdomains from `name_value` fields across all certificates. This often reveals:
- Development/staging environments
- Internal services accidentally exposed
- Forgotten subdomains with valid certificates

### 2. Infrastructure Grouping

Group certificates by:
- **Issuer** → identifies CDN/cloud provider (Cloudflare, AWS, GCP)
- **Wildcard pattern** → identifies service categories
- **Validity period** → identifies automation (Let's Encrypt = 90 days)

### 3. Change Detection

Periodic CT searches can detect:
- New subdomains being provisioned
- New certificates being issued (potential unauthorized issuance)
- Changes in certificate authority (security implications)

### 4. Attack Surface Reduction

Use CT search results to:
- Identify and revoke unnecessary certificates
- Clean up forgotten subdomains
- Enforce certificate policy compliance
