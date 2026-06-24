---
name: crl-generator
description: Use when generating Certificate Revocation Lists (CRLs), listing revoked certificate serials, or assigning RFC 5280 revocation reason codes. Triggers on mentions of generate CRL, create revocation list, revoke certificate by serial, CRL signing, or revocation reason.
tools:
  - cert_generate_crl
  - cert_parse_crl
  - cert_verify_crl_signature
  - cert_check_revoked_by_crl
---

# CRL Generator

## Capabilities
- Generate CRLs signed by a CA certificate
- Support RFC 5280 revocation reason codes
- Parse and inspect existing CRL files
- Verify CRL signatures against CA certificates
- Check if a certificate is revoked in a CRL

## Usage

### CLI
```bash
# Generate a CRL with revoked serials
cert-skills generate-crl --ca-cert ca.pem --ca-key ca-key.pem --serials 123456,789012

# With revocation reasons
cert-skills generate-crl --ca-cert ca.pem --ca-key ca-key.pem --serials 123456 --reasons key-compromise

# Parse a CRL
cert-skills parse-crl crl.pem
```

### MCP
```
cert_generate_crl(ca_cert_path, ca_key_path, serial_numbers, reasons, ...)
cert_parse_crl(crl_path)
cert_verify_crl_signature(crl_path, ca_cert_path)
cert_check_revoked_by_crl(cert_path, crl_path)
```

## Revocation Reason Codes (RFC 5280)
| Code | Reason | Description |
|------|--------|-------------|
| 0 | unspecified | Default reason |
| 1 | key-compromise | Private key compromised |
| 2 | ca-compromise | CA was compromised |
| 3 | affiliation-changed | Subject changed affiliation |
| 4 | superseded | Certificate superseded |
| 5 | cessation-of-operation | CA ceased operations |
| 6 | certificate-hold | Certificate on hold |
| 9 | privilege-withdrawn | Privilege withdrawn |
| 10 | aa-compromise | AA compromised |

## AI Integration
Use this skill when managing certificate revocation, publishing CRLs, or checking revocation status via CRL instead of OCSP.
