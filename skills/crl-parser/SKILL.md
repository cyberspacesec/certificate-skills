---
name: crl-parser
description: Use when parsing Certificate Revocation List (CRL) files, displaying revoked certificates, verifying CRL signatures, or checking whether a certificate appears in a CRL. Triggers on mentions of parse CRL, inspect revocation list, CRL signature, revoked serial, or check cert in CRL.
tools:
  - cert_parse_crl
  - cert_verify_crl_signature
  - cert_check_revoked_by_crl
---

# CRL Parser

## Capabilities
- Parse CRL files (PEM and DER formats)
- Display issuer, update times, and CRL number
- List all revoked certificates with serial numbers, dates, and reasons
- Verify CRL signatures against CA certificates
- Check if a specific certificate is revoked in a CRL

## Usage

### CLI
```bash
# Parse a CRL file
cert-skills parse-crl crl.pem

# JSON output
cert-skills parse-crl crl.pem -o json
```

### MCP
```
cert_parse_crl(crl_path)
cert_verify_crl_signature(crl_path, ca_cert_path)
cert_check_revoked_by_crl(cert_path, crl_path)
```

## AI Integration
Use this skill when analyzing CRL contents, verifying CRL authenticity, or checking certificate revocation status against a CRL.
