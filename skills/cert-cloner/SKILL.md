---
name: cert-cloner
description: Clone certificates by copying subject info and generating new keys. For authorized security testing only.
tools:
  - cert_clone_certificate
---

# Certificate Cloner

⚠️ **WARNING**: This tool is for authorized security testing and research only.

## Capabilities
- Clone a certificate with new key pair and serial number
- Copy subject information and extensions from source certificate
- Modify subject fields (CN, Organization) during cloning
- Optionally sign with a CA instead of self-signing
- Generate new fingerprints distinct from the original

## Usage

### CLI
```bash
# Basic clone (self-signed)
cert-skills clone-cert --source cert.pem

# Clone with modified CN
cert-skills clone-cert --source cert.pem --modify-subject --new-cn test.example.com

# Clone with CA signing
cert-skills clone-cert --source cert.pem --ca-cert ca.pem --ca-key ca-key.pem

# Clone with different key type
cert-skills clone-cert --source cert.pem --key-type ecdsa --key-size 384
```

### MCP
```
cert_clone_certificate(source_cert_path, key_type, key_size, modify_subject, new_common_name, ...)
```

## Security Notes
- Cloned certificates have DIFFERENT fingerprints
- Cloned certificates are NOT trusted by standard PKI
- Proper certificate validation will detect cloned certificates
- Always obtain proper authorization before testing

## AI Integration
Use this skill for authorized penetration testing, security research on certificate validation, or testing PKI implementations. Never use for impersonation or fraud.
