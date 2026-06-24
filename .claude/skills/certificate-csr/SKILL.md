---
name: certificate-csr
description: Use when generating a Certificate Signing Request (CSR) for submitting to a Certificate Authority. Triggers on mentions of generate CSR, create signing request, CSR generation, or certificate request.
allowed-tools: ["mcp__certificate-skills__cert_generate_csr"]
---

# certificate-csr

## When to Use

- User needs a CSR to submit to a CA (Let's Encrypt, DigiCert, etc.)
- User wants to generate a new certificate signing request
- User asks about creating a CSR with specific key type or SANs
- User is setting up TLS and needs to request a certificate from a CA

## When NOT to Use

- User wants a self-signed certificate (use certificate-generator instead)
- User wants to validate an existing CSR (not supported — CSRs are for generation)
- User wants to parse an existing certificate (use certificate-parse instead)

## Instructions

1. Determine the user's requirements:
   - Common Name (CN) — required, the primary domain
   - Key type: rsa (default), ecdsa, ed25519
   - Key size: RSA 2048/4096, ECDSA P-256/P-384/P-521
   - DNS SANs: additional domain names to include
2. Run the MCP tool:
   `cert_generate_csr(common_name="example.com", key_type="ecdsa", dns_names=["www.example.com", "api.example.com"])`
3. Present the PEM-encoded CSR text to the user
4. Remind the user: the private key is NOT saved to disk — they must save it if needed
5. Guide the user to submit the CSR to their chosen CA

**CLI equivalent:**
`cert-skills generate-csr -n example.com -o json`

**Important:** The private key is generated but NOT saved to disk. Only the CSR is returned. Save the key separately if needed.

## Anti-Patterns

- Don't forget to remind the user that the private key is NOT saved
- Don't generate a CSR without SANs — modern CAs require them
- Don't share the CSR with untrusted parties — it contains public key information only, but still
