---
name: chain-verifier
description: Use when verifying that a certificate chain validates against the system trust store. Triggers on mentions of chain verification, trust chain, certificate trust, chain validation, or root CA verification.
allowed-tools: ["mcp__certificate-skills__cert_verify_chain"]
---

# chain-verifier

## When to Use

- User wants to verify the certificate chain is trusted
- User asks about chain of trust or root CA verification
- User sees 'untrusted certificate' errors
- User needs to check if a certificate chain is valid
- User is debugging TLS connection failures related to trust

## When NOT to Use

- User wants bundle completeness check (use bundle-checker instead)
- User wants full cert security scan (use cert-security-scanner instead)
- User wants hostname verification (use hostname-verifier instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_verify_chain(target="DOMAIN")`
2. Report: is the chain valid?
3. If invalid, show the specific verification error
4. Show the chain path from leaf to root
5. If untrusted, suggest:
   - bundle-checker to diagnose missing intermediates
   - distrusted-ca-checker to check for compromised CAs
6. If valid, confirm the trust anchor and chain length

**CLI equivalent:**
`cert-skills verify-chain DOMAIN -o json`

**Chain verification:** Validates that each certificate in the chain is signed by the next, and the root is in the system trust store.

## Anti-Patterns

- Don't assume chain verification failure means the certificate is bad — it may be a missing intermediate
- Don't confuse chain verification with hostname verification — they test different things
- Don't skip checking for distrusted CAs in the chain — use distrusted-ca-checker
