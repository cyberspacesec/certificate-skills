---
name: chain-verifier
description: Verify certificate chain validates to a trusted root
tools:
  - cert_verify_chain
---

# Chain Verifier

> **TL;DR:** Verify certificate chain validates to a trusted root

## Capabilities

- Full chain verification against system trust store
- Chain path display from leaf to root
- Intermediate certificate analysis
- Specific failure reason identification

## Usage

```
cert_verify_chain target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Chain validity status
- Chain length and paths
- Verification errors
- Certificate subjects at each level

## Workflow

1. Run `cert_verify_chain` on target
2. If invalid, use `cert_check_bundle` to diagnose
3. If valid, review the trust path
4. Check for distrusted CAs with `cert_check_distrusted_ca`

## Cyberspace Mapping Applications

- Identify servers with broken certificate chains
- Detect misconfigured TLS deployments
- Map certificate authority usage patterns

## Limitations

- Uses system trust store (varies by OS)
- Missing intermediates cause failure (see cert_check_bundle)

## Related Skills

- [[cert_check_bundle]] cert_check_bundle
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
- [[cert_analyze_security]] cert_analyze_security
