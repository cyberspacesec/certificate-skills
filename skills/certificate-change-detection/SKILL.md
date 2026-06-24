---
name: certificate-change-detection
description: Use when detecting certificate changes over time — renewal, key rotation, issuer change, or expiry. Triggers on mentions of certificate monitoring, cert change, cert rotation, certificate diff, or continuous monitoring.
tools:
  - cert_detect_change
---

# Certificate Change Detection

Use this skill when you need to compare a domain's current certificate state against a previous snapshot.

## Use Cases

- Monitor certificate renewal and rotation across production domains
- Detect unexpected certificate replacement during incident response
- Track issuer, validity, key, or fingerprint drift over time
- Build recurring cyberspace mapping snapshots for infrastructure change tracking

## Workflow

1. Run `cert_detect_change` against the target domain.
2. Save the first result as a baseline when no previous snapshot exists.
3. Compare later runs against the most recent baseline.
4. Treat key replacement as the highest-priority review item, then review issuer and validity changes.

## CLI

```bash
cert-skills detect-change example.com --save -o json
```

## References

- [Change states](references/change-states.md) - Read when classifying renewal, key rotation, issuer change, expiry, or no-change results.
