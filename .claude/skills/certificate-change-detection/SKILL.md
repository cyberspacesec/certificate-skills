---
name: certificate-change-detection
description: Use when detecting certificate changes over time — renewal, key rotation, issuer change, or expiry. Triggers on mentions of certificate monitoring, cert change, cert rotation, certificate diff, or continuous monitoring.
allowed-tools: ["mcp__certificate-skills__cert_detect_change"]
---

# certificate-change-detection

## When to Use

- User wants to monitor if a domain's certificate has changed
- User asks about certificate renewal, key rotation, or issuer changes
- User needs to detect certificate replacement (potential compromise indicator)
- User wants continuous monitoring for cyberspace mapping
- User asks to compare current cert state against a previous snapshot

## When NOT to Use

- User wants a one-time certificate analysis (use certificate-analysis instead)
- User wants to compare two specific certificates (use certificate-compare instead)
- User wants to check revocation status (use certificate-revocation instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_detect_change(target="DOMAIN")`
2. Review the result for changes:
   - **new**: First snapshot for this target (no previous data)
   - **renewed**: Certificate renewed with same key (normal renewal)
   - **replaced**: Certificate replaced with different key (potential concern)
   - **expired**: Certificate has expired
   - **unchanged**: No changes detected
3. For continuous monitoring, use `save=true` and `snapshot_dir` to persist snapshots:
   `cert_detect_change(target="DOMAIN", save=true, snapshot_dir="/path/to/snaps")`
4. On subsequent runs, the tool automatically loads the latest previous snapshot and compares

**CLI equivalent:**
`cert-skills detect-change DOMAIN --save -o json`

**For security monitoring:** Key rotation (replaced) is the highest-priority change type — it may indicate certificate compromise or infrastructure takeover.

## Anti-Patterns

- Don't assume "replaced" always means compromise — organizations regularly rotate keys
- Don't ignore "renewed" changes — even normal renewals should be logged for audit trails
- Don't rely on this alone for compromise detection — combine with revocation checking and CT log monitoring
