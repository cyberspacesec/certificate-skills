---
name: expiry-monitor
description: Monitor certificate expiration across multiple targets with urgency classification
tools:
  - cert_expiry_monitor
---

# Expiry Monitor

> **TL;DR:** Monitor certificate expiration across multiple targets with urgency classification

## Capabilities

- Multi-target monitoring (domains + files)
- Urgency: Expired/Critical(<=7d)/Warning(<=30d)/Healthy
- Mixed input support
- Batch processing

## Usage

```
cert_expiry_monitor target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `targets` | array (required) | List of domain names, domain:port, or certificate file paths |

## Output

- Per-target: expiry date, days remaining, status
- Summary: total count, per-status counts

## Workflow

1. Prepare list of targets
2. Run `cert_expiry_monitor` with all targets
3. Focus on Expired and Critical first
4. Use `cert_info` for detailed analysis

## Cyberspace Mapping Applications

- Track certificate lifecycle across infrastructure
- Identify expiring certificates proactively
- Alert on expired certificates in production

## Limitations

- Network required for domain targets
- Does not send notifications (polling only)

## Related Skills

- [[cert_info]] cert_info
- [[cert_analyze_security]] cert_analyze_security
- [[cert_check_revocation]] cert_check_revocation
