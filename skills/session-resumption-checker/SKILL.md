---
name: session-resumption-checker
description: Check TLS session resumption support (Session ID and Session Tickets)
tools:
  - cert_check_session_resumption
---

# Session Resumption Checker

> **TL;DR:** Check TLS session resumption support (Session ID and Session Tickets)

## Capabilities

- Session ID resumption check
- Session Ticket (RFC 5077) check
- TLS version reporting
- Ticket lifetime reporting

## Usage

```
cert_check_session_resumption target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Session ID resumption support
- Session ticket support
- TLS version
- Ticket lifetime hint

## Workflow

1. Run `cert_check_session_resumption` on target
2. Check session ID and ticket support
3. Review ticket lifetime
4. Configure load balancers appropriately

## Cyberspace Mapping Applications

- Assess TLS performance optimization across infrastructure
- Identify servers missing session resumption
- Compare support across service providers

## Limitations

- TLS 1.3 uses pre-shared keys instead of session tickets
- Results may vary based on server-side session cache state

## Related Skills

- [[cert_scan_protocols]] cert_scan_protocols
- [[cert_scan_ciphers]] cert_scan_ciphers
- [[cert_check_pfs]] cert_check_pfs
