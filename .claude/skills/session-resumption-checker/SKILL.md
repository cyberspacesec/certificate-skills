---
name: session-resumption-checker
description: Use when checking TLS session resumption support (Session ID and Session Tickets per RFC 5077). Triggers on mentions of session resumption, session tickets, TLS session reuse, or session caching.
allowed-tools: ["mcp__certificate-hacker__cert_check_session_resumption"]
---

# session-resumption-checker

## When to Use

- User wants to check TLS session resumption support
- User asks about session IDs or session tickets
- User is troubleshooting TLS performance issues
- User needs to configure load balancers for session persistence
- User asks about RFC 5077 session tickets

## When NOT to Use

- User wants PFS check (use pfs-checker instead — related but different)
- User wants TLS protocol scan (use tls-scanner instead)
- User wants cipher analysis (use tls-scanner instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_session_resumption(target="DOMAIN")`
2. Report: Session ID resumption and Session Ticket support
3. If session tickets are supported, note the ticket lifetime hint
4. Explain the performance implications: session resumption avoids full handshake
5. For load balancer configuration: ensure session tickets are consistently configured across servers
6. Cross-reference with pfs-checker — session tickets with static keys can weaken PFS

**CLI equivalent:**
`cert-skills check-session-resumption DOMAIN -o json`

**Performance impact:** Session resumption reduces handshake latency from 2 RTT to 1 RTT (or 0 RTT with TLS 1.3).

## Anti-Patterns

- Don't assume session tickets are always good — they can weaken PFS if keys are static
- Don't confuse session resumption with PFS — they're independent features
- Don't ignore ticket lifetime — very long lifetimes may be a security concern
