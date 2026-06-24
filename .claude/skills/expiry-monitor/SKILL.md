---
name: expiry-monitor
description: Use when monitoring certificate expiration across multiple targets with urgency classification (Expired, Critical ≤7d, Warning ≤30d, Healthy). Triggers on mentions of cert expiry, certificate expiration, expiring certificates, cert monitoring, or expiration alert.
allowed-tools: ["mcp__certificate-skills__cert_expiry_monitor"]
---

# expiry-monitor

## When to Use

- User wants to check if certificates are expiring soon
- User asks about certificate expiration dates
- User needs to monitor multiple domains for certificate renewal
- User wants expiration alerts or urgency classification

## When NOT to Use

- User wants info for a single domain (use certificate-info instead — faster)
- User wants security analysis (use certificate-analysis instead)
- User wants to check revocation status (use certificate-revocation instead)

## Instructions

1. Collect the list of target domains and/or certificate file paths
2. Run the MCP tool:
   `cert_expiry_monitor(targets=["domain1.com", "domain2.com", "/path/to/cert.pem"])`
3. Present the results sorted by urgency:
   - **Expired** → immediate action required
   - **Critical** (≤7 days) → renew today
   - **Warning** (≤30 days) → renew soon
   - **Healthy** (>30 days) → no action needed
4. For any Expired or Critical targets, provide the exact expiry date and days remaining
5. Suggest certificate-info for detailed analysis of problem certificates

**CLI equivalent:**
`cert-skills expiry-monitor -t "domain1.com,domain2.com" -o json`

**Supports mixed input:** domains, domain:port, and local certificate file paths

## Anti-Patterns

- Don't treat Warning as non-urgent — 30 days goes quickly with CA validation
- Don't check a single domain with expiry-monitor — use certificate-info instead
- Don't forget to include all important domains in the monitoring list
