---
name: certificate-analysis
description: Use when performing SSL/TLS security analysis on a domain, checking certificate security scoring (0-100), auditing TLS configuration, or identifying certificate vulnerabilities. Triggers on mentions of SSL audit, TLS security score, certificate analysis, security assessment, or cert security review.
allowed-tools: ["mcp__certificate-hacker__cert_analyze_security"]
---

# certificate-analysis

## When to Use

- User asks to analyze SSL/TLS security of a domain
- User wants a security score (0-100) for a website's certificate
- User mentions SSL audit, TLS assessment, or certificate security review
- User needs to identify certificate or TLS configuration issues
- User asks about overall certificate security posture

## When NOT to Use

- User wants only certificate info (use certificate-info instead)
- User needs specific vulnerability scanning (use tls-vulnerability-scanner instead)
- User asks about a single specific check (use the appropriate checker skill)
- Target is a local certificate file (use cert-security-scanner with file path)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_analyze_security(target="DOMAIN")`
2. Read the overall security score (0-100) and security level (Critical/High/Medium/Good)
3. If score is low, review the issues list sorted by severity
4. Present findings to the user with clear severity classification
5. For each Critical or High issue, provide the specific recommendation from the output
6. If the user wants deeper analysis on a specific issue, suggest the relevant specialized skill

**CLI equivalent:**
`cert-skills analyze DOMAIN -o json`

**Output interpretation:**
- Score 90-100: Good — minor issues only
- Score 70-89: Medium — some improvements needed
- Score 50-69: High — significant security concerns
- Score 0-49: Critical — immediate action required

## Anti-Patterns

- Don't run this on multiple domains in sequence; use certificate-batch-analysis instead
- Don't ignore Critical severity findings — always highlight them
- Don't confuse the security score with vulnerability scan results — they are different assessments
