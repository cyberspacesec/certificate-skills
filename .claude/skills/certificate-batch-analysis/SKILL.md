---
name: certificate-batch-analysis
description: Use when analyzing SSL/TLS security for multiple domains at once, batch security scoring, or comparing security posture across organizations. Triggers on mentions of batch cert analysis, multi-domain security, bulk SSL check, or mass certificate assessment.
allowed-tools: ["mcp__certificate-hacker__cert_batch_analyze"]
---

# certificate-batch-analysis

## When to Use

- User provides a list of multiple domains to analyze
- User wants to compare security posture across domains
- User asks for bulk or batch SSL/TLS security analysis
- User needs summary statistics across many certificates

## When NOT to Use

- Single domain analysis (use certificate-analysis instead — it's faster)
- User needs detailed per-domain analysis (batch gives summary; follow up with certificate-analysis)
- Targets are local certificate files (not supported by batch analysis)

## Instructions

1. Collect the list of target domains from the user
2. Run the MCP tool with all targets:
   `cert_batch_analyze(targets=["domain1.com", "domain2.com", ...])`
3. Review the summary section first: counts per security level, average score
4. Identify domains with Critical or High severity
5. Present the summary to the user
6. For any low-scoring domains, suggest running certificate-analysis for deeper investigation

**CLI equivalent:**
`cert-skills batch-analyze -t "domain1.com,domain2.com" -o json`

**Output interpretation:**
- Summary shows count per level and average score
- Drill into individual domains with Critical/High scores
- Use certificate-analysis on problem domains for detailed findings

## Anti-Patterns

- Don't run batch analysis on a single domain — use certificate-analysis instead
- Don't skip the summary — always present aggregate findings first
- Don't run batch on more than 50 domains at once without warning about time
