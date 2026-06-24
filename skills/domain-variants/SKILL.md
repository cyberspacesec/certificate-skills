---
name: domain-variants
description: Use when generating certificate test cases for domain variants such as homoglyphs, subdomains, TLD changes, hyphenation, or inserted characters for authorized phishing detection research. Triggers on mentions of domain variants, homoglyph cert, typosquatting certificate, lookalike domain, or phishing research.
tools:
  - cert_generate_domain_variants
---

# Domain Variant Generator

⚠️ **WARNING**: This tool is for authorized security research only.

## Capabilities
- Generate homoglyph variants (visual character substitution)
- Generate subdomain variants (common prefix additions)
- Generate TLD variants (different top-level domains)
- Generate hyphenation variants (hyphen insertion)
- Generate character insertion variants
- Optional CA signing for realistic test certificates
- Maximum 50 variants per request

## Usage

### CLI
```bash
# Generate all variant types
cert-skills domain-variants --domain example.com

# Specific variant types
cert-skills domain-variants --domain example.com --types homoglyph,tld

# With CA signing
cert-skills domain-variants --domain example.com --ca-cert ca.pem --ca-key ca-key.pem
```

### MCP
```
cert_generate_domain_variants(base_domain, variant_types, key_type, key_size, ...)
```

## Variant Types
| Type | Description | Example (base: example.com) |
|------|-------------|------------------------------|
| homoglyph | Visual character substitution | èxample.com, examplе.com |
| subdomain | Common prefix additions | www.example.com, mail.example.com |
| tld | Different TLDs | example.net, example.org, example.io |
| hyphenation | Hyphen insertion | ex-ample.com, exa-mple.com |
| insertion | Character insertion | sexample.com, examplee.com |

## AI Integration
Use this skill for phishing detection research, typosquatting analysis, brand protection monitoring, or certificate validation testing. Never use for creating actual phishing infrastructure.
