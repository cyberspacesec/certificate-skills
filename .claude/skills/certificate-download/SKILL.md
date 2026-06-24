---
name: certificate-download
description: Use when downloading SSL/TLS certificate chain from a remote domain and saving to PEM files. Triggers on mentions of download cert, save certificate, export SSL cert, or get certificate chain files.
allowed-tools: ["mcp__certificate-skills__cert_download"]
---

# certificate-download

## When to Use

- User wants to download a domain's certificate chain as PEM files
- User needs to save certificate files locally for inspection or backup
- User asks to export SSL certificate from a website
- User needs the certificate chain files for configuration

## When NOT to Use

- User just wants to view certificate info (use certificate-info instead — no file download needed)
- User wants to parse a local file (use certificate-parse instead)
- User wants to compare certificates (use certificate-compare instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_download(target="DOMAIN")`
   Optionally specify output directory: `cert_download(target="DOMAIN", output_dir="/path/to/dir")`
2. Confirm the saved file paths to the user
3. Suggest next steps: use certificate-parse to inspect the downloaded file
4. Suggest certificate-fingerprint for fingerprint extraction from the saved file

**CLI equivalent:**
`cert-skills download DOMAIN -o json`

**Output:** Saves both full chain and leaf certificate as separate PEM files

## Anti-Patterns

- Don't download certificates you don't have authorization to analyze
- Don't forget to tell the user where the files were saved
- Don't skip verification — use certificate-parse on the downloaded file to confirm it's valid
