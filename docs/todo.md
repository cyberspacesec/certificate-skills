# Certificate Security Toolkit Development Checklist

## 🎯 Development Goal
Build a comprehensive certificate security toolkit supporting certificate retrieval, analysis, generation, PKI management, CRL operations, and security testing.

## 📋 Development Task Checklist

### Phase 1: Infrastructure (Priority: 🔴 High) ✅

- [x] **1.1 Project Structure**
  - [x] Create `cmd/` directory and main program entry
  - [x] Design CLI interface (cobra library)
  - [x] Add configuration file support
  - [x] Create logging system

- [x] **1.2 Dependency Management**
  - [x] Add necessary Go dependencies
  - [x] Create Makefile build script
  - [x] Add version information management

### Phase 2: Core Certificate Functions (Priority: 🔴 High) ✅

- [x] **2.1 Certificate Retrieval**
  - [x] Retrieve certificates from URL
  - [x] Read certificates from file
  - [x] Certificate chain retrieval
  - [x] Timeout and retry mechanisms

- [x] **2.2 Certificate Parsing**
  - [x] Basic certificate info parsing (subject, issuer, validity, etc.)
  - [x] Extension info parsing (SAN, key usage, etc.)
  - [x] Certificate chain verification (x509.Verify real verification)
  - [x] Multiple certificate formats (PEM, DER, auto-detection)

- [x] **2.3 Certificate Info Output**
  - [x] Formatted text output
  - [x] JSON format output
  - [x] CSV format output (batch processing)

### Phase 3: Certificate Analysis (Priority: 🟡 Medium) ✅

- [x] **3.1 SSL/TLS Connection Analysis**
  - [x] SSL handshake analysis
  - [x] TLS protocol version detection (scan-protocols)
  - [x] Cipher suite enumeration and analysis (scan-ciphers)
  - [x] Certificate chain integrity check (x509.Verify)

- [x] **3.2 Certificate Security Checks**
  - [x] Certificate expiration check
  - [x] Weak key detection (RSA key length, EC curve parameters)
  - [x] Signature algorithm security check
  - [x] OCSP Stapling detection
  - [x] HSTS header detection
  - [x] Certificate Transparency log query

- [x] **3.3 Certificate Fingerprint Generation** ✅
  - [x] SHA-1 fingerprint
  - [x] SHA-256 fingerprint
  - [x] MD5 fingerprint
  - [x] Public key fingerprint (SSL Pinning)

### Phase 4: Certificate Generation (Priority: 🟡 Medium) ✅

- [x] **4.1 Self-Signed Certificate Generation**
  - [x] RSA key pair generation (2048/4096)
  - [x] ECDSA key pair generation (P-256/P-384/P-521)
  - [x] Ed25519 key pair generation
  - [x] Custom certificate subject info
  - [x] Certificate extensions (SAN, key usage, etc.)
  - [x] CSR generation (generate-csr)

- [x] **4.2 CA Certificate Management** ✅
  - [x] Root CA generation (--is-ca, includes CertSign+CRLSign key usage)
  - [x] Intermediate CA generation (generate-intermediate-ca)
  - [x] CA-signed terminal certificates (sign-cert)
  - [x] CRL generation (generate-crl)
  - [x] CRL parsing (parse-crl)
  - [x] CRL signature verification (cert_verify_crl_signature)
  - [x] CRL revocation status check (cert_check_revoked_by_crl)

### Phase 5: Security Testing Tools (Priority: 🟢 Low) ✅

⚠️ **Note**: The following features are for authorized security testing and research only.

- [x] **5.1 Certificate Cloning** ✅
  - [x] Copy target certificate subject info (clone-cert)
  - [x] Generate similar but different certificates (different keys and serials)
  - [x] Subject info modification (new-cn, new-org)
  - [x] Domain variant generation (domain-variants)
  - [x] CA-signed cloned certificates

- [x] **5.2 SSL Vulnerability Detection** ✅
  - [x] Heartbleed detection
  - [x] POODLE attack detection
  - [x] BEAST attack detection
  - [x] CRIME/BREACH attack detection
  - [x] ROBOT, FREAK, Logjam, Sweet32, DROWN, etc.

- [x] **5.3 Downgrade Attack Testing** ✅
  - [x] TLS version downgrade testing (scan-protocols)
  - [x] Cipher suite downgrade testing (scan-ciphers)

### Phase 6: System Integration (Priority: 🟡 Medium)

- [ ] **6.1 System Certificate Store**
  - [ ] Windows certificate store reading
  - [ ] macOS Keychain access
  - [ ] Linux system certificate directory scanning
  - [ ] Suspicious root certificate detection

- [x] **6.2 Batch Processing** ✅
  - [x] Batch domain certificate check (batch-analyze)
  - [x] Certificate expiration batch monitoring
  - [x] CSV format result export
  - [ ] Report generation (PDF/HTML)

### Phase 7: Polish and Optimization (Priority: 🟢 Low) ✅

- [x] **7.1 Testing and Documentation**
  - [x] Unit test coverage (30+ test files, all pkg packages covered)
  - [x] golangci-lint configuration and CI integration
  - [x] MCP tool documentation (51 tools)
  - [x] Usage examples and tutorials
  - [x] All Chinese comments translated to English
  - [x] All cert-hacker references updated to cert-skills
  - [x] Stale files removed (README_clean.md, PLUGIN_README.md, .claude-plugin/)

- [x] **7.2 Release Preparation**
  - [x] Cross-compilation support (GoReleaser)
  - [x] Docker containerization
  - [x] GitHub Actions CI/CD (with lint + coverage)
  - [x] Version release automation

## 🛠️ Tech Stack

- **Language**: Go 1.25+
- **CLI Framework**: cobra
- **Crypto Library**: crypto/x509, crypto/tls
- **MCP**: mark3labs/mcp-go
- **Network Library**: net/http
- **Testing Framework**: testing (with -short for offline tests)
- **Linting**: golangci-lint
- **Build Tool**: Make + GoReleaser

## 🚀 CLI Command Reference (48 commands)

| Command | Description | Example |
|---------|-------------|---------|
| `info` | Get certificate info | `cert-skills info google.com` |
| `download` | Download certificate chain | `cert-skills download google.com` |
| `parse` | Parse certificate file | `cert-skills parse cert.pem` |
| `generate` | Generate self-signed cert | `cert-skills generate --common-name localhost --is-ca` |
| `generate-csr` | Generate CSR | `cert-skills generate-csr --common-name example.com` |
| `generate-intermediate-ca` | Generate intermediate CA | `cert-skills generate-intermediate-ca --parent-cert root.pem --parent-key root-key.pem -n "Sub CA"` |
| `sign-cert` | CA-sign terminal cert | `cert-skills sign-cert --ca-cert ca.pem --ca-key ca-key.pem -n server.local` |
| `generate-crl` | Generate CRL | `cert-skills generate-crl --ca-cert ca.pem --ca-key ca-key.pem --serials 12345` |
| `parse-crl` | Parse CRL | `cert-skills parse-crl crl.pem` |
| `clone-cert` | Clone certificate | `cert-skills clone-cert --source cert.pem` |
| `domain-variants` | Domain variant certs | `cert-skills domain-variants --domain example.com` |
| `analyze` | Security analysis | `cert-skills analyze google.com` |
| `batch-analyze` | Batch security analysis (CSV) | `cert-skills batch-analyze -t google.com,github.com -o csv` |
| `fingerprint` | Generate fingerprints | `cert-skills fingerprint google.com` |
| `compare` | Compare two certificates | `cert-skills compare --target1 google.com --target2 github.com` |
| `validate` | Validate cert and key | `cert-skills validate --cert cert.pem --key key.pem` |
| `validate-fingerprint` | Validate fingerprint format | `cert-skills validate-fingerprint --fingerprint ... --hash-type sha256` |
| `scan-protocols` | Scan TLS versions | `cert-skills scan-protocols google.com` |
| `scan-ciphers` | Scan cipher suites | `cert-skills scan-ciphers google.com` |
| `jarm` | JARM fingerprint | `cert-skills jarm google.com` |
| `ja3` | JA3/JA3S fingerprint | `cert-skills ja3 google.com` |
| `scan-vulns` | TLS vulnerability scan | `cert-skills scan-vulns google.com` |
| `search-ct` | CT log search | `cert-skills search-ct google.com` |
| `ct-enumerate` | CT subdomain enumeration | `cert-skills ct-enumerate google.com` |
| `search-ct-fingerprint` | CT fingerprint search | `cert-skills search-ct-fingerprint <sha256>` |
| `check-revocation` | OCSP/CRL revocation check | `cert-skills check-revocation google.com` |
| `check-hsts` | HSTS detection | `cert-skills check-hsts google.com` |
| `check-pfs` | PFS support check | `cert-skills check-pfs google.com` |
| `detect-ev` | EV certificate detection | `cert-skills detect-ev google.com` |
| `verify-chain` | Certificate chain verification | `cert-skills verify-chain google.com` |
| `verify-hostname` | Hostname verification | `cert-skills verify-hostname google.com` |
| `check-session-resumption` | Session resumption check | `cert-skills check-session-resumption google.com` |
| `expiry-monitor` | Expiry monitoring (CSV) | `cert-skills expiry-monitor -t google.com,github.com -o csv` |
| `check-wildcard` | Wildcard cert analysis | `cert-skills check-wildcard example.com` |
| `get-trusted-domains` | Extract trusted domains | `cert-skills get-trusted-domains example.com` |
| `check-caa` | CAA record check | `cert-skills check-caa example.com` |
| `check-sct` | SCT compliance check | `cert-skills check-sct example.com` |
| `scan-cert-security` | 18 cert security checks | `cert-skills scan-cert-security example.com` |
| `check-distrusted-ca` | Distrusted CA detection | `cert-skills check-distrusted-ca example.com` |
| `check-ocsp-must-staple` | OCSP Must-Staple check | `cert-skills check-ocsp-must-staple example.com` |
| `check-key-usage` | Key usage compliance | `cert-skills check-key-usage example.com` |
| `check-serial-entropy` | Serial entropy analysis | `cert-skills check-serial-entropy example.com` |
| `check-policy` | Certificate policy analysis | `cert-skills check-policy example.com` |
| `check-name-constraints` | Name constraints check | `cert-skills check-name-constraints example.com` |
| `check-bundle` | Bundle completeness check | `cert-skills check-bundle example.com` |
| `detect-change` | Certificate change detection | `cert-skills detect-change google.com --save` |
| `match-fingerprints` | Fingerprint matching | `cert-skills match-fingerprints google.com` |
| `match-fingerprint-by-hash` | Match single fingerprint | `cert-skills match-fingerprint-by-hash --hash ... --type jarm` |

## 🔌 MCP Tool Reference (51 tools)

| Tool | Description |
|------|-------------|
| `cert_info` | Get domain certificate info |
| `cert_parse` | Parse local certificate file |
| `cert_analyze_security` | Comprehensive security analysis |
| `cert_download` | Download certificate chain |
| `cert_fingerprint_domain` | Domain certificate fingerprints |
| `cert_fingerprint_file` | File certificate fingerprints |
| `cert_generate` | Generate self-signed certificate |
| `cert_generate_csr` | Generate CSR |
| `cert_validate_files` | Validate cert-key pair matching |
| `cert_validate_fingerprint` | Validate fingerprint format |
| `cert_compare` | Compare two certificates |
| `cert_batch_analyze` | Batch security analysis |
| `cert_scan_protocols` | TLS protocol version scan |
| `cert_scan_ciphers` | Cipher suite scan |
| `cert_check_hsts` | HSTS detection |
| `cert_jarm` | JARM fingerprint |
| `cert_ja3` | JA3/JA3S fingerprint |
| `cert_scan_vulnerabilities` | TLS vulnerability scan |
| `cert_search_ct` | CT log search |
| `cert_check_revocation` | OCSP/CRL revocation check |
| `cert_check_pfs` | PFS support check |
| `cert_detect_ev` | EV certificate detection |
| `cert_verify_chain` | Certificate chain verification |
| `cert_check_session_resumption` | Session resumption check |
| `cert_expiry_monitor` | Expiry monitoring |
| `cert_check_wildcard` | Wildcard cert analysis |
| `cert_get_trusted_domains` | Extract trusted domains |
| `cert_check_caa` | CAA record check |
| `cert_check_sct` | SCT compliance check |
| `cert_verify_hostname` | Hostname verification |
| `cert_scan_cert_security` | 18 cert security checks |
| `cert_ct_enumerate` | CT subdomain enumeration |
| `cert_search_ct_fingerprint` | CT fingerprint search |
| `cert_check_distrusted_ca` | Distrusted CA detection |
| `cert_check_ocsp_must_staple` | OCSP Must-Staple check |
| `cert_check_key_usage` | Key usage compliance |
| `cert_check_serial_entropy` | Serial entropy analysis |
| `cert_check_policy` | Certificate policy analysis |
| `cert_check_name_constraints` | Name constraints check |
| `cert_check_bundle` | Bundle completeness check |
| `cert_sign_certificate` | CA-sign terminal certificate |
| `cert_generate_intermediate_ca` | Generate intermediate CA |
| `cert_generate_crl` | Generate CRL |
| `cert_parse_crl` | Parse CRL |
| `cert_verify_crl_signature` | Verify CRL signature |
| `cert_check_revoked_by_crl` | Check cert revocation by CRL |
| `cert_clone_certificate` | Clone certificate |
| `cert_generate_domain_variants` | Generate domain variant certs |
| `cert_detect_change` | Detect certificate changes |
| `cert_match_fingerprints` | Match TLS fingerprints |
| `cert_match_fingerprint_by_hash` | Match single fingerprint hash |

---

## 📊 Project Status (Updated: 2026-06-21)

### ✅ Completed Features
1. **Infrastructure**: Complete Go project structure, CLI (48 commands), MCP server (51 tools, stdio/SSE/Streamable HTTP)
2. **Certificate Retrieval**: Domain and file certificate retrieval, chain support, DER auto-detection
3. **Certificate Parsing**: Full certificate info parsing + KeySize + HTTP/2 detection + OCSP Stapling
4. **Certificate Fingerprints**: SHA1/SHA256/MD5/PublicKey SHA256 fingerprint generation
5. **Certificate Generation**: RSA/ECDSA/Ed25519 self-signed certs + CSR generation + CA certs (CertSign+CRLSign)
6. **PKI Management**: Intermediate CA generation + CA-signed terminal certs (server/client/both)
7. **CRL Management**: CRL generation + CRL parsing + CRL signature verification + CRL revocation check
8. **Certificate Cloning**: Clone certs (with subject modification) + domain variant generation (homoglyph/subdomain/tld/hyphenation/insertion)
9. **Certificate Validation**: Cert+key matching validation, fingerprint format validation
10. **Security Analysis**: Comprehensive security scoring (0-100), cert/TLS/expiration checks, OCSP/HSTS detection
11. **TLS Scanning**: Protocol version detection (TLS 1.0-1.3), cipher suite enumeration (secure/weak)
12. **Vulnerability Scanning**: 11 TLS vulnerability checks (Heartbleed/POODLE/ROBOT, etc.)
13. **Batch Processing**: Batch security analysis, certificate comparison (domain/file), CSV output
14. **Cyberspace Mapping**: CT log search + subdomain enumeration + fingerprint search, JARM/JA3 fingerprints, trusted domain extraction, certificate change detection
15. **Compliance Checks**: 18 cert security checks, 8 compliance checks (SCT/CAA/key usage/serial entropy/policy/name constraints/OCSP Must-Staple/distrusted CA)
16. **Output Formats**: Text/JSON/CSV output formats
17. **48 CLI Commands + 51 MCP Tools**: Complete toolset
18. **45 Skills**: AI Agent executable prompt definitions
19. **Unit Tests**: 30+ test files covering all pkg packages, offline tests with -short flag
20. **Code Quality**: golangci-lint configured, all Chinese comments translated to English, all cert-hacker references updated
21. **CI/CD**: GitHub Actions with lint + coverage reporting, GoReleaser for cross-platform builds

### 🎯 Next Phase Focus
1. **System Certificate Store**: Windows/Mac/Linux system cert scanning + suspicious root cert detection
2. **Report Generation**: PDF/HTML format export
3. **Integration Tests**: End-to-end test coverage
4. **Performance Benchmarks**: Benchmark tests

### 📈 Completion Assessment
- **Infrastructure**: 100% ✅
- **Core Functions**: 100% ✅
- **Analysis Functions**: 100% ✅
- **Generation Functions**: 100% ✅
- **PKI Management**: 100% ✅
- **CRL Management**: 100% ✅
- **Security Functions**: 100% ✅
- **Testing & Documentation**: 95% ✅
- **Release Preparation**: 100% ✅

**Overall Completion: ~97%**

---

> **Tip**: Mark items as ✅ when completed
