package mcpserver

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Tools returns all MCP tool definitions paired with their handlers.
func Tools() []server.ServerTool {
	return []server.ServerTool{
		{Tool: CertInfoTool, Handler: HandleCertInfo},
		{Tool: CertParseTool, Handler: HandleCertParse},
		{Tool: CertAnalyzeTool, Handler: HandleCertAnalyze},
		{Tool: CertDownloadTool, Handler: HandleCertDownload},
		{Tool: CertFingerprintDomainTool, Handler: HandleCertFingerprintDomain},
		{Tool: CertFingerprintFileTool, Handler: HandleCertFingerprintFile},
		{Tool: CertGenerateTool, Handler: HandleCertGenerate},
		{Tool: CertGenerateCSRTool, Handler: HandleCertGenerateCSR},
		{Tool: CertValidateFilesTool, Handler: HandleCertValidateFiles},
		{Tool: CertValidateFingerprintTool, Handler: HandleCertValidateFingerprint},
		{Tool: CertCompareTool, Handler: HandleCertCompare},
		{Tool: CertBatchAnalyzeTool, Handler: HandleCertBatchAnalyze},
		{Tool: CertScanProtocolsTool, Handler: HandleCertScanProtocols},
		{Tool: CertScanCiphersTool, Handler: HandleCertScanCiphers},
		{Tool: CertCheckHSTSTool, Handler: HandleCertCheckHSTS},
		{Tool: JARMScanTool, Handler: HandleJARMScan},
		{Tool: JA3ScanTool, Handler: HandleJA3Scan},
		{Tool: VulnScanTool, Handler: HandleVulnScan},
		{Tool: CTSearchTool, Handler: HandleCTSearch},
		{Tool: CheckRevocationTool, Handler: HandleCheckRevocation},
		{Tool: CheckPFSTool, Handler: HandleCheckPFS},
		{Tool: DetectEVTool, Handler: HandleDetectEV},
		{Tool: VerifyCertChainTool, Handler: HandleVerifyCertChain},
		{Tool: CheckSessionResumptionTool, Handler: HandleCheckSessionResumption},
		{Tool: CertExpiryMonitorTool, Handler: HandleCertExpiryMonitor},
		{Tool: CheckWildcardTool, Handler: HandleCheckWildcard},
		{Tool: GetTrustedDomainsTool, Handler: HandleGetTrustedDomains},
		{Tool: CheckCAATool, Handler: HandleCheckCAA},
		{Tool: CheckSCTTool, Handler: HandleCheckSCT},
		{Tool: VerifyHostnameTool, Handler: HandleVerifyHostname},
		{Tool: ScanCertSecurityTool, Handler: HandleScanCertSecurity},
		{Tool: CTEnumerateSubdomainsTool, Handler: HandleCTEnumerateSubdomains},
		{Tool: SearchCTByFingerprintTool, Handler: HandleSearchCTByFingerprint},
		{Tool: CheckDistrustedCATool, Handler: HandleCheckDistrustedCA},
		{Tool: CheckOCSPMustStapleTool, Handler: HandleCheckOCSPMustStaple},
		{Tool: CheckKeyUsageComplianceTool, Handler: HandleCheckKeyUsageCompliance},
		{Tool: CheckSerialEntropyTool, Handler: HandleCheckSerialEntropy},
		{Tool: CheckPolicyAnalysisTool, Handler: HandleCheckPolicyAnalysis},
		{Tool: CheckNameConstraintsTool, Handler: HandleCheckNameConstraints},
		{Tool: CheckBundleCompletenessTool, Handler: HandleCheckBundleCompleteness},
	}
}

// --- Tool Definitions ---
// (Ordered alphabetically by tool name for readability.)

var CertAnalyzeTool = mcp.NewTool("cert_analyze_security",
	mcp.WithDescription(
		"Perform a comprehensive security analysis of an SSL/TLS connection. Returns a 0-100 security score "+
			"with severity level (Critical/High/Medium/Good), identified security issues with descriptions and impact, "+
			"certificate checks (expiration, self-signed, weak signature, wildcard), TLS checks (version and cipher suite security), "+
			"and actionable recommendations."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var CertBatchAnalyzeTool = mcp.NewTool("cert_batch_analyze",
	mcp.WithDescription(
		"Perform security analysis on multiple domains simultaneously. Returns individual security "+
			"scores and a summary with counts per security level and average score. Useful for "+
			"monitoring certificate security across multiple services."),
	mcp.WithArray("targets",
		mcp.Required(),
		mcp.Description("List of domain names or IP addresses to analyze (e.g., ['google.com', 'github.com', 'cloudflare.com:443'])"),
	),
)

var CertCompareTool = mcp.NewTool("cert_compare",
	mcp.WithDescription(
		"Compare two SSL/TLS certificates to determine if they are identical or different. "+
			"Compares fingerprints, subjects, issuers, validity dates, key algorithms, and more. "+
			"Can compare two domains, two files, or a domain vs a file."),
	mcp.WithString("target1",
		mcp.Required(),
		mcp.Description("First certificate target - a domain name (e.g., 'example.com') or file path (e.g., '/path/to/cert.pem')"),
	),
	mcp.WithString("target2",
		mcp.Required(),
		mcp.Description("Second certificate target - a domain name or file path"),
	),
)

var CertFingerprintDomainTool = mcp.NewTool("cert_fingerprint_domain",
	mcp.WithDescription(
		"Generate certificate fingerprints (SHA-256, SHA-1, MD5, public key SHA-256 for SSL pinning) "+
			"by connecting to a domain and retrieving its certificate."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com'). Default port is 443."),
	),
)

var CertFingerprintFileTool = mcp.NewTool("cert_fingerprint_file",
	mcp.WithDescription(
		"Generate certificate fingerprints (SHA-256, SHA-1, MD5, public key SHA-256 for SSL pinning) "+
			"from a local certificate file."),
	mcp.WithString("file_path",
		mcp.Required(),
		mcp.Description("Path to the certificate file (PEM or DER format)"),
	),
)

var CertGenerateTool = mcp.NewTool("cert_generate",
	mcp.WithDescription(
		"Generate a self-signed SSL/TLS certificate and private key, saving them as PEM files on disk. "+
			"Supports RSA 2048/4096-bit keys, ECDSA P-256/P-384/P-521 keys, Ed25519 keys, CA certificate generation, "+
			"and custom Subject Alternative Names. "+
			"WARNING: Self-signed certificates are for testing only, not for production use."),
	mcp.WithString("common_name",
		mcp.Description("Common Name (CN) for the certificate. Default: 'localhost'"),
	),
	mcp.WithString("organization",
		mcp.Description("Organization name (O field in the certificate subject)"),
	),
	mcp.WithString("country",
		mcp.Description("Two-letter country code (C field, e.g., 'US', 'CN')"),
	),
	mcp.WithString("province",
		mcp.Description("Province or state (ST field in the certificate subject)"),
	),
	mcp.WithString("locality",
		mcp.Description("City or locality (L field in the certificate subject)"),
	),
	mcp.WithArray("dns_names",
		mcp.Description("Subject Alternative Names - additional DNS names (e.g., ['www.example.com', 'api.example.com'])"),
	),
	mcp.WithArray("ip_addresses",
		mcp.Description("Subject Alternative Names - IP addresses as strings (e.g., ['192.168.1.1', '10.0.0.1'])"),
	),
	mcp.WithNumber("validity_days",
		mcp.Description("Certificate validity period in days. Default: 365. Use 3650 for CA certs."),
	),
	mcp.WithNumber("key_size",
		mcp.Description("Key size in bits. RSA: 2048 (default) or 4096. ECDSA: 256 (P-256), 384 (P-384), 521 (P-521). Ed25519: fixed 256."),
	),
	mcp.WithString("key_type",
		mcp.Description("Key algorithm type. Options: 'rsa' (default), 'ecdsa', 'ed25519'. For ECDSA, key_size selects curve: 256=P-256, 384=P-384, 521=P-521"),
	),
	mcp.WithBoolean("is_ca",
		mcp.Description("Set to true to generate a CA (Certificate Authority) certificate. Default: false"),
	),
	mcp.WithString("output_cert_path",
		mcp.Description("File path for the generated certificate. Default: '<common_name>.pem' in current directory"),
	),
	mcp.WithString("output_key_path",
		mcp.Description("File path for the generated private key. Default: '<common_name>-key.pem' in current directory"),
	),
)

var CertGenerateCSRTool = mcp.NewTool("cert_generate_csr",
	mcp.WithDescription(
		"Generate a Certificate Signing Request (CSR) in PEM format. Returns the CSR text content, "+
			"suitable for submitting to a Certificate Authority (e.g., Let's Encrypt, DigiCert). "+
			"The private key is generated but NOT saved to disk — only the CSR is returned."),
	mcp.WithString("common_name",
		mcp.Required(),
		mcp.Description("Common Name (CN) for the CSR (usually the primary domain name)"),
	),
	mcp.WithString("organization",
		mcp.Description("Organization name (O field)"),
	),
	mcp.WithString("country",
		mcp.Description("Two-letter country code (C field)"),
	),
	mcp.WithString("province",
		mcp.Description("Province or state (ST field)"),
	),
	mcp.WithString("locality",
		mcp.Description("City or locality (L field)"),
	),
	mcp.WithArray("dns_names",
		mcp.Description("Subject Alternative Names - additional DNS names to include"),
	),
	mcp.WithArray("ip_addresses",
		mcp.Description("Subject Alternative Names - IP addresses as strings"),
	),
	mcp.WithNumber("key_size",
		mcp.Description("Key size in bits. Default: 2048 (RSA), 256 (ECDSA)"),
	),
	mcp.WithString("key_type",
		mcp.Description("Key algorithm type. Options: 'rsa' (default), 'ecdsa', 'ed25519'"),
	),
)

var CertInfoTool = mcp.NewTool("cert_info",
	mcp.WithDescription(
		"Retrieve SSL/TLS certificate and connection information from a domain. "+
			"Connects to the target server and returns the full certificate chain details, "+
			"TLS version, cipher suite, handshake time, and fingerprints (SHA-256, SHA-1, MD5, public key SHA-256)."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com', 'example.com:8443'). Default port is 443."),
	),
)

var CertParseTool = mcp.NewTool("cert_parse",
	mcp.WithDescription(
		"Parse a certificate from a local file (PEM or DER format) and return detailed information "+
			"including subject, issuer, validity dates, Subject Alternative Names (SANs), key usage, "+
			"public key algorithm, signature algorithm, key size, and fingerprints."),
	mcp.WithString("file_path",
		mcp.Required(),
		mcp.Description("Absolute or relative path to the certificate file (supports .pem, .crt, .cer, .der formats)"),
	),
)

var CertValidateFilesTool = mcp.NewTool("cert_validate_files",
	mcp.WithDescription(
		"Validate that a certificate file and private key file are correctly formatted PEM files "+
			"and that the public key in the certificate matches the private key. "+
			"Supports RSA, ECDSA, and Ed25519 key types. "+
			"Returns success if both files are valid and the key pair matches."),
	mcp.WithString("cert_path",
		mcp.Required(),
		mcp.Description("Path to the certificate PEM file"),
	),
	mcp.WithString("key_path",
		mcp.Required(),
		mcp.Description("Path to the private key PEM file"),
	),
)

var CertValidateFingerprintTool = mcp.NewTool("cert_validate_fingerprint",
	mcp.WithDescription(
		"Validate whether a fingerprint string has the correct format for a given hash algorithm. "+
			"Checks that the hex characters are valid and the length matches the expected hash output size."),
	mcp.WithString("fingerprint",
		mcp.Required(),
		mcp.Description("The fingerprint hex string to validate (colons optional, e.g., 'ab:cd:ef...' or 'abcdef...')"),
	),
	mcp.WithString("hash_type",
		mcp.Required(),
		mcp.Description("Hash algorithm to validate against"),
		mcp.Enum("md5", "sha1", "sha256"),
	),
)

var CertDownloadTool = mcp.NewTool("cert_download",
	mcp.WithDescription(
		"Download SSL/TLS certificate chain from a remote domain and save as PEM files on disk. "+
			"Saves both the full certificate chain and the leaf certificate separately. "+
			"Returns the target domain, chain length, and list of saved file paths."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
	mcp.WithString("output_dir",
		mcp.Description("Directory to save the certificate files. Default: current working directory."),
	),
)

var CertScanProtocolsTool = mcp.NewTool("cert_scan_protocols",
	mcp.WithDescription(
		"Scan a server for supported TLS protocol versions by attempting to connect "+
			"with each version (TLS 1.0, 1.1, 1.2, 1.3) individually. "+
			"Returns which versions are supported/unsupported and whether the server is secure "+
			"(i.e., doesn't support insecure TLS 1.0/1.1)."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var CertScanCiphersTool = mcp.NewTool("cert_scan_ciphers",
	mcp.WithDescription(
		"Scan a server for supported cipher suites by probing individual cipher suites. "+
			"Tests both secure (AES-GCM, ChaCha20) and weak (RC4, 3DES, NULL) cipher suites. "+
			"Returns which cipher suites are supported, categorized as secure or weak."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
	mcp.WithNumber("tls_version",
		mcp.Description("TLS version to scan cipher suites for. Default: 1.2 (0x0303). Use 1.3 (0x0304) for TLS 1.3 cipher suites."),
	),
)

var CertCheckHSTSTool = mcp.NewTool("cert_check_hsts",
	mcp.WithDescription(
		"Check if a domain has HSTS (HTTP Strict Transport Security) enabled by making "+
			"an HTTPS request and inspecting the response headers. Returns HSTS status, "+
			"max-age, includeSubDomains, and preload directives."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name (e.g., 'example.com'). Default port is 443."),
	),
)

var JARMScanTool = mcp.NewTool("cert_jarm",
	mcp.WithDescription(
		"Generate a JARM TLS server fingerprint by sending multiple TLS Client Hello probes "+
			"and analyzing the server's responses. JARM is used for server identification, "+
			"C2 infrastructure detection, and cyberspace mapping. Returns the JARM hash, "+
			"negotiated TLS version, and cipher suite."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var JA3ScanTool = mcp.NewTool("cert_ja3",
	mcp.WithDescription(
		"Generate JA3 (client) and JA3S (server) TLS fingerprints by connecting to a target. "+
			"JA3 fingerprints are MD5 hashes of TLS handshake parameters used for service "+
			"identification, malware C2 detection, and cyberspace mapping. "+
			"Returns both JA3 and JA3S hashes with raw fingerprint strings."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var VulnScanTool = mcp.NewTool("cert_scan_vulnerabilities",
	mcp.WithDescription(
		"Scan a server for known TLS vulnerabilities including Heartbleed, POODLE, ROBOT, "+
			"CCS Injection, FREAK, Logjam, Sweet32, BEAST, CRIME, DROWN, and insecure renegotiation. "+
			"Returns vulnerability status for each check with severity levels and a summary."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var CTSearchTool = mcp.NewTool("cert_search_ct",
	mcp.WithDescription(
		"Search Certificate Transparency (CT) logs for certificates associated with a domain. "+
			"Essential for cyberspace mapping - discovers subdomains, certificate issuance history, "+
			"unauthorized certificates, and organizational infrastructure. "+
			"Returns all certificates found with subdomain enumeration."),
	mcp.WithString("domain",
		mcp.Required(),
		mcp.Description("Domain name to search for (e.g., 'example.com'). Searches for all subdomain certificates."),
	),
)

var CheckRevocationTool = mcp.NewTool("cert_check_revocation",
	mcp.WithDescription(
		"Check the revocation status of a certificate using both OCSP (Online Certificate Status Protocol) "+
			"and CRL (Certificate Revocation List). For domain targets, connects and checks the leaf certificate. "+
			"For file targets, checks CRL only (OCSP requires issuer certificate). "+
			"Returns OCSP and CRL status with overall revocation verdict."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name (e.g., 'example.com') or file path (e.g., '/path/to/cert.pem') to check."),
	),
)

var CheckPFSTool = mcp.NewTool("cert_check_pfs",
	mcp.WithDescription(
		"Check whether a server supports Perfect Forward Secrecy (PFS). PFS ensures that "+
			"even if the server's private key is compromised, past session keys cannot be derived. "+
			"Checks ECDHE/DHE key exchange and lists PFS and non-PFS cipher suites."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var DetectEVTool = mcp.NewTool("cert_detect_ev",
	mcp.WithDescription(
		"Detect whether a domain's certificate is an Extended Validation (EV) certificate. "+
			"EV certificates provide the highest level of identity assurance and display the "+
			"organization name in the browser address bar. Checks certificate policy OIDs against "+
			"known EV policy identifiers."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var VerifyCertChainTool = mcp.NewTool("cert_verify_chain",
	mcp.WithDescription(
		"Verify a server's certificate chain against the system trust store. Returns detailed "+
			"information about each verified chain path, trust anchor, and any errors or warnings. "+
			"Checks chain validity, hostname matching, expiration, and weak signature algorithms."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var CheckSessionResumptionTool = mcp.NewTool("cert_check_session_resumption",
	mcp.WithDescription(
		"Check whether a server supports TLS session resumption via session IDs or "+
			"session tickets (RFC 5077). Session resumption improves TLS handshake performance "+
			"by allowing clients to reuse previously negotiated session parameters."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var CertExpiryMonitorTool = mcp.NewTool("cert_expiry_monitor",
	mcp.WithDescription(
		"Monitor certificate expiration for multiple domains. Returns expiry status for each target "+
			"categorized as Expired, Critical (<=7 days), Warning (<=30 days), or Healthy (>30 days). "+
			"Useful for proactive certificate lifecycle management."),
	mcp.WithArray("targets",
		mcp.Required(),
		mcp.Description("List of domain names or file paths to monitor (e.g., ['google.com', 'github.com', '/path/to/cert.pem'])"),
	),
)

var CheckWildcardTool = mcp.NewTool("cert_check_wildcard",
	mcp.WithDescription(
		"Analyze wildcard certificate patterns in a domain's certificate. Detects wildcard SANs, "+
			"classifies wildcard levels, assesses security risk, and lists covered domains. "+
			"Essential for cyberspace mapping to understand certificate scope."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or file path to analyze for wildcard patterns."),
	),
)

var GetTrustedDomainsTool = mcp.NewTool("cert_get_trusted_domains",
	mcp.WithDescription(
		"Extract all domain names trusted by a certificate, including wildcard expansions. "+
			"Returns exact domains, wildcard domains, base domains, and organization info. "+
			"Key for cyberspace mapping to understand what domain namespace a certificate covers."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var CheckCAATool = mcp.NewTool("cert_check_caa",
	mcp.WithDescription(
		"Check DNS CAA (Certification Authority Authorization) records for a domain. "+
			"Verifies if the issuing CA is authorized by CAA policy. Detects CAA misconfigurations "+
			"and unauthorized certificate issuance."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name to check CAA records for (e.g., 'example.com')."),
	),
)

var CheckSCTTool = mcp.NewTool("cert_check_sct",
	mcp.WithDescription(
		"Verify Signed Certificate Timestamps (SCTs) in a certificate. Checks if the certificate "+
			"meets CA/Browser Forum CT requirements (2+ SCTs for standard validity). "+
			"Missing SCTs indicate potential non-compliance or misissuance."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var VerifyHostnameTool = mcp.NewTool("cert_verify_hostname",
	mcp.WithDescription(
		"Verify that a server's certificate matches the requested hostname. Checks SAN/CN matching, "+
			"detects hostname mismatches, wildcard matches, and RFC 6125 compliance. "+
			"Critical for identifying misconfigured or potentially malicious certificates."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var ScanCertSecurityTool = mcp.NewTool("cert_scan_cert_security",
	mcp.WithDescription(
		"Perform certificate-specific security checks (not TLS protocol checks). Detects weak signatures, "+
			"short keys, missing SANs, hostname mismatches, excessive validity, self-signed certs, "+
			"expired/expiring certs, wildcard risks, internal names, and untrusted chains."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var CTEnumerateSubdomainsTool = mcp.NewTool("cert_ct_enumerate",
	mcp.WithDescription(
		"Enumerate subdomains through Certificate Transparency logs. Enhanced CT search focused on "+
			"cyberspace mapping - discovers all subdomains, groups by issuer, identifies wildcard domains, "+
			"and tracks active vs expired certificates."),
	mcp.WithString("domain",
		mcp.Required(),
		mcp.Description("Domain name to enumerate subdomains for (e.g., 'example.com')."),
	),
)

var SearchCTByFingerprintTool = mcp.NewTool("cert_search_ct_fingerprint",
	mcp.WithDescription(
		"Search Certificate Transparency logs for a specific certificate by its SHA-256 fingerprint. "+
			"Useful for tracking a specific certificate, verifying CT log inclusion, "+
			"and finding all instances of a known certificate across CT logs."),
	mcp.WithString("fingerprint",
		mcp.Required(),
		mcp.Description("SHA-256 fingerprint of the certificate (hex, with or without colons)."),
	),
)

var CheckDistrustedCATool = mcp.NewTool("cert_check_distrusted_ca",
	mcp.WithDescription(
		"Check if a certificate chain contains any known distrusted or compromised "+
			"Certificate Authorities (DigiNotar, WoSign, StartCom, Symantec legacy, CNNIC, TrustCor, etc.). "+
			"Detects certificates that chain to CAs removed from browser root stores."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com:8443'). Default port is 443."),
	),
)

var CheckOCSPMustStapleTool = mcp.NewTool("cert_check_ocsp_must_staple",
	mcp.WithDescription(
		"Check OCSP Must-Staple compliance (RFC 7633). A certificate with Must-Staple "+
			"that fails to provide an OCSP staple causes hard-failures in compliant clients."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com'). Default port is 443."),
	),
)

var CheckKeyUsageComplianceTool = mcp.NewTool("cert_check_key_usage",
	mcp.WithDescription(
		"Validate that a certificate's key usage extensions comply with RFC 5280 and "+
			"CA/Browser Forum Baseline Requirements. Checks CA keyCertSign, leaf digitalSignature, etc."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com'). Default port is 443."),
	),
)

var CheckSerialEntropyTool = mcp.NewTool("cert_check_serial_entropy",
	mcp.WithDescription(
		"Analyze certificate serial number entropy. CA/Browser Forum Baseline Requirements "+
			"mandate at least 64 bits of entropy. Detects sequential, predictable, or low-entropy serials."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com'). Default port is 443."),
	),
)

var CheckPolicyAnalysisTool = mcp.NewTool("cert_check_policy",
	mcp.WithDescription(
		"Analyze certificate policy OIDs beyond simple EV detection. Identifies DV/OV/EV validation type, "+
			"unknown policy OIDs, and missing Certificate Policies on public CA-issued certificates."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com'). Default port is 443."),
	),
)

var CheckNameConstraintsTool = mcp.NewTool("cert_check_name_constraints",
	mcp.WithDescription(
		"Check CA certificate Name Constraints and verify leaf certificate names comply with "+
			"parent CA constraints. Detects trust boundary violations where certificates are issued "+
			"outside a CA's permitted namespace."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com'). Default port is 443."),
	),
)

var CheckBundleCompletenessTool = mcp.NewTool("cert_check_bundle",
	mcp.WithDescription(
		"Check if a server provides a complete certificate chain. If intermediates are missing, "+
			"attempts to fetch them via AIA CA Issuers URLs and re-verify the chain."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP address with optional port (e.g., 'example.com'). Default port is 443."),
	),
)
