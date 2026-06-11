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
