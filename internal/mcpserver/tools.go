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
		{Tool: CertFingerprintDomainTool, Handler: HandleCertFingerprintDomain},
		{Tool: CertFingerprintFileTool, Handler: HandleCertFingerprintFile},
		{Tool: CertGenerateTool, Handler: HandleCertGenerate},
		{Tool: CertGenerateCSRTool, Handler: HandleCertGenerateCSR},
		{Tool: CertValidateFilesTool, Handler: HandleCertValidateFiles},
		{Tool: CertValidateFingerprintTool, Handler: HandleCertValidateFingerprint},
	}
}

// --- Tool Definitions ---

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
			"public key algorithm, signature algorithm, and fingerprints."),
	mcp.WithString("file_path",
		mcp.Required(),
		mcp.Description("Absolute or relative path to the certificate file (supports .pem, .crt, .cer, .der formats)"),
	),
)

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
			"Supports RSA 2048/4096-bit keys, CA certificate generation, and custom Subject Alternative Names. "+
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
		mcp.Description("RSA key size in bits. Options: 2048 (default, standard security) or 4096 (high security, slower)"),
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
		mcp.Description("RSA key size in bits. Default: 2048"),
	),
)

var CertValidateFilesTool = mcp.NewTool("cert_validate_files",
	mcp.WithDescription(
		"Validate that a certificate file and private key file are correctly formatted PEM files "+
			"and that the public key in the certificate matches the private key. "+
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
