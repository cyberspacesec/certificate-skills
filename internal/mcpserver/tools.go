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
		{Tool: CertGenerateTool, Handler: HandleCertGenerate},
		{Tool: CertGenerateCSRTool, Handler: HandleCertGenerateCSR},
		{Tool: CertValidateFilesTool, Handler: HandleCertValidateFiles},
		{Tool: CertFingerprintTool, Handler: HandleCertFingerprint},
		{Tool: CertValidateFingerprintTool, Handler: HandleCertValidateFingerprint},
	}
}

// --- Tool Definitions ---

var CertInfoTool = mcp.NewTool("cert_info",
	mcp.WithDescription("Retrieve SSL/TLS certificate and connection information from a domain. Connects to the target and returns certificate chain details, TLS version, cipher suite, and fingerprints."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP with optional port (e.g., 'example.com', 'example.com:8443'). Default port is 443."),
	),
)

var CertParseTool = mcp.NewTool("cert_parse",
	mcp.WithDescription("Parse a certificate from a local PEM/DER file and return detailed certificate information including subject, issuer, validity dates, SANs, key usage, and fingerprints."),
	mcp.WithString("file_path",
		mcp.Required(),
		mcp.Description("Path to the certificate file (PEM or DER format, e.g., /path/to/cert.pem)"),
	),
)

var CertAnalyzeTool = mcp.NewTool("cert_analyze_security",
	mcp.WithDescription("Perform comprehensive security analysis of an SSL/TLS connection. Returns a 0-100 security score, identified issues by severity (Critical/High/Medium/Low), certificate checks, TLS checks, expiration status, and actionable recommendations."),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("Domain name or IP with optional port (e.g., 'example.com:8443')"),
	),
)

var CertGenerateTool = mcp.NewTool("cert_generate",
	mcp.WithDescription("Generate a self-signed SSL/TLS certificate and private key. Creates certificate and key PEM files on disk. Supports RSA 2048/4096-bit keys, CA certificates, and custom SANs."),
	mcp.WithString("common_name",
		mcp.Description("Common Name (CN) for the certificate. Default: localhost"),
	),
	mcp.WithString("organization",
		mcp.Description("Organization name (O field)"),
	),
	mcp.WithString("country",
		mcp.Description("Country code, 2 letters (C field, e.g., 'US')"),
	),
	mcp.WithString("province",
		mcp.Description("Province or state (ST field)"),
	),
	mcp.WithString("locality",
		mcp.Description("City or locality (L field)"),
	),
	mcp.WithArray("dns_names",
		mcp.Description("Subject Alternative Names - DNS names (e.g., ['www.example.com', 'api.example.com'])"),
	),
	mcp.WithArray("ip_addresses",
		mcp.Description("Subject Alternative Names - IP addresses as strings (e.g., ['192.168.1.1', '10.0.0.1'])"),
	),
	mcp.WithNumber("validity_days",
		mcp.Description("Certificate validity period in days. Default: 365"),
	),
	mcp.WithNumber("key_size",
		mcp.Description("RSA key size in bits. Options: 2048, 4096. Default: 2048"),
	),
	mcp.WithBoolean("is_ca",
		mcp.Description("Generate as CA (Certificate Authority) certificate. Default: false"),
	),
	mcp.WithString("output_cert_path",
		mcp.Description("Output path for certificate file. Default: <common_name>.pem"),
	),
	mcp.WithString("output_key_path",
		mcp.Description("Output path for private key file. Default: <common_name>-key.pem"),
	),
)

var CertGenerateCSRTool = mcp.NewTool("cert_generate_csr",
	mcp.WithDescription("Generate a Certificate Signing Request (CSR) in PEM format. Returns the CSR as text content, suitable for submitting to a Certificate Authority."),
	mcp.WithString("common_name",
		mcp.Required(),
		mcp.Description("Common Name (CN) for the CSR"),
	),
	mcp.WithString("organization",
		mcp.Description("Organization name (O field)"),
	),
	mcp.WithString("country",
		mcp.Description("Country code, 2 letters (C field)"),
	),
	mcp.WithString("province",
		mcp.Description("Province or state (ST field)"),
	),
	mcp.WithString("locality",
		mcp.Description("City or locality (L field)"),
	),
	mcp.WithArray("dns_names",
		mcp.Description("Subject Alternative Names - DNS names"),
	),
	mcp.WithArray("ip_addresses",
		mcp.Description("Subject Alternative Names - IP addresses as strings"),
	),
	mcp.WithNumber("key_size",
		mcp.Description("RSA key size in bits. Default: 2048"),
	),
)

var CertValidateFilesTool = mcp.NewTool("cert_validate_files",
	mcp.WithDescription("Validate that a certificate and private key pair match and are correctly formatted PEM files. Checks that the public key in the certificate corresponds to the private key."),
	mcp.WithString("cert_path",
		mcp.Required(),
		mcp.Description("Path to the certificate PEM file"),
	),
	mcp.WithString("key_path",
		mcp.Required(),
		mcp.Description("Path to the private key PEM file"),
	),
)

var CertFingerprintTool = mcp.NewTool("cert_fingerprint",
	mcp.WithDescription("Generate certificate fingerprints (MD5, SHA-1, SHA-256) from raw certificate data provided as base64-encoded DER bytes."),
	mcp.WithString("certificate_data_base64",
		mcp.Required(),
		mcp.Description("Base64-encoded DER certificate data"),
	),
)

var CertValidateFingerprintTool = mcp.NewTool("cert_validate_fingerprint",
	mcp.WithDescription("Validate whether a fingerprint string matches the expected format for a given hash algorithm. Checks hex character validity and length."),
	mcp.WithString("fingerprint",
		mcp.Required(),
		mcp.Description("The fingerprint hex string to validate (with or without colon separators)"),
	),
	mcp.WithString("hash_type",
		mcp.Required(),
		mcp.Description("Hash algorithm to validate against"),
		mcp.Enum("md5", "sha1", "sha256"),
	),
)
