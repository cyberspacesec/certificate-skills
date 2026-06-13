package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cyberspacesec/certificate-skills/pkg"
	"github.com/mark3labs/mcp-go/mcp"
)

// HandleCertInfo retrieves certificate information from a domain.
func HandleCertInfo(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	sslInfo, err := pkg.GetCertFromDomain(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to get certificate from %s: %v", target, err)), nil
	}

	return marshalResult(sslInfo)
}

// HandleCertParse parses a certificate from a local file.
func HandleCertParse(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filePath, err := req.RequireString("file_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	certInfo, err := pkg.GetCertFromFile(filePath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to parse certificate file: %v", err)), nil
	}

	return marshalResult(certInfo)
}

// HandleCertAnalyze performs comprehensive security analysis.
func HandleCertAnalyze(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	analysis, err := pkg.AnalyzeSecurity(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze %s: %v", target, err)), nil
	}

	return marshalResult(analysis)
}

// HandleCertFingerprintDomain generates fingerprints by connecting to a domain.
func HandleCertFingerprintDomain(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	sslInfo, err := pkg.GetCertFromDomain(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to connect to %s: %v", target, err)), nil
	}

	// Extract fingerprints from the leaf certificate (first in chain)
	if len(sslInfo.PeerCerts.Certificates) == 0 {
		return mcp.NewToolResultError(fmt.Sprintf("no certificates found for %s", target)), nil
	}

	leafCert := sslInfo.PeerCerts.Certificates[0]
	result := map[string]interface{}{
		"target":       target,
		"tls_version":  sslInfo.TLSVersion,
		"fingerprints": leafCert.Fingerprints,
	}

	return marshalResult(result)
}

// HandleCertFingerprintFile generates fingerprints from a local certificate file.
func HandleCertFingerprintFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filePath, err := req.RequireString("file_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Verify file exists before attempting to parse
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return mcp.NewToolResultError(fmt.Sprintf("file not found: %s", filePath)), nil
	}

	certInfo, err := pkg.GetCertFromFile(filePath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to parse certificate: %v", err)), nil
	}

	result := map[string]interface{}{
		"file_path":    filePath,
		"subject":      certInfo.Subject,
		"fingerprints": certInfo.Fingerprints,
	}

	return marshalResult(result)
}

// HandleCertGenerate generates a self-signed certificate.
func HandleCertGenerate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Parse IP addresses from strings
	ipStrings := req.GetStringSlice("ip_addresses", []string{})
	var ipAddrs []net.IP
	for _, s := range ipStrings {
		ip := net.ParseIP(s)
		if ip == nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid IP address: %s", s)), nil
		}
		ipAddrs = append(ipAddrs, ip)
	}

	certReq := pkg.CertificateRequest{
		CommonName:     req.GetString("common_name", "localhost"),
		Organization:   req.GetString("organization", ""),
		Country:        req.GetString("country", ""),
		Province:       req.GetString("province", ""),
		Locality:       req.GetString("locality", ""),
		DNSNames:       req.GetStringSlice("dns_names", []string{}),
		IPAddresses:    ipAddrs,
		ValidityDays:   req.GetInt("validity_days", 365),
		KeySize:        req.GetInt("key_size", 2048),
		KeyType:        req.GetString("key_type", "rsa"),
		IsCA:           req.GetBool("is_ca", false),
		OutputCertPath: req.GetString("output_cert_path", ""),
		OutputKeyPath:  req.GetString("output_key_path", ""),
	}

	result, err := pkg.GenerateSelfSignedCert(certReq)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to generate certificate: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCertGenerateCSR generates a Certificate Signing Request.
func HandleCertGenerateCSR(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Parse IP addresses from strings
	ipStrings := req.GetStringSlice("ip_addresses", []string{})
	var ipAddrs []net.IP
	for _, s := range ipStrings {
		ip := net.ParseIP(s)
		if ip == nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid IP address: %s", s)), nil
		}
		ipAddrs = append(ipAddrs, ip)
	}

	certReq := pkg.CertificateRequest{
		CommonName:   req.GetString("common_name", ""),
		Organization: req.GetString("organization", ""),
		Country:      req.GetString("country", ""),
		Province:     req.GetString("province", ""),
		Locality:     req.GetString("locality", ""),
		DNSNames:     req.GetStringSlice("dns_names", []string{}),
		IPAddresses:  ipAddrs,
		KeySize:      req.GetInt("key_size", 2048),
		KeyType:      req.GetString("key_type", "rsa"),
	}

	if certReq.CommonName == "" {
		return mcp.NewToolResultError("common_name is required"), nil
	}

	csrPEM, err := pkg.GenerateCSR(certReq)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to generate CSR: %v", err)), nil
	}

	return mcp.NewToolResultText(csrPEM), nil
}

// HandleCertValidateFiles validates that certificate and key files match.
func HandleCertValidateFiles(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	certPath, err := req.RequireString("cert_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	keyPath, err := req.RequireString("key_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	err = pkg.ValidateCertificateFiles(certPath, keyPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("validation failed: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Certificate and key files are valid and match.\nCertificate: %s\nPrivate Key: %s", certPath, keyPath)), nil
}

// HandleCertValidateFingerprint validates a fingerprint format.
func HandleCertValidateFingerprint(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fingerprint, err := req.RequireString("fingerprint")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	hashType, err := req.RequireString("hash_type")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	valid := pkg.ValidateFingerprint(fingerprint, hashType)

	result := map[string]interface{}{
		"fingerprint": fingerprint,
		"hash_type":   hashType,
		"is_valid":    valid,
	}

	if valid {
		result["message"] = fmt.Sprintf("Fingerprint is a valid %s hash", hashType)
	} else {
		result["message"] = fmt.Sprintf("Fingerprint is NOT a valid %s hash (check length and hex characters)", hashType)
	}

	return marshalResult(result)
}

// HandleCertCompare compares two certificates.
func HandleCertCompare(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target1, err := req.RequireString("target1")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	target2, err := req.RequireString("target2")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var comparison *pkg.CertComparison

	// 判断目标类型：文件路径 or 域名
	isFile1 := isFilePath(target1)
	isFile2 := isFilePath(target2)

	if isFile1 && isFile2 {
		comparison, err = pkg.CompareCertsFromFiles(target1, target2)
	} else if !isFile1 && !isFile2 {
		comparison, err = pkg.CompareCertsFromDomains(target1, target2)
	} else if isFile1 && !isFile2 {
		// 文件 vs 域名
		cert1, err1 := pkg.ReadCertFromFile(target1)
		if err1 != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read cert from %s: %v", target1, err1)), nil
		}
		conn2, err2 := pkg.TLSDial(target2)
		if err2 != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to %s: %v", target2, err2)), nil
		}
		defer conn2.Close()
		certs2 := conn2.ConnectionState().PeerCertificates
		if len(certs2) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("no certificates found for %s", target2)), nil
		}
		comparison = pkg.CompareCerts(cert1, certs2[0])
		err = nil
	} else {
		// 域名 vs 文件
		conn1, err1 := pkg.TLSDial(target1)
		if err1 != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to %s: %v", target1, err1)), nil
		}
		defer conn1.Close()
		certs1 := conn1.ConnectionState().PeerCertificates
		if len(certs1) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("no certificates found for %s", target1)), nil
		}
		cert2, err2 := pkg.ReadCertFromFile(target2)
		if err2 != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read cert from %s: %v", target2, err2)), nil
		}
		comparison = pkg.CompareCerts(certs1[0], cert2)
		err = nil
	}

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to compare certificates: %v", err)), nil
	}

	return marshalResult(comparison)
}

// HandleCertBatchAnalyze performs security analysis on multiple domains.
func HandleCertBatchAnalyze(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	targets := req.GetStringSlice("targets", []string{})
	if len(targets) == 0 {
		return mcp.NewToolResultError("targets array is required and must contain at least one domain"), nil
	}

	if len(targets) > 50 {
		return mcp.NewToolResultError("maximum 50 targets allowed per batch"), nil
	}

	result := pkg.BatchAnalyzeSecurity(targets)
	return marshalResult(result)
}

// isFilePath 判断目标是否为文件路径
func isFilePath(target string) bool {
	fileExts := []string{".pem", ".crt", ".cer", ".der", ".p7b", ".p7c"}
	for _, ext := range fileExts {
		if strings.HasSuffix(strings.ToLower(target), ext) {
			return true
		}
	}
	return false
}

// marshalResult is a helper that JSON-serializes a value as a tool result.
func marshalResult(v interface{}) (*mcp.CallToolResult, error) {
	jsonBytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to serialize result: %v", err)), nil
	}
	return mcp.NewToolResultText(string(jsonBytes)), nil
}
// HandleCertDownload downloads certificate chain from a domain and saves to files.
func HandleCertDownload(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	outputDir := req.GetString("output_dir", "")

	result, err := pkg.DownloadCertsFromDomain(target, outputDir)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to download certificate from %s: %v", target, err)), nil
	}

	return marshalResult(result)
}

// HandleCertScanProtocols scans for supported TLS protocol versions.
func HandleCertScanProtocols(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.TLSProtocolScan(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to scan TLS protocols for %s: %v", target, err)), nil
	}

	return marshalResult(result)
}

// HandleCertScanCiphers scans for supported cipher suites.
func HandleCertScanCiphers(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	tlsVersion := uint16(req.GetFloat("tls_version", 0))

	result, err := pkg.CipherSuiteScan(target, tlsVersion)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to scan cipher suites for %s: %v", target, err)), nil
	}

	return marshalResult(result)
}

// HandleCertCheckHSTS checks if a domain has HSTS enabled.
func HandleCertCheckHSTS(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result := pkg.CheckHSTS(target)
	return marshalResult(result)
}

// HandleJARMScan generates a JARM TLS fingerprint.
func HandleJARMScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.JARMScan(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to generate JARM fingerprint: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleJA3Scan generates JA3/JA3S TLS fingerprints.
func HandleJA3Scan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.JA3Scan(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to generate JA3 fingerprints: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleVulnScan scans for TLS vulnerabilities.
func HandleVulnScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.VulnerabilityScan(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to scan vulnerabilities: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCTSearch searches Certificate Transparency logs.
func HandleCTSearch(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	domain, err := req.RequireString("domain")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.CTSearch(domain)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to search CT logs: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCheckRevocation checks certificate revocation status.
func HandleCheckRevocation(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.CheckRevocation(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check revocation: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCheckPFS checks whether a server supports Perfect Forward Secrecy.
func HandleCheckPFS(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.CheckPFS(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check PFS: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleDetectEV detects whether a domain's certificate is an Extended Validation certificate.
func HandleDetectEV(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.DetectEV(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to detect EV: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleVerifyCertChain verifies a server's certificate chain.
func HandleVerifyCertChain(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.VerifyCertChain(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to verify chain: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCheckSessionResumption checks TLS session resumption support.
func HandleCheckSessionResumption(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.CheckSessionResumption(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check session resumption: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCertExpiryMonitor monitors certificate expiration for multiple targets.
func HandleCertExpiryMonitor(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	targets := req.GetStringSlice("targets", []string{})
	if len(targets) == 0 {
		return mcp.NewToolResultError("targets array is required and must contain at least one domain"), nil
	}

	if len(targets) > 50 {
		return mcp.NewToolResultError("maximum 50 targets allowed per batch"), nil
	}

	result := pkg.CertExpiryMonitor(targets)
	return marshalResult(result)
}

// HandleCheckWildcard analyzes wildcard certificate patterns.
func HandleCheckWildcard(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.CheckWildcard(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check wildcard: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleGetTrustedDomains extracts all trusted domains from a certificate.
func HandleGetTrustedDomains(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.GetTrustedDomains(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to get trusted domains: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCheckCAA checks CAA DNS records.
func HandleCheckCAA(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.CheckCAA(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check CAA: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCheckSCT verifies Signed Certificate Timestamps.
func HandleCheckSCT(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.CheckSCT(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check SCT: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleVerifyHostname verifies hostname matching.
func HandleVerifyHostname(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.VerifyHostname(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to verify hostname: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleScanCertSecurity performs certificate-specific security checks.
func HandleScanCertSecurity(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.ScanCertSecurity(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to scan cert security: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCTEnumerateSubdomains enumerates subdomains via CT logs.
func HandleCTEnumerateSubdomains(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	domain, err := req.RequireString("domain")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.CTEnumerateSubdomains(domain)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to enumerate subdomains: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleSearchCTByFingerprint searches CT logs by certificate fingerprint.
func HandleSearchCTByFingerprint(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fingerprint, err := req.RequireString("fingerprint")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := pkg.CTSearchByFingerprint(fingerprint)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to search CT by fingerprint: %v", err)), nil
	}

	return marshalResult(result)
}

// HandleCheckDistrustedCA checks for distrusted CAs in the certificate chain.
func HandleCheckDistrustedCA(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := pkg.CheckDistrustedCA(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check distrusted CA: %v", err)), nil
	}
	return marshalResult(result)
}

// HandleCheckOCSPMustStaple checks OCSP Must-Staple compliance.
func HandleCheckOCSPMustStaple(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := pkg.CheckOCSPMustStaple(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check OCSP Must-Staple: %v", err)), nil
	}
	return marshalResult(result)
}

// HandleCheckKeyUsageCompliance validates key usage compliance.
func HandleCheckKeyUsageCompliance(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := pkg.CheckKeyUsageCompliance(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check key usage: %v", err)), nil
	}
	return marshalResult(result)
}

// HandleCheckSerialEntropy analyzes serial number entropy.
func HandleCheckSerialEntropy(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := pkg.CheckSerialEntropy(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check serial entropy: %v", err)), nil
	}
	return marshalResult(result)
}

// HandleCheckPolicyAnalysis analyzes certificate policy OIDs.
func HandleCheckPolicyAnalysis(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := pkg.CheckPolicyAnalysis(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check policy: %v", err)), nil
	}
	return marshalResult(result)
}

// HandleCheckNameConstraints checks CA name constraints compliance.
func HandleCheckNameConstraints(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := pkg.CheckNameConstraints(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check name constraints: %v", err)), nil
	}
	return marshalResult(result)
}

// HandleCheckBundleCompleteness checks certificate bundle completeness.
func HandleCheckBundleCompleteness(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := pkg.CheckBundleCompleteness(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to check bundle: %v", err)), nil
	}
	return marshalResult(result)
}
