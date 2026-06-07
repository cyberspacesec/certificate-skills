package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"

	"github.com/cyberspacesec/certificate-hacker/pkg"
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

// HandleCertFingerprint generates fingerprints from base64-encoded DER data.
func HandleCertFingerprint(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	certDataB64, err := req.RequireString("certificate_data_base64")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	certData, err := base64.StdEncoding.DecodeString(certDataB64)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid base64 encoding: %v", err)), nil
	}

	fingerprints := pkg.GenerateFingerprintFromBytes(certData)
	return marshalResult(fingerprints)
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

// marshalResult is a helper that JSON-serializes a value as a tool result.
func marshalResult(v interface{}) (*mcp.CallToolResult, error) {
	jsonBytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to serialize result: %v", err)), nil
	}
	return mcp.NewToolResultText(string(jsonBytes)), nil
}
