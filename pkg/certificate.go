package pkg

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// BatchResult represents the result of a batch analysis operation.
type BatchResult struct {
	Target   string    `json:"target"`
	SSLInfo  *SSLInfo  `json:"ssl_info,omitempty"`
	CertInfo *CertInfo `json:"cert_info,omitempty"`
	Error    error     `json:"error,omitempty"`
}

// CertInfo represents certificate information.
type CertInfo struct {
	Subject            string            `json:"subject"`
	Issuer             string            `json:"issuer"`
	SerialNumber       string            `json:"serial_number"`
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	DNSNames           []string          `json:"dns_names"`
	IPAddresses        []string          `json:"ip_addresses"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	KeySize            int               `json:"key_size"`
	KeyUsage           []string          `json:"key_usage"`
	ExtKeyUsage        []string          `json:"ext_key_usage"`
	IsCA               bool              `json:"is_ca"`
	Version            int               `json:"version"`
	Fingerprints       map[string]string `json:"fingerprints"`
}

// CertChain represents certificate chain information.
type CertChain struct {
	Certificates []CertInfo `json:"certificates"`
	ChainLength  int        `json:"chain_length"`
	IsValid      bool       `json:"is_valid"`
	TrustAnchor  string     `json:"trust_anchor"`
}

// SSLInfo represents SSL/TLS connection information.
type SSLInfo struct {
	TLSVersion    string        `json:"tls_version"`
	CipherSuite   string        `json:"cipher_suite"`
	PeerCerts     CertChain     `json:"peer_certificates"`
	ConnectedAt   time.Time     `json:"connected_at"`
	HandshakeTime time.Duration `json:"handshake_time"`
	SupportsHTTP2 bool          `json:"supports_http2"`
	HasOCSPStaple bool          `json:"has_ocsp_staple"`
	OCSPResponse  []byte        `json:"ocsp_response,omitempty"`
}

// GetCertFromDomainWithContext retrieves certificate information from a domain with context support.
func GetCertFromDomainWithContext(ctx context.Context, domain string) (*SSLInfo, error) {
	start := time.Now()

	// Establish TLS connection
	conn, err := TLSDialWithContext(ctx, domain, defaultDialOptions())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	handshakeTime := time.Since(start)

	// Get connection state
	state := conn.ConnectionState()

	// Build certificate chain info
	certChain, err := buildCertChain(state.PeerCertificates)
	if err != nil {
		return nil, WrapChainError(domain, err)
	}

	// Detect HTTP/2 support: ALPN negotiation includes h2
	supportsHTTP2 := state.NegotiatedProtocol == "h2"
	hasOCSPStaple := len(state.OCSPResponse) > 0

	// Build SSL info
	sslInfo := &SSLInfo{
		TLSVersion:    getTLSVersionName(state.Version),
		CipherSuite:   tls.CipherSuiteName(state.CipherSuite),
		PeerCerts:     *certChain,
		ConnectedAt:   time.Now(),
		HandshakeTime: handshakeTime,
		SupportsHTTP2: supportsHTTP2,
		HasOCSPStaple: hasOCSPStaple,
		OCSPResponse:  state.OCSPResponse,
	}

	return sslInfo, nil
}

// GetCertFromDomain retrieves certificate information from a domain.
func GetCertFromDomain(domain string) (*SSLInfo, error) {
	return GetCertFromDomainWithContext(context.Background(), domain)
}

// GetCertFromFile reads a certificate from a file (supports PEM and DER formats).
func GetCertFromFile(filename string) (*CertInfo, error) {
	// Read file content
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, WrapFileError(filename, err)
	}

	// Try parsing as PEM format
	block, _ := pem.Decode(data)
	if block != nil {
		// PEM decoded successfully
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, WrapCertParseError(filename, err)
		}
		return buildCertInfo(cert), nil
	}

	// PEM decode failed, try DER format (binary)
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, WrapCertParseError(filename, fmt.Errorf("failed as PEM or DER format: %v", err))
	}

	return buildCertInfo(cert), nil
}

// buildCertChain builds certificate chain info with real chain verification.
func buildCertChain(certs []*x509.Certificate) (*CertChain, error) {
	if len(certs) == 0 {
		return nil, ErrCertNotFound
	}

	chain := &CertChain{
		Certificates: make([]CertInfo, len(certs)),
		ChainLength:  len(certs),
	}

	for i, cert := range certs {
		chain.Certificates[i] = *buildCertInfo(cert)
	}

	// Set trust anchor (root certificate)
	if len(certs) > 0 {
		lastCert := certs[len(certs)-1]
		chain.TrustAnchor = lastCert.Subject.CommonName
	}

	// Verify certificate chain using system cert pool
	leafCert := certs[0]
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Try verifying with system root certificates
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		// Cannot load system cert pool, mark as unverifiable
		chain.IsValid = false
		chain.TrustAnchor = "Unable to verify (system cert pool unavailable)"
		return chain, nil
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: intermediates,
		// Don't enforce DNS name matching; analysis only needs chain integrity
	}

	_, err = leafCert.Verify(verifyOpts)
	chain.IsValid = err == nil

	if err != nil {
		// If system root verification fails, try using the last cert in chain as root.
		// This occurs with self-signed certificates or private CAs.
		selfSignedOpts := x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: intermediates,
		}
		selfSignedOpts.Roots.AddCert(certs[len(certs)-1])

		_, selfSignedErr := leafCert.Verify(selfSignedOpts)
		chain.IsValid = selfSignedErr == nil
	}

	return chain, nil
}

// buildCertInfo builds certificate info from an x509 certificate.
func buildCertInfo(cert *x509.Certificate) *CertInfo {
	info := &CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DNSNames:           cert.DNSNames,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
		Version:            cert.Version,
		Fingerprints:       make(map[string]string),
	}

	// Extract key size
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeySize = key.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeySize = key.Curve.Params().BitSize
	case ed25519.PublicKey:
		info.KeySize = 256 // Ed25519 is always 256 bits
	}

	// Convert IP addresses to strings
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	// Parse key usage
	info.KeyUsage = parseKeyUsage(cert.KeyUsage)
	info.ExtKeyUsage = parseExtKeyUsage(cert.ExtKeyUsage)

	// Generate fingerprints
	info.Fingerprints = GenerateFingerprints(cert)

	return info
}

// parseHostPort parses hostname and port (supports IPv6 addresses like [::1]:443).
func parseHostPort(addr string) (host, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port specified, use default 443
		return addr, "443"
	}
	return host, port
}

// IsFileTarget checks if a target string looks like a file path.
func IsFileTarget(target string) bool {
	fileExts := []string{".pem", ".crt", ".cer", ".der", ".p7b", ".p7c"}
	for _, ext := range fileExts {
		if strings.HasSuffix(strings.ToLower(target), ext) {
			return true
		}
	}
	return false
}

// getTLSVersionName returns the human-readable TLS version name.
func getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// parseKeyUsage parses key usage bitmask to human-readable strings.
func parseKeyUsage(usage x509.KeyUsage) []string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

// parseExtKeyUsage parses extended key usage to human-readable strings.
func parseExtKeyUsage(usage []x509.ExtKeyUsage) []string {
	var usages []string

	for _, u := range usage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		}
	}

	return usages
}
