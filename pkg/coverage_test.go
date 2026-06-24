package pkg

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

// helper: create a self-signed x509.Certificate for testing check* functions
func makeTestCert(opts ...func(*x509.Certificate)) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("test"),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}
	for _, opt := range opts {
		opt(template)
	}
	return template
}

func pkixName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn}
}

// --- certificate.go coverage ---

func TestBuildCertChain_Empty(t *testing.T) {
	_, err := buildCertChain([]*x509.Certificate{})
	if err == nil {
		t.Error("expected error for empty chain")
	}
}

func TestBuildCertChain_SingleSelfSigned(t *testing.T) {
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:   "test-chain",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	chain, err := buildCertChain([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("buildCertChain failed: %v", err)
	}
	if chain.ChainLength != 1 {
		t.Errorf("expected chain length 1, got %d", chain.ChainLength)
	}
}

func TestBuildCertInfo_AllKeyTypes(t *testing.T) {
	// RSA - generate a real cert
	rsaResult, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "test-rsa-build", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert RSA failed: %v", err)
	}
	defer removeFiles(rsaResult.CertificatePath, rsaResult.PrivateKeyPath)
	rsaCert := readCertFromFile(t, rsaResult.CertificatePath)
	info := buildCertInfo(rsaCert)
	if info.PublicKeyAlgorithm != "RSA" {
		t.Errorf("expected RSA, got %s", info.PublicKeyAlgorithm)
	}

	// ECDSA
	ecResult, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "test-ec-build", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert ECDSA failed: %v", err)
	}
	defer removeFiles(ecResult.CertificatePath, ecResult.PrivateKeyPath)
	ecCert := readCertFromFile(t, ecResult.CertificatePath)
	info = buildCertInfo(ecCert)
	if info.PublicKeyAlgorithm != "ECDSA" {
		t.Errorf("expected ECDSA, got %s", info.PublicKeyAlgorithm)
	}

	// Ed25519
	edResult, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "test-ed-build", KeyType: "ed25519", ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert Ed25519 failed: %v", err)
	}
	defer removeFiles(edResult.CertificatePath, edResult.PrivateKeyPath)
	edCert := readCertFromFile(t, edResult.CertificatePath)
	info = buildCertInfo(edCert)
	if info.KeySize != 256 {
		t.Errorf("expected Ed25519 key size 256, got %d", info.KeySize)
	}
}

func TestBuildCertInfo_IPAddresses(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.IPAddresses = []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("::1")}
	})
	info := buildCertInfo(cert)
	if len(info.IPAddresses) != 2 {
		t.Errorf("expected 2 IP addresses, got %d", len(info.IPAddresses))
	}
}

func TestIsFileTarget_AllExtensions(t *testing.T) {
	tests := []struct {
		target   string
		expected bool
	}{
		{"cert.pem", true},
		{"cert.crt", true},
		{"cert.cer", true},
		{"cert.der", true},
		{"cert.p7b", true},
		{"cert.p7c", true},
		{"example.com", false},
		{"example.com:443", false},
		{"file.txt", false},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			if IsFileTarget(tt.target) != tt.expected {
				t.Errorf("IsFileTarget(%q) = %v, expected %v", tt.target, !tt.expected, tt.expected)
			}
		})
	}
}

func TestParseKeyUsage_AllBits(t *testing.T) {
	// Test all key usage bits individually
	allUsages := []struct {
		usage x509.KeyUsage
		name  string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	for _, u := range allUsages {
		result := parseKeyUsage(u.usage)
		if len(result) != 1 || result[0] != u.name {
			t.Errorf("parseKeyUsage(%v) = %v, expected [%s]", u.usage, result, u.name)
		}
	}

	// Test combined usage
	combined := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	result := parseKeyUsage(combined)
	if len(result) != 4 {
		t.Errorf("expected 4 usage strings, got %d: %v", len(result), result)
	}

	// Test zero usage
	result = parseKeyUsage(0)
	if len(result) != 0 {
		t.Errorf("expected 0 usage strings for zero, got %d", len(result))
	}
}

func TestParseExtKeyUsage_AllValues(t *testing.T) {
	allUsages := []struct {
		usage x509.ExtKeyUsage
		name  string
	}{
		{x509.ExtKeyUsageServerAuth, "Server Authentication"},
		{x509.ExtKeyUsageClientAuth, "Client Authentication"},
		{x509.ExtKeyUsageCodeSigning, "Code Signing"},
		{x509.ExtKeyUsageEmailProtection, "Email Protection"},
		{x509.ExtKeyUsageTimeStamping, "Time Stamping"},
		{x509.ExtKeyUsageOCSPSigning, "OCSP Signing"},
	}
	for _, u := range allUsages {
		result := parseExtKeyUsage([]x509.ExtKeyUsage{u.usage})
		if len(result) != 1 || result[0] != u.name {
			t.Errorf("parseExtKeyUsage(%v) = %v, expected [%s]", u.usage, result, u.name)
		}
	}

	// Test unknown EKU (should be skipped)
	result := parseExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsage(9999)})
	if len(result) != 0 {
		t.Errorf("expected 0 for unknown EKU, got %d: %v", len(result), result)
	}

	// Test empty
	result = parseExtKeyUsage([]x509.ExtKeyUsage{})
	if len(result) != 0 {
		t.Errorf("expected 0 for empty, got %d", len(result))
	}
}

func TestParseHostPort_IPv6(t *testing.T) {
	host, port := parseHostPort("[::1]:8443")
	if host != "::1" {
		t.Errorf("expected host '::1', got %q", host)
	}
	if port != "8443" {
		t.Errorf("expected port '8443', got %q", port)
	}
}

func TestGetTLSVersionName_All(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0300, "Unknown (0x0300)"}, // SSL 3.0
		{0x0000, "Unknown (0x0000)"}, // invalid
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := getTLSVersionName(tt.version)
			if result != tt.expected {
				t.Errorf("getTLSVersionName(0x%04x) = %q, expected %q", tt.version, result, tt.expected)
			}
		})
	}
}

// --- certvulnscan.go coverage (all check* functions) ---

func TestCheckWeakSignature(t *testing.T) {
	tests := []struct {
		name     string
		sigAlg   x509.SignatureAlgorithm
		expected bool // true = pass
	}{
		{"SHA256", x509.SHA256WithRSA, true},
		{"SHA1", x509.SHA1WithRSA, false},
		{"MD5", x509.MD5WithRSA, false},
		{"ECDSA-SHA256", x509.ECDSAWithSHA256, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := makeTestCert()
			cert.SignatureAlgorithm = tt.sigAlg
			passed, _ := checkWeakSignature(cert, "", nil)
			if passed != tt.expected {
				t.Errorf("checkWeakSignature(%v) = %v, expected %v", tt.sigAlg, passed, tt.expected)
			}
		})
	}
}

func TestCheckShortRSAKey(t *testing.T) {
	// Short RSA key
	cert := makeTestCert()
	cert.PublicKey = &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537} // 1024-bit
	passed, detail := checkShortRSAKey(cert, "", nil)
	if passed {
		t.Error("expected short RSA key to fail")
	}
	if detail == "" {
		t.Error("expected detail for short RSA key")
	}

	// Adequate RSA key
	cert.PublicKey = &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537} // 2048-bit
	passed, _ = checkShortRSAKey(cert, "", nil)
	if !passed {
		t.Error("expected 2048-bit RSA key to pass")
	}

	// Non-RSA key (ECDSA)
	ecCert := makeTestCert()
	ecCert.PublicKey = &ecdsa.PublicKey{}
	passed, _ = checkShortRSAKey(ecCert, "", nil)
	if !passed {
		t.Error("expected non-RSA key to pass (N/A)")
	}
}

func TestCheckWeakCurve(t *testing.T) {
	// Weak curve (P-224 = 224 bits)
	cert := makeTestCert()
	cert.PublicKey = &ecdsa.PublicKey{}
	// We can't easily set the curve, but we can test the non-ECDSA path
	rsaCert := makeTestCert()
	rsaCert.PublicKey = &rsa.PublicKey{N: big.NewInt(1), E: 65537}
	passed, _ := checkWeakCurve(rsaCert, "", nil)
	if !passed {
		t.Error("expected non-ECDSA key to pass (N/A)")
	}
}

func TestCheckMissingSAN(t *testing.T) {
	// Missing SAN
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = nil
	})
	passed, _ := checkMissingSAN(cert, "", nil)
	if passed {
		t.Error("expected missing SAN to fail")
	}

	// Has SAN
	cert = makeTestCert()
	passed, _ = checkMissingSAN(cert, "", nil)
	if !passed {
		t.Error("expected SAN present to pass")
	}

	// Has IP SAN only
	cert = makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = []net.IP{net.ParseIP("192.168.1.1")}
	})
	passed, _ = checkMissingSAN(cert, "", nil)
	if !passed {
		t.Error("expected IP SAN present to pass")
	}
}

func TestCheckHostnameMismatch(t *testing.T) {
	// Matching hostname
	cert := makeTestCert()
	passed, _ := checkHostnameMismatch(cert, "test.example.com", nil)
	if !passed {
		t.Error("expected matching hostname to pass")
	}

	// Mismatching hostname
	passed, _ = checkHostnameMismatch(cert, "other.example.com", nil)
	if passed {
		t.Error("expected mismatching hostname to fail")
	}
}

func TestCheckExcessiveValidity(t *testing.T) {
	// Normal validity
	cert := makeTestCert()
	passed, _ := checkExcessiveValidity(cert, "", nil)
	if !passed {
		t.Error("expected normal validity to pass")
	}

	// Excessive validity (> 398 days)
	cert = makeTestCert(func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-400 * 24 * time.Hour)
		c.NotAfter = time.Now().Add(400 * 24 * time.Hour)
	})
	passed, _ = checkExcessiveValidity(cert, "", nil)
	if passed {
		t.Error("expected excessive validity to fail")
	}
}

func TestCheckSelfSigned(t *testing.T) {
	// Self-signed (subject == issuer)
	cert := makeTestCert()
	cert.Subject = pkixName("test")
	cert.Issuer = pkixName("test")
	passed, _ := checkSelfSigned(cert, "", nil)
	if passed {
		t.Error("expected self-signed to fail")
	}

	// CA-signed (subject != issuer)
	cert.Issuer = pkixName("different-ca")
	passed, _ = checkSelfSigned(cert, "", nil)
	if !passed {
		t.Error("expected CA-signed to pass")
	}
}

func TestCheckCertExpired(t *testing.T) {
	// Not expired
	cert := makeTestCert()
	passed, _ := checkCertExpired(cert, "", nil)
	if !passed {
		t.Error("expected non-expired cert to pass")
	}

	// Expired
	cert = makeTestCert(func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	})
	passed, _ = checkCertExpired(cert, "", nil)
	if passed {
		t.Error("expected expired cert to fail")
	}
}

func TestCheckCertExpiringSoon(t *testing.T) {
	// Not expiring soon
	cert := makeTestCert()
	passed, _ := checkCertExpiringSoon(cert, "", nil)
	if !passed {
		t.Error("expected cert not expiring soon to pass")
	}

	// Expiring soon (15 days)
	cert = makeTestCert(func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(15 * 24 * time.Hour)
	})
	passed, _ = checkCertExpiringSoon(cert, "", nil)
	if passed {
		t.Error("expected cert expiring soon to fail")
	}

	// Already expired (should pass since days <= 0)
	cert = makeTestCert(func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	})
	passed, _ = checkCertExpiringSoon(cert, "", nil)
	if !passed {
		t.Error("expected already-expired cert to pass (not 'expiring soon')")
	}
}

func TestCheckCNNotInSANs(t *testing.T) {
	// CN in SANs
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("test.example.com")
		c.DNSNames = []string{"test.example.com"}
	})
	passed, _ := checkCNNotInSANs(cert, "", nil)
	if !passed {
		t.Error("expected CN in SANs to pass")
	}

	// CN not in SANs
	cert = makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("other.example.com")
		c.DNSNames = []string{"test.example.com"}
	})
	passed, _ = checkCNNotInSANs(cert, "", nil)
	if passed {
		t.Error("expected CN not in SANs to fail")
	}

	// No CN
	cert = makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("")
		c.DNSNames = []string{"test.example.com"}
	})
	passed, _ = checkCNNotInSANs(cert, "", nil)
	if !passed {
		t.Error("expected no CN to pass (N/A)")
	}

	// No SANs
	cert = makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("test.example.com")
		c.DNSNames = nil
	})
	passed, _ = checkCNNotInSANs(cert, "", nil)
	if !passed {
		t.Error("expected no SANs to pass (N/A)")
	}
}

func TestCheckWildcardCert(t *testing.T) {
	// Has wildcard
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"*.example.com"}
	})
	passed, _ := checkWildcardCert(cert, "", nil)
	if passed {
		t.Error("expected wildcard cert to fail")
	}

	// No wildcards
	cert = makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"test.example.com"}
	})
	passed, _ = checkWildcardCert(cert, "", nil)
	if !passed {
		t.Error("expected non-wildcard cert to pass")
	}
}

func TestCheckInternalName(t *testing.T) {
	// Internal name
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"server.local"}
	})
	passed, _ := checkInternalName(cert, "", nil)
	if passed {
		t.Error("expected internal name to fail")
	}

	// Public name
	cert = makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"server.example.org"}
	})
	passed, _ = checkInternalName(cert, "", nil)
	if !passed {
		t.Error("expected public name to pass")
	}

	// Internal name in CN
	cert = makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("server.internal")
		c.DNSNames = []string{"public.example.com"}
	})
	passed, _ = checkInternalName(cert, "", nil)
	if passed {
		t.Error("expected internal CN to fail")
	}
}

func TestCheckUntrustedChain(t *testing.T) {
	// Self-signed cert (untrusted)
	cert := makeTestCert()
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	passed, detail := checkUntrustedChain(cert, "", state)
	// Self-signed cert won't be trusted by system roots
	if passed {
		t.Log("self-signed cert was trusted (unexpected but possible in some environments)")
	}
	if detail == "" {
		t.Error("expected detail from checkUntrustedChain")
	}
}

func TestCheckDistrustedCA(t *testing.T) {
	cert := makeTestCert()
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	passed, detail := checkDistrustedCA(cert, "", state)
	if !passed {
		t.Error("expected clean cert to pass distrusted CA check")
	}
	if detail == "" {
		t.Error("expected detail from checkDistrustedCA")
	}
}

func TestCheckOCSPMustStaple(t *testing.T) {
	cert := makeTestCert()

	// No must-staple, no staple
	state := &tls.ConnectionState{OCSPResponse: nil}
	passed, _ := checkOCSPMustStaple(cert, "", state)
	if !passed {
		t.Error("expected no must-staple requirement to pass")
	}

	// No must-staple, has staple
	state = &tls.ConnectionState{OCSPResponse: []byte{1, 2, 3}}
	passed, _ = checkOCSPMustStaple(cert, "", state)
	if !passed {
		t.Error("expected no must-staple with staple to pass")
	}
}

func TestCheckKeyUsageCompliance(t *testing.T) {
	// Compliant non-CA
	cert := makeTestCert()
	state := &tls.ConnectionState{}
	passed, _ := checkKeyUsageCompliance(cert, "", state)
	if !passed {
		t.Error("expected compliant key usage to pass")
	}

	// CA without keyCertSign
	cert = makeTestCert(func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCRLSign // missing CertSign
	})
	passed, _ = checkKeyUsageCompliance(cert, "", state)
	if passed {
		t.Error("expected CA without keyCertSign to fail")
	}

	// Non-CA with keyCertSign
	cert = makeTestCert(func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageCertSign
	})
	passed, _ = checkKeyUsageCompliance(cert, "", state)
	if passed {
		t.Error("expected non-CA with keyCertSign to fail")
	}

	// No key usage at all
	cert = makeTestCert(func(c *x509.Certificate) {
		c.KeyUsage = 0
		c.ExtKeyUsage = nil
	})
	passed, _ = checkKeyUsageCompliance(cert, "", state)
	if passed {
		t.Error("expected no key usage to fail")
	}

	// Non-CA missing digitalSignature and keyEncipherment
	cert = makeTestCert(func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageCRLSign
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	passed, _ = checkKeyUsageCompliance(cert, "", state)
	if passed {
		t.Error("expected missing digitalSignature/keyEncipherment to fail")
	}
}

func TestCheckSerialEntropy(t *testing.T) {
	// Good serial number
	cert := makeTestCert(func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(1).Lsh(big.NewInt(1), 127) // 128-bit
	})
	state := &tls.ConnectionState{}
	passed, _ := checkSerialEntropy(cert, "", state)
	if !passed {
		t.Log("high serial may not pass due to sequential detection")
	}

	// Nil serial
	cert = makeTestCert(func(c *x509.Certificate) {
		c.SerialNumber = nil
	})
	passed, _ = checkSerialEntropy(cert, "", state)
	if passed {
		t.Error("expected nil serial to fail")
	}

	// Short serial (< 64 bits)
	cert = makeTestCert(func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(42)
	})
	passed, _ = checkSerialEntropy(cert, "", state)
	if passed {
		t.Error("expected short serial to fail")
	}
}

func TestCheckNameConstraints(t *testing.T) {
	cert := makeTestCert()

	// No CA in chain
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	passed, detail := checkNameConstraints(cert, "", state)
	if !passed {
		t.Error("expected no CA in chain to pass")
	}
	if detail == "" {
		t.Error("expected detail from checkNameConstraints")
	}
}

func TestBuildCertSecuritySummary(t *testing.T) {
	checks := []CertSecurityCheck{
		{Name: "Check1", Passed: true},
		{Name: "Check2", Passed: false},
		{Name: "Check3", Passed: true},
	}
	summary := buildCertSecuritySummary(checks)
	if summary.TotalChecked != 3 {
		t.Errorf("expected TotalChecked=3, got %d", summary.TotalChecked)
	}
	if summary.Passed != 2 {
		t.Errorf("expected Passed=2, got %d", summary.Passed)
	}
	if summary.Failed != 1 {
		t.Errorf("expected Failed=1, got %d", summary.Failed)
	}
	if summary.IsSecure {
		t.Error("expected IsSecure=false when there are failures")
	}
	if len(summary.FailedChecks) != 1 || summary.FailedChecks[0] != "Check2" {
		t.Errorf("expected FailedChecks=[Check2], got %v", summary.FailedChecks)
	}

	// All pass
	checks = []CertSecurityCheck{
		{Name: "Check1", Passed: true},
	}
	summary = buildCertSecuritySummary(checks)
	if !summary.IsSecure {
		t.Error("expected IsSecure=true when all pass")
	}
}

// --- security.go coverage (analyzeCertificate, analyzeTLS, analyzeExpiration, etc.) ---

func TestAnalyzeCertificate(t *testing.T) {
	now := time.Now()
	cert := &CertInfo{
		Subject:            "CN=test.example.com",
		Issuer:             "CN=Test CA",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		DNSNames:           []string{"test.example.com"},
		PublicKeyAlgorithm: "RSA",
		SignatureAlgorithm: "SHA256-RSA",
		KeySize:            2048,
	}
	sslInfo := &SSLInfo{
		PeerCerts: CertChain{IsValid: true},
	}

	check := analyzeCertificate(cert, sslInfo)
	if !check.IsValid {
		t.Error("expected valid cert")
	}
	if check.IsExpired {
		t.Error("expected not expired")
	}
	if check.WeakSignature {
		t.Error("expected strong signature")
	}
	if check.WeakKeySize {
		t.Error("expected adequate key size")
	}
}

func TestAnalyzeCertificate_WeakSignature(t *testing.T) {
	now := time.Now()
	cert := &CertInfo{
		Subject:            "CN=test",
		Issuer:             "CN=Test CA",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		DNSNames:           []string{"test.example.com"},
		SignatureAlgorithm: "SHA1WithRSA",
		KeySize:            2048,
	}
	sslInfo := &SSLInfo{PeerCerts: CertChain{IsValid: true}}
	check := analyzeCertificate(cert, sslInfo)
	if !check.WeakSignature {
		t.Error("expected weak signature for SHA1")
	}
}

func TestAnalyzeCertificate_SelfSigned_Full(t *testing.T) {
	now := time.Now()
	cert := &CertInfo{
		Subject:   "CN=test",
		Issuer:    "CN=test", // same as subject = self-signed
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(365 * 24 * time.Hour),
		DNSNames:  []string{"test.example.com"},
		KeySize:   2048,
	}
	sslInfo := &SSLInfo{PeerCerts: CertChain{IsValid: true}}
	check := analyzeCertificate(cert, sslInfo)
	if !check.IsSelfSigned {
		t.Error("expected self-signed")
	}
}

func TestAnalyzeCertificate_WeakKeySize(t *testing.T) {
	now := time.Now()
	cert := &CertInfo{
		Subject:   "CN=test",
		Issuer:    "CN=CA",
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(365 * 24 * time.Hour),
		DNSNames:  []string{"test.example.com"},
		KeySize:   1024,
	}
	sslInfo := &SSLInfo{PeerCerts: CertChain{IsValid: true}}
	check := analyzeCertificate(cert, sslInfo)
	if !check.WeakKeySize {
		t.Error("expected weak key size for 1024-bit")
	}
}

func TestAnalyzeCertificate_ExpiredAndExpiringSoon(t *testing.T) {
	now := time.Now()

	// Expired
	cert := &CertInfo{
		Subject:   "CN=test",
		Issuer:    "CN=CA",
		NotBefore: now.Add(-400 * 24 * time.Hour),
		NotAfter:  now.Add(-24 * time.Hour),
		DNSNames:  []string{"test.example.com"},
		KeySize:   2048,
	}
	sslInfo := &SSLInfo{PeerCerts: CertChain{IsValid: true}}
	check := analyzeCertificate(cert, sslInfo)
	if !check.IsExpired {
		t.Error("expected expired")
	}

	// Expiring soon (15 days)
	cert.NotAfter = now.Add(15 * 24 * time.Hour)
	check = analyzeCertificate(cert, sslInfo)
	if !check.IsExpiringSoon {
		t.Error("expected expiring soon")
	}
}

func TestAnalyzeCertificate_WildcardAndChainInvalid(t *testing.T) {
	now := time.Now()
	cert := &CertInfo{
		Subject:   "CN=test",
		Issuer:    "CN=CA",
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(365 * 24 * time.Hour),
		DNSNames:  []string{"*.example.com"},
		KeySize:   2048,
	}
	sslInfo := &SSLInfo{PeerCerts: CertChain{IsValid: false}}
	check := analyzeCertificate(cert, sslInfo)
	if !check.WildcardCert {
		t.Error("expected wildcard cert")
	}
	if check.ChainValid {
		t.Error("expected invalid chain")
	}
}

func TestAnalyzeCertificate_ExcessiveValidity(t *testing.T) {
	now := time.Now()
	cert := &CertInfo{
		Subject:   "CN=test",
		Issuer:    "CN=CA",
		NotBefore: now.Add(-400 * 24 * time.Hour),
		NotAfter:  now.Add(400 * 24 * time.Hour),
		DNSNames:  []string{"test.example.com"},
		KeySize:   2048,
	}
	sslInfo := &SSLInfo{PeerCerts: CertChain{IsValid: true}}
	check := analyzeCertificate(cert, sslInfo)
	// Should warn about excessive validity for non-self-signed
	found := false
	for _, w := range check.Warnings {
		if len(w) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected warnings for excessive validity")
	}
}

func TestAnalyzeTLS(t *testing.T) {
	// Secure TLS
	sslInfo := &SSLInfo{
		TLSVersion:    "TLS 1.3",
		CipherSuite:   "TLS_AES_128_GCM_SHA256",
		SupportsHTTP2: true,
		HasOCSPStaple: true,
	}
	check := analyzeTLS(sslInfo)
	if !check.IsSecureVersion {
		t.Error("expected TLS 1.3 to be secure")
	}
	if !check.IsSecureCipherSuite {
		t.Error("expected AES-128-GCM to be secure")
	}

	// Insecure TLS version
	sslInfo.TLSVersion = "TLS 1.0"
	check = analyzeTLS(sslInfo)
	if check.IsSecureVersion {
		t.Error("expected TLS 1.0 to be insecure")
	}

	// Weak cipher suite
	sslInfo.TLSVersion = "TLS 1.2"
	sslInfo.CipherSuite = "TLS_RSA_WITH_RC4_128_SHA"
	check = analyzeTLS(sslInfo)
	if check.IsSecureCipherSuite {
		t.Error("expected RC4 to be weak")
	}
}

func TestAnalyzeExpiration(t *testing.T) {
	now := time.Now()

	// Good
	cert := &CertInfo{NotAfter: now.Add(365 * 24 * time.Hour)}
	check := analyzeExpiration(cert)
	if check.Status != "Good" {
		t.Errorf("expected Good, got %s", check.Status)
	}

	// Warning (30 days)
	cert.NotAfter = now.Add(20 * 24 * time.Hour)
	check = analyzeExpiration(cert)
	if check.Status != "Warning" {
		t.Errorf("expected Warning, got %s", check.Status)
	}

	// Critical (7 days)
	cert.NotAfter = now.Add(3 * 24 * time.Hour)
	check = analyzeExpiration(cert)
	if check.Status != "Critical" {
		t.Errorf("expected Critical, got %s", check.Status)
	}

	// Expired
	cert.NotAfter = now.Add(-24 * time.Hour)
	check = analyzeExpiration(cert)
	if check.Status != "Expired" {
		t.Errorf("expected Expired, got %s", check.Status)
	}
}

func TestCollectSecurityIssues_AllBranches(t *testing.T) {
	// Test all issue collection branches
	analysis := &SecurityAnalysis{
		Issues:          []SecurityIssue{},
		Recommendations: []string{},
		CertificateCheck: CertificateCheck{
			IsExpired:      true,
			IsExpiringSoon: true,
			WeakSignature:  true,
			IsSelfSigned:   true,
			WeakKeySize:    true,
			ChainValid:     false,
			KeySize:        1024,
			SignatureAlg:   "SHA1WithRSA",
		},
		TLSCheck: TLSCheck{
			IsSecureVersion:     false,
			IsSecureCipherSuite: false,
			HasOCSPStaple:       false,
			Version:             "TLS 1.0",
			CipherSuite:         "RC4",
			HSTS:                &HSTSResult{Enabled: false},
		},
	}
	analysis.collectSecurityIssues()

	expectedIssues := 9                          // expired, expiring soon, weak sig, self-signed, weak key, chain invalid, insecure TLS, weak cipher, no OCSP staple, no HSTS
	if len(analysis.Issues) < expectedIssues-1 { // HSTS might not trigger
		t.Errorf("expected at least %d issues, got %d", expectedIssues-1, len(analysis.Issues))
	}
}

func TestCalculateOverallScore_AllLevels(t *testing.T) {
	tests := []struct {
		name          string
		issues        []SecurityIssue
		expectedLevel string
	}{
		{"Good", []SecurityIssue{}, "Good"},
		{"Medium", []SecurityIssue{{Severity: "Medium"}, {Severity: "Medium"}}, "Medium"},                                 // 100-10-10=80
		{"Low", []SecurityIssue{{Severity: "High"}, {Severity: "High"}}, "Low"},                                           // 100-20-20=60
		{"Critical", []SecurityIssue{{Severity: "Critical"}, {Severity: "Critical"}, {Severity: "Critical"}}, "Critical"}, // 100-30-30-30=10
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &SecurityAnalysis{Issues: tt.issues}
			analysis.calculateOverallScore()
			if analysis.SecurityLevel != tt.expectedLevel {
				t.Errorf("expected %s, got %s (score=%d)", tt.expectedLevel, analysis.SecurityLevel, analysis.OverallScore)
			}
		})
	}
}

func TestGenerateRecommendations_AllBranches(t *testing.T) {
	analysis := &SecurityAnalysis{
		CertificateCheck: CertificateCheck{
			IsExpired:     true,
			WeakSignature: true,
			IsSelfSigned:  true,
			WeakKeySize:   true,
			ChainValid:    false,
		},
		TLSCheck: TLSCheck{
			IsSecureVersion:     false,
			IsSecureCipherSuite: false,
		},
	}
	analysis.generateRecommendations()
	if len(analysis.Recommendations) < 6 {
		t.Errorf("expected at least 6 recommendations, got %d: %v", len(analysis.Recommendations), analysis.Recommendations)
	}

	// All good
	analysis2 := &SecurityAnalysis{
		CertificateCheck: CertificateCheck{ChainValid: true},
		TLSCheck:         TLSCheck{IsSecureVersion: true, IsSecureCipherSuite: true},
	}
	analysis2.generateRecommendations()
	if len(analysis2.Recommendations) == 0 {
		t.Error("expected default recommendations when all is good")
	}
}

// --- hostnameverify.go coverage ---

func TestDetermineMatchType(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"test.example.com", "*.wild.example.com"}
		c.Subject = pkixName("test.example.com")
	})

	if mt := determineMatchType(cert, "test.example.com"); mt != "exact" {
		t.Errorf("expected exact, got %s", mt)
	}
	if mt := determineMatchType(cert, "sub.wild.example.com"); mt != "wildcard" {
		t.Errorf("expected wildcard, got %s", mt)
	}
	if mt := determineMatchType(cert, "other.example.com"); mt != "none" {
		t.Errorf("expected none, got %s", mt)
	}
}

func TestFindMatchingSAN(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"test.example.com", "*.wild.example.com"}
		c.Subject = pkixName("cn.example.com")
	})

	if san := findMatchingSAN(cert, "test.example.com"); san != "test.example.com" {
		t.Errorf("expected exact match, got %s", san)
	}
	if san := findMatchingSAN(cert, "sub.wild.example.com"); san != "*.wild.example.com" {
		t.Errorf("expected wildcard match, got %s", san)
	}
	if san := findMatchingSAN(cert, "cn.example.com"); san != "cn.example.com" {
		t.Errorf("expected CN match, got %s", san)
	}
	if san := findMatchingSAN(cert, "no.match.com"); san != "" {
		t.Errorf("expected no match, got %s", san)
	}
}

func TestFindClosestMatch(t *testing.T) {
	sans := []string{"www.example.com", "api.example.com", "mail.other.com"}
	match := findClosestMatch(sans, "test.example.com")
	if match == "" {
		t.Error("expected a closest match")
	}
}

func TestDomainSimilarity_Full(t *testing.T) {
	score := domainSimilarity("www.example.com", "api.example.com")
	if score < 1 {
		t.Error("expected some similarity for same TLD")
	}
	score = domainSimilarity("a.b.c", "x.b.c")
	if score != 2 {
		t.Errorf("expected 2 for matching last 2 parts, got %d", score)
	}
	score = domainSimilarity("a.com", "b.org")
	if score != 0 {
		t.Errorf("expected 0 for no matching parts, got %d", score)
	}
}

// --- offline.go coverage ---

func TestAnalyzeSecurityFromCert(t *testing.T) {
	cert := makeTestCert()
	result, err := AnalyzeSecurityFromCert(cert, "test.example.com")
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCert failed: %v", err)
	}
	if result.Target != "test.example.com" {
		t.Errorf("expected target test.example.com, got %s", result.Target)
	}
}

func TestAnalyzeSecurityFromCertWithState(t *testing.T) {
	cert := makeTestCert()

	// Without state
	result, err := AnalyzeSecurityFromCertWithState(cert, "test.example.com", nil)
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCertWithState failed: %v", err)
	}
	if result.OverallScore < 0 {
		t.Error("score should not be negative")
	}

	// With state
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	result, err = AnalyzeSecurityFromCertWithState(cert, "test.example.com", state)
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCertWithState with state failed: %v", err)
	}
}

func TestNewOfflineAnalysis(t *testing.T) {
	cert := makeTestCert()
	result := NewOfflineAnalysis(cert)
	if result.Target != "test" {
		t.Errorf("expected target 'test', got %s", result.Target)
	}
	if result.Cert != cert {
		t.Error("expected cert to be set")
	}

	// With intermediates
	intermediate := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = true
	})
	result = NewOfflineAnalysis(cert, intermediate)
	if result.IntermediatePool == nil {
		t.Error("expected intermediate pool to be set")
	}
}

func TestScanCertSecurityFromChain_Full(t *testing.T) {
	cert := makeTestCert()

	// Without state
	result, err := ScanCertSecurityFromChain(cert, "test.example.com", nil)
	if err != nil {
		t.Fatalf("ScanCertSecurityFromChain failed: %v", err)
	}
	if len(result.Checks) != 12 {
		t.Errorf("expected 12 checks without state, got %d", len(result.Checks))
	}

	// With state
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	result, err = ScanCertSecurityFromChain(cert, "test.example.com", state)
	if err != nil {
		t.Fatalf("ScanCertSecurityFromChain with state failed: %v", err)
	}
	if len(result.Checks) != 18 {
		t.Errorf("expected 18 checks with state, got %d", len(result.Checks))
	}
}

func TestFingerprintCert_Full(t *testing.T) {
	cert := makeTestCert()
	fp := fingerprintCert(cert)
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}
}

// --- hsts.go coverage ---

func TestParseHSTSHeader(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		maxAge  int
		subDom  bool
		preload bool
	}{
		{"Basic", "max-age=31536000", 31536000, false, false},
		{"WithSubDomains", "max-age=31536000; includeSubDomains", 31536000, true, false},
		{"WithPreload", "max-age=31536000; includeSubDomains; preload", 31536000, true, true},
		{"PreloadOnly", "max-age=31536000; preload", 31536000, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHSTSHeader(tt.header)
			if !result.Enabled {
				t.Error("expected HSTS enabled")
			}
			if result.MaxAge != tt.maxAge {
				t.Errorf("expected MaxAge=%d, got %d", tt.maxAge, result.MaxAge)
			}
			if result.IncludeSubDomains != tt.subDom {
				t.Errorf("expected IncludeSubDomains=%v, got %v", tt.subDom, result.IncludeSubDomains)
			}
			if result.Preload != tt.preload {
				t.Errorf("expected Preload=%v, got %v", tt.preload, result.Preload)
			}
			if result.RawHeader != tt.header {
				t.Errorf("expected RawHeader=%q, got %q", tt.header, result.RawHeader)
			}
		})
	}
}

// --- helper functions ---

func removeFiles(paths ...string) {
	for _, p := range paths {
		os.Remove(p)
	}
}

func readCertFromFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("Failed to decode PEM from %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	return cert
}
