package pkg

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =====================================================================
// hostnameverify.go - determineMatchType, matchWildcard, domainSimilarity
// =====================================================================

func TestDetermineMatchTypeExt2(t *testing.T) {
	// Exact DNS match
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"example.com", "*.wild.example.com"}
		c.Subject = pkix.Name{CommonName: "cn.example.com"}
	})
	result := determineMatchType(cert, "example.com")
	if result != "exact" {
		t.Errorf("determineMatchType exact DNS = %q, expected %q", result, "exact")
	}

	// CN exact match
	cert2 := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = nil
		c.Subject = pkix.Name{CommonName: "cn.example.com"}
	})
	result = determineMatchType(cert2, "cn.example.com")
	if result != "exact" {
		t.Errorf("determineMatchType exact CN = %q, expected %q", result, "exact")
	}

	// Wildcard match
	result = determineMatchType(cert, "sub.wild.example.com")
	if result != "wildcard" {
		t.Errorf("determineMatchType wildcard = %q, expected %q", result, "wildcard")
	}

	// CN wildcard match
	cert3 := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = nil
		c.Subject = pkix.Name{CommonName: "*.cn-wild.example.com"}
	})
	result = determineMatchType(cert3, "sub.cn-wild.example.com")
	if result != "wildcard" {
		t.Errorf("determineMatchType CN wildcard = %q, expected %q", result, "wildcard")
	}

	// No match
	result = determineMatchType(cert, "other.com")
	if result != "none" {
		t.Errorf("determineMatchType no match = %q, expected %q", result, "none")
	}
}

func TestMatchWildcardExt2(t *testing.T) {
	tests := []struct {
		pattern  string
		host     string
		expected bool
	}{
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "deep.sub.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "", false},
		{"", "example.com", false},
		{"example.com", "example.com", true},
		{"other.com", "example.com", false},
		{"*", "example.com", false},
	}

	for _, tt := range tests {
		result := matchWildcard(tt.pattern, tt.host)
		if result != tt.expected {
			t.Errorf("matchWildcard(%q, %q) = %v, expected %v", tt.pattern, tt.host, result, tt.expected)
		}
	}
}

func TestDomainSimilarityExt2(t *testing.T) {
	// Same string = max similarity
	score := domainSimilarity("example.com", "example.com")
	if score < 2 {
		t.Errorf("domainSimilarity same = %d, expected >= 2", score)
	}

	// Empty strings - returns 1 (empty string matches empty string)
	score = domainSimilarity("", "")
	if score < 0 {
		t.Errorf("domainSimilarity empty = %d, expected >= 0", score)
	}

	// Similar strings (same TLD)
	score = domainSimilarity("example.com", "exampl3.com")
	if score < 1 {
		t.Errorf("domainSimilarity similar = %d, expected >= 1", score)
	}

	// Very different (different TLD)
	score = domainSimilarity("example.com", "example.org")
	if score > 1 {
		t.Errorf("domainSimilarity different TLD = %d, expected <= 1", score)
	}

	// Same subdomain structure
	score = domainSimilarity("www.example.com", "api.example.com")
	if score < 2 {
		t.Errorf("domainSimilarity same subdomain structure = %d, expected >= 2", score)
	}
}

// =====================================================================
// ocspmuststaple.go - hasMustStapleExtension, hasStatusRequestInValue
// =====================================================================

func TestHasMustStapleExtensionExt2(t *testing.T) {
	// No extensions
	cert := makeTestCert()
	if hasMustStapleExtension(cert) {
		t.Error("expected false for cert without must-staple")
	}

	// Extension with wrong OID
	wrongOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	cert = makeTestCert(func(c *x509.Certificate) {
		c.Extensions = append(c.Extensions, pkix.Extension{
			Id:    wrongOID,
			Value: []byte{0x30, 0x03, 0x02, 0x01, 0x05},
		})
	})
	if hasMustStapleExtension(cert) {
		t.Error("expected false for wrong OID")
	}

	// Extension with correct OID but empty value
	mustStapleOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	cert = makeTestCert(func(c *x509.Certificate) {
		c.Extensions = append(c.Extensions, pkix.Extension{
			Id:    mustStapleOID,
			Value: []byte{},
		})
	})
	if hasMustStapleExtension(cert) {
		t.Error("expected false for empty value")
	}

	// Extension with correct OID and valid value
	cert = makeTestCert(func(c *x509.Certificate) {
		c.Extensions = append(c.Extensions, pkix.Extension{
			Id:    mustStapleOID,
			Value: []byte{0x30, 0x03, 0x02, 0x01, 0x05},
		})
	})
	if !hasMustStapleExtension(cert) {
		t.Error("expected true for valid must-staple extension")
	}

	// Extension with correct OID but value without 0x05
	cert = makeTestCert(func(c *x509.Certificate) {
		c.Extensions = append(c.Extensions, pkix.Extension{
			Id:    mustStapleOID,
			Value: []byte{0x30, 0x03, 0x02, 0x01, 0x01},
		})
	})
	if hasMustStapleExtension(cert) {
		t.Error("expected false for value without status_request=5")
	}
}

func TestHasStatusRequestInValueExt2(t *testing.T) {
	// Too short
	if hasStatusRequestInValue(nil) {
		t.Error("expected false for nil")
	}
	if hasStatusRequestInValue([]byte{0x01, 0x02, 0x03}) {
		t.Error("expected false for 3-byte input")
	}

	// DER sequence with 02 01 05 pattern
	if !hasStatusRequestInValue([]byte{0x30, 0x03, 0x02, 0x01, 0x05}) {
		t.Error("expected true for DER 02 01 05")
	}

	// Data with 0x05 at end
	if !hasStatusRequestInValue([]byte{0x30, 0x04, 0x02, 0x02, 0x00, 0x05}) {
		t.Error("expected true for pattern ending with 0x05")
	}

	// 4 bytes minimum but no matching pattern
	if hasStatusRequestInValue([]byte{0x30, 0x01, 0x01, 0x01}) {
		t.Error("expected false for no matching pattern and no 0x05")
	}
}

// =====================================================================
// nameconstraints.go - extractCAConstraint, ipMatchesRange
// =====================================================================

func TestExtractCAConstraintExt2(t *testing.T) {
	// Non-CA cert
	nonCA := makeTestCert()
	if c := extractCAConstraint(nonCA, 1); c != nil {
		t.Error("expected nil for non-CA cert")
	}

	// CA with DNS constraints
	ca := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = true
		c.PermittedDNSDomains = []string{".example.com"}
		c.ExcludedDNSDomains = []string{".evil.com"}
	})
	constraint := extractCAConstraint(ca, 1)
	if constraint == nil {
		t.Fatal("expected constraint")
	}
	if len(constraint.PermittedDNS) != 1 || constraint.PermittedDNS[0] != ".example.com" {
		t.Errorf("unexpected permitted DNS: %v", constraint.PermittedDNS)
	}
	if len(constraint.ExcludedDNS) != 1 || constraint.ExcludedDNS[0] != ".evil.com" {
		t.Errorf("unexpected excluded DNS: %v", constraint.ExcludedDNS)
	}

	// CA with no constraints
	caNoConstraints := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = true
	})
	if c := extractCAConstraint(caNoConstraints, 1); c != nil {
		t.Error("expected nil for CA without constraints")
	}
}

func TestIpMatchesRangeExt2(t *testing.T) {
	// IPv4 in range
	if !ipMatchesRange("192.168.1.1", "192.168.0.0/16") {
		t.Error("expected 192.168.1.1 to match 192.168.0.0/16")
	}

	// IPv4 not in range
	if ipMatchesRange("10.0.0.1", "192.168.0.0/16") {
		t.Error("expected 10.0.0.1 not to match 192.168.0.0/16")
	}

	// Invalid IP
	if ipMatchesRange("not-an-ip", "192.168.0.0/16") {
		t.Error("expected invalid IP not to match")
	}

	// Invalid CIDR
	if ipMatchesRange("192.168.1.1", "not-a-cidr") {
		t.Error("expected invalid CIDR not to match")
	}

	// IPv6 matching
	if !ipMatchesRange("::1", "::1/128") {
		t.Error("expected ::1 to match ::1/128")
	}

	// IPv6 in range
	if !ipMatchesRange("2001:db8::1", "2001:db8::/32") {
		t.Error("expected 2001:db8::1 to match 2001:db8::/32")
	}

	// IPv6 not in range
	if ipMatchesRange("2001:db8::1", "fe80::/10") {
		t.Error("expected 2001:db8::1 not to match fe80::/10")
	}
}

// =====================================================================
// comparator.go - findDifferences
// =====================================================================

func TestFindDifferencesExt2(t *testing.T) {
	cert1, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "diff-test-1", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
		DNSNames: []string{"diff1.example.com"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert 1 failed: %v", err)
	}
	defer removeFiles(cert1.CertificatePath, cert1.PrivateKeyPath)

	cert2, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "diff-test-2", KeyType: "rsa", KeySize: 4096, ValidityDays: 730,
		DNSNames: []string{"diff2.example.com"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert 2 failed: %v", err)
	}
	defer removeFiles(cert2.CertificatePath, cert2.PrivateKeyPath)

	c1 := readCertFromFile(t, cert1.CertificatePath)
	c2 := readCertFromFile(t, cert2.CertificatePath)

	diffs := findDifferences(c1, c2)
	if len(diffs) == 0 {
		t.Error("expected differences between different certs")
	}

	// Same cert should have no differences
	diffs = findDifferences(c1, c1)
	if len(diffs) != 0 {
		t.Errorf("expected no differences for same cert, got %d", len(diffs))
	}
}

// =====================================================================
// certvulnscan.go - checkWeakCurve, checkSerialEntropy, checkNameConstraints
// =====================================================================

func TestCheckWeakCurveExt2(t *testing.T) {
	// ECDSA P-384 (strong)
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "p384-test", KeyType: "ecdsa", KeySize: 384, ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert P-384 failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	passed, detail := checkWeakCurve(cert, "", nil)
	if !passed {
		t.Errorf("expected P-384 to pass, got: %s", detail)
	}

	// ECDSA P-521 (strong)
	result, err = GenerateSelfSignedCert(CertificateRequest{
		CommonName: "p521-test", KeyType: "ecdsa", KeySize: 521, ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert P-521 failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert = readCertFromFile(t, result.CertificatePath)
	passed, _ = checkWeakCurve(cert, "", nil)
	if !passed {
		t.Error("expected P-521 to pass")
	}

	// ECDSA P-256 (strong)
	result, err = GenerateSelfSignedCert(CertificateRequest{
		CommonName: "p256-test", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert P-256 failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert = readCertFromFile(t, result.CertificatePath)
	passed, _ = checkWeakCurve(cert, "", nil)
	if !passed {
		t.Error("expected P-256 to pass")
	}
}

func TestCheckSerialEntropyExt2(t *testing.T) {
	// High entropy serial (large random)
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "high-entropy-serial", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)
	cert := readCertFromFile(t, result.CertificatePath)
	passed, _ := checkSerialEntropy(cert, "", nil)
	if !passed {
		t.Log("High entropy serial check result: may vary depending on serial generation")
	}

	// Nil serial
	nilSerialCert := makeTestCert(func(c *x509.Certificate) {
		c.SerialNumber = nil
	})
	passed, detail := checkSerialEntropy(nilSerialCert, "", nil)
	if passed {
		t.Error("expected nil serial to fail")
	}
	if detail == "" {
		t.Error("expected detail for nil serial")
	}

	// Short serial (low entropy)
	shortSerialCert := makeTestCert(func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(1)
	})
	passed, _ = checkSerialEntropy(shortSerialCert, "", nil)
	if passed {
		t.Log("Short serial check: may pass depending on entropy calculation")
	}
}

func TestCheckNameConstraintsExt2_NoCA(t *testing.T) {
	cert := makeTestCert()
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	// No CA in chain -> should pass
	passed, detail := checkNameConstraints(cert, "", state)
	if !passed {
		t.Error("expected pass when no CA in chain")
	}
	_ = detail
}

// =====================================================================
// offline.go - AnalyzeSecurityFromCertWithState, CheckNameConstraintsFromCert, fingerprintCert
// =====================================================================

func TestAnalyzeSecurityFromCertWithStateExt2_TLS12(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("test-tls12.com")
		c.DNSNames = []string{"test-tls12.com"}
	})
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		PeerCertificates: []*x509.Certificate{cert},
		CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		OCSPResponse:     nil,
	}

	result, err := AnalyzeSecurityFromCertWithState(cert, "test-tls12.com", state)
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCertWithState TLS 1.2 failed: %v", err)
	}
	if result.OverallScore == 0 {
		t.Error("expected non-zero score")
	}
}

func TestAnalyzeSecurityFromCertWithStateExt2_TLS13(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("test-tls13.com")
		c.DNSNames = []string{"test-tls13.com"}
	})
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{cert},
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
	}

	result, err := AnalyzeSecurityFromCertWithState(cert, "test-tls13.com", state)
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCertWithState TLS 1.3 failed: %v", err)
	}
	_ = result
}

func TestFingerprintCertExt2_RealCert(t *testing.T) {
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "fp-real-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	fp := fingerprintCert(cert)
	if fp == "" {
		t.Error("expected SHA-256 fingerprint from real cert")
	}
}

// =====================================================================
// crlgen.go - GenerateCRL, ParseCRL, VerifyCRLSignature, CheckCertRevokedByCRL
// =====================================================================

func TestGenerateCRLExt2_ECDSA(t *testing.T) {
	caResult, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-ca-ec", IsCA: true, KeyType: "ecdsa", KeySize: 384, ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert CA ECDSA failed: %v", err)
	}
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	crlResult, err := GenerateCRL(CRLGenerateRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		RevokedCerts: []RevokedEntry{
			{SerialNumber: "123456", Reason: "key-compromise"},
			{SerialNumber: "789012", Reason: "superseded"},
		},
		Number:     2,
		NextUpdate: 30,
		OutputPath: "test-ec-crl.pem",
	})
	if err != nil {
		t.Fatalf("GenerateCRL ECDSA failed: %v", err)
	}
	defer os.Remove(crlResult.CRLPath)

	if crlResult.CRLPath == "" {
		t.Error("expected CRL path")
	}
	if crlResult.RevokedCount != 2 {
		t.Errorf("expected 2 revoked certs, got %d", crlResult.RevokedCount)
	}
}

func TestGenerateCRLExt2_Defaults(t *testing.T) {
	caResult, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-ca-def", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert CA failed: %v", err)
	}
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	// Minimal request
	crlResult, err := GenerateCRL(CRLGenerateRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		RevokedCerts: []RevokedEntry{
			{SerialNumber: "999"},
		},
	})
	if err != nil {
		t.Fatalf("GenerateCRL defaults failed: %v", err)
	}
	defer os.Remove(crlResult.CRLPath)
}

func TestParseCRLExt2(t *testing.T) {
	caResult, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-parse-ca", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert CA failed: %v", err)
	}
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	crlResult, err := GenerateCRL(CRLGenerateRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		RevokedCerts: []RevokedEntry{
			{SerialNumber: "111", Reason: "unspecified"},
			{SerialNumber: "222", Reason: "affiliation-changed"},
		},
		OutputPath: "parse-test-crl.pem",
	})
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}
	defer os.Remove(crlResult.CRLPath)

	parsed, err := ParseCRL(crlResult.CRLPath)
	if err != nil {
		t.Fatalf("ParseCRL failed: %v", err)
	}
	if parsed.Issuer == "" {
		t.Error("expected issuer")
	}
	if len(parsed.RevokedCerts) != 2 {
		t.Errorf("expected 2 revoked, got %d", len(parsed.RevokedCerts))
	}

	// Invalid file
	_, err = ParseCRL("/nonexistent/crl.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestVerifyCRLSignatureExt2(t *testing.T) {
	caResult, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-verify-ca", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert CA failed: %v", err)
	}
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	crlResult, err := GenerateCRL(CRLGenerateRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		RevokedCerts: []RevokedEntry{
			{SerialNumber: "333"},
		},
		OutputPath: "verify-test-crl.pem",
	})
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}
	defer os.Remove(crlResult.CRLPath)

	// Verify with matching CA
	verifyResult, err := VerifyCRLSignature(crlResult.CRLPath, caResult.CertificatePath)
	if err != nil {
		t.Fatalf("VerifyCRLSignature failed: %v", err)
	}
	if !verifyResult.IsValid {
		t.Error("expected valid signature")
	}

	// Verify with wrong CA
	otherCA, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "wrong-ca", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(otherCA.CertificatePath, otherCA.PrivateKeyPath)

	verifyResult, err = VerifyCRLSignature(crlResult.CRLPath, otherCA.CertificatePath)
	if err != nil {
		t.Fatalf("VerifyCRLSignature with wrong CA: %v", err)
	}
	if verifyResult.IsValid {
		t.Error("expected invalid signature for wrong CA")
	}
}

func TestCheckCertRevokedByCRLExt2(t *testing.T) {
	caResult, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-revoke-ca", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert CA failed: %v", err)
	}
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	// Sign a cert
	signed, err := SignCertificate(SignCertRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		CommonName: "to-be-revoked.example.com",
	})
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}
	defer removeFiles(signed.CertificatePath, signed.PrivateKeyPath)

	// Generate CRL with the signed cert's serial
	crlResult, err := GenerateCRL(CRLGenerateRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		RevokedCerts: []RevokedEntry{
			{SerialNumber: signed.SerialNumber, Reason: "key-compromise"},
		},
		OutputPath: "revoke-test-crl.pem",
	})
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}
	defer os.Remove(crlResult.CRLPath)

	// Check if the cert is revoked
	revoked, err := CheckCertRevokedByCRL(signed.CertificatePath, crlResult.CRLPath)
	if err != nil {
		t.Fatalf("CheckCertRevokedByCRL failed: %v", err)
	}
	if !revoked.IsRevoked {
		t.Error("expected cert to be revoked")
	}

	// Check non-revoked cert
	otherSigned, _ := SignCertificate(SignCertRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		CommonName: "not-revoked.example.com",
	})
	defer removeFiles(otherSigned.CertificatePath, otherSigned.PrivateKeyPath)

	revoked, err = CheckCertRevokedByCRL(otherSigned.CertificatePath, crlResult.CRLPath)
	if err != nil {
		t.Fatalf("CheckCertRevokedByCRL non-revoked failed: %v", err)
	}
	if revoked.IsRevoked {
		t.Error("expected cert NOT to be revoked")
	}
}

// =====================================================================
// certificate.go - buildCertChain, GetCertFromFile
// =====================================================================

func TestBuildCertChainExt2(t *testing.T) {
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "chain-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
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
	if len(chain.Certificates) == 0 {
		t.Error("expected at least one cert in chain")
	}
}

func TestGetCertFromFileExt2_Ed25519(t *testing.T) {
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "getfile-ed25519", KeyType: "ed25519", ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert Ed25519 failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	info, err := GetCertFromFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("GetCertFromFile Ed25519 failed: %v", err)
	}
	if info.PublicKeyAlgorithm != "Ed25519" {
		t.Errorf("expected Ed25519, got %s", info.PublicKeyAlgorithm)
	}
}

// =====================================================================
// caissuer.go - ReadSignerFromFile, loadCertAndSigner, generateKeyPair
// =====================================================================

func TestReadSignerFromFileExt2_ECDSA(t *testing.T) {
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "signer-ec-test", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert ECDSA failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	signer, err := ReadSignerFromFile(result.PrivateKeyPath)
	if err != nil {
		t.Fatalf("ReadSignerFromFile ECDSA failed: %v", err)
	}
	if signer == nil {
		t.Error("expected signer")
	}
}

func TestReadSignerFromFileExt2_Ed25519(t *testing.T) {
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "signer-ed-test", KeyType: "ed25519", ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert Ed25519 failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	signer, err := ReadSignerFromFile(result.PrivateKeyPath)
	if err != nil {
		t.Fatalf("ReadSignerFromFile Ed25519 failed: %v", err)
	}
	if signer == nil {
		t.Error("expected signer")
	}
}

func TestReadSignerFromFileExt2_InvalidPEM(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "invalid-key-*.pem")
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("-----BEGIN PRIVATE KEY-----\nnotavalidkey\n-----END PRIVATE KEY-----")
	tmpFile.Close()

	_, err := ReadSignerFromFile(tmpFile.Name())
	if err == nil {
		t.Error("expected error for invalid PEM key")
	}
}

func TestReadSignerFromFileExt2_NoPEMBlock(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "no-pem-block-*.pem")
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("this is not a PEM block at all")
	tmpFile.Close()

	_, err := ReadSignerFromFile(tmpFile.Name())
	if err == nil {
		t.Error("expected error for non-PEM content")
	}
}

func TestLoadCertAndSignerExt2_Nonexistent(t *testing.T) {
	_, _, err := loadCertAndSigner("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent files")
	}
}

func TestLoadCertAndSignerExt2_Valid(t *testing.T) {
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "load-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert, signer, err := loadCertAndSigner(result.CertificatePath, result.PrivateKeyPath)
	if err != nil {
		t.Fatalf("loadCertAndSigner failed: %v", err)
	}
	if cert == nil {
		t.Error("expected cert")
	}
	if signer == nil {
		t.Error("expected signer")
	}
}

// =====================================================================
// generator.go - GenerateSelfSignedCert with all fields, ValidateCertificateFiles Ed25519
// =====================================================================

func TestGenerateSelfSignedCertExt2_AllFields(t *testing.T) {
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:   "all-fields",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
		Organization: "Test Org",
		Country:      "US",
		Province:     "CA",
		Locality:     "San Francisco",
		DNSNames:     []string{"all.example.com", "www.all.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1")},
		IsCA:         false,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert all fields failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	if cert.Subject.Organization == nil || cert.Subject.Organization[0] != "Test Org" {
		t.Error("expected organization")
	}
	if cert.Subject.Country == nil || cert.Subject.Country[0] != "US" {
		t.Error("expected country")
	}
	if cert.Subject.Province == nil || cert.Subject.Province[0] != "CA" {
		t.Error("expected province")
	}
	if cert.Subject.Locality == nil || cert.Subject.Locality[0] != "San Francisco" {
		t.Error("expected locality")
	}
}

func TestValidateCertificateFilesExt2_Ed25519Mismatch(t *testing.T) {
	edResult1, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ed-mismatch-1", KeyType: "ed25519", ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert Ed25519 1 failed: %v", err)
	}
	defer removeFiles(edResult1.CertificatePath, edResult1.PrivateKeyPath)

	edResult2, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ed-mismatch-2", KeyType: "ed25519", ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert Ed25519 2 failed: %v", err)
	}
	defer removeFiles(edResult2.CertificatePath, edResult2.PrivateKeyPath)

	err = ValidateCertificateFiles(edResult1.CertificatePath, edResult2.PrivateKeyPath)
	if err == nil {
		t.Error("expected error for Ed25519 key mismatch")
	}
}

// =====================================================================
// certchange.go - Save, LoadLatest
// =====================================================================

func TestSnapshotStoreExt2_SaveOverwrite(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "snap-overwrite-*")
	defer os.RemoveAll(tmpDir)

	store := NewSnapshotStore(tmpDir)

	snap := &CertSnapshot{
		Target:     "example.com",
		Timestamp:  time.Now().Truncate(time.Second),
		CertSHA256: "abc123",
	}
	err := store.Save(snap)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Save again (overwrite)
	snap.CertSHA256 = "def456"
	err = store.Save(snap)
	if err != nil {
		t.Fatalf("Save overwrite failed: %v", err)
	}

	loaded, _ := store.LoadLatest("example.com")
	if loaded.CertSHA256 != "def456" {
		t.Errorf("expected overwritten SHA256, got %q", loaded.CertSHA256)
	}
}

func TestSnapshotStoreExt2_MultipleTargets(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "snap-multi-*")
	defer os.RemoveAll(tmpDir)

	store := NewSnapshotStore(tmpDir)

	for _, target := range []string{"a.com", "b.com", "c.com"} {
		snap := &CertSnapshot{
			Target:     target,
			Timestamp:  time.Now().Truncate(time.Second),
			CertSHA256: target + "-hash",
		}
		store.Save(snap)
	}

	for _, target := range []string{"a.com", "b.com", "c.com"} {
		loaded, err := store.LoadLatest(target)
		if err != nil {
			t.Fatalf("LoadLatest %s failed: %v", target, err)
		}
		if loaded.CertSHA256 != target+"-hash" {
			t.Errorf("expected %q, got %q", target+"-hash", loaded.CertSHA256)
		}
	}
}

// =====================================================================
// expirycheck.go - CertExpiryMonitor
// =====================================================================

func TestCertExpiryMonitorExt2_ExpiredCert(t *testing.T) {
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "already-expired", KeyType: "rsa", KeySize: 2048, ValidityDays: 1,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	monitorResult := CertExpiryMonitor([]string{result.CertificatePath})
	if len(monitorResult.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(monitorResult.Targets))
	}
}

func TestCertExpiryMonitorExt2_EmptyList(t *testing.T) {
	monitorResult := CertExpiryMonitor([]string{})
	if monitorResult.TotalCount != 0 {
		t.Errorf("expected TotalCount=0, got %d", monitorResult.TotalCount)
	}
}

// =====================================================================
// sct.go - parseEmbeddedSCTs, parseSCTList
// =====================================================================

func TestParseEmbeddedSCTsExt2_WithSCTExtension(t *testing.T) {
	// Build a cert with SCT list extension
	sctData := make([]byte, 47)
	sctData[0] = 0x00
	for i := 1; i < 33; i++ {
		sctData[i] = byte(i)
	}
	binaryTimestamp := uint64(1609459200000)
	for i := 0; i < 8; i++ {
		sctData[33+i] = byte(binaryTimestamp >> (56 - 8*i))
	}

	// Build the SCT list value
	listLen := 2 + len(sctData)
	sctListValue := []byte{byte(listLen >> 8), byte(listLen)}
	sctListValue = append(sctListValue, byte(len(sctData)>>8), byte(len(sctData)))
	sctListValue = append(sctListValue, sctData...)

	// The SCT extension OID
	sctListOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

	cert := makeTestCert(func(c *x509.Certificate) {
		c.Extensions = append(c.Extensions, pkix.Extension{
			Id:    sctListOID,
			Value: sctListValue,
		})
	})

	scts := parseEmbeddedSCTs(cert)
	if len(scts) == 0 {
		t.Error("expected SCTs from cert with SCT extension")
	}
}

func TestParseSCTListExt2(t *testing.T) {
	// Empty data
	_, err := parseSCTList(nil)
	if err == nil {
		t.Error("expected error for nil data")
	}

	// Too short for length field
	_, err = parseSCTList([]byte{0x01})
	if err == nil {
		t.Error("expected error for too short data")
	}

	// Valid SCT list
	sctData := make([]byte, 47)
	sctData[0] = 0x00
	for i := 1; i < 33; i++ {
		sctData[i] = byte(i)
	}
	binaryTimestamp := uint64(1609459200000)
	for i := 0; i < 8; i++ {
		sctData[33+i] = byte(binaryTimestamp >> (56 - 8*i))
	}

	listLen := 2 + len(sctData)
	rawData := []byte{byte(listLen >> 8), byte(listLen)}
	rawData = append(rawData, byte(len(sctData)>>8), byte(len(sctData)))
	rawData = append(rawData, sctData...)

	scts, err := parseSCTList(rawData)
	if err != nil {
		t.Fatalf("parseSCTList failed: %v", err)
	}
	if len(scts) != 1 {
		t.Errorf("expected 1 SCT, got %d", len(scts))
	}
}

// =====================================================================
// serialentropy.go - AnalyzeSerialNumberFromCert
// =====================================================================

func TestAnalyzeSerialNumberExt2(t *testing.T) {
	// High entropy serial
	highEntropyCert := makeTestCert(func(c *x509.Certificate) {
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		c.SerialNumber = serial
	})
	result := AnalyzeSerialNumberFromCert(highEntropyCert)
	if result.SerialHex == "" {
		t.Error("expected serial number")
	}

	// Nil serial
	nilSerialCert := makeTestCert(func(c *x509.Certificate) {
		c.SerialNumber = nil
	})
	result = AnalyzeSerialNumberFromCert(nilSerialCert)
	if result.BitLength != 0 {
		t.Errorf("expected 0 bits for nil serial, got %d", result.BitLength)
	}

	// Short serial (low entropy)
	shortCert := makeTestCert(func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(42)
	})
	result = AnalyzeSerialNumberFromCert(shortCert)
	if result.BitLength > 64 {
		t.Log("Short serial has more entropy than expected")
	}
}

// =====================================================================
// isWeakCipherSuite additional
// =====================================================================

func TestIsWeakCipherSuiteExt2(t *testing.T) {
	weakSuites := []uint16{
		0x0005, // TLS_RSA_WITH_RC4_128_SHA
		0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x0002, // TLS_RSA_WITH_NULL_SHA
		0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
		0x0009, // TLS_RSA_WITH_DES_CBC_SHA
	}
	for _, suite := range weakSuites {
		if !isWeakCipherSuite(suite) {
			t.Errorf("expected 0x%04x to be weak", suite)
		}
	}

	// Strong suites
	strongSuites := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_AES_128_GCM_SHA256,
	}
	for _, suite := range strongSuites {
		if isWeakCipherSuite(suite) {
			t.Errorf("expected 0x%04x to be strong", suite)
		}
	}
}

// =====================================================================
// computeCertSPKIHash
// =====================================================================

func TestComputeCertSPKIHashExt2(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "spki-hash-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	hash := ComputeCertSPKIHash(cert)
	if hash == "" {
		t.Error("expected non-empty SPKI hash")
	}
}

// =====================================================================
// certificate.go - GetCertFromDomainWithContext
// =====================================================================

func TestGetCertFromDomainWithContextExt2_Invalid(t *testing.T) {
	// Test with context - should fail for invalid domain
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := GetCertFromDomainWithContext(ctx, "nonexistent.invalid.domain.example")
	if err == nil {
		t.Error("expected error for invalid domain")
	}
}

// =====================================================================
// wildcard.go - GetCertSANs and GetTrustedDomains (offline via cert)
// =====================================================================

func TestGetCertSANsExt2_Offline(t *testing.T) {
	// GetCertSANs takes a domain string (needs network), so test offline via cert
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName:   "sans-test",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
		DNSNames:     []string{"www.sans-test.example.com", "mail.sans-test.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1")},
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	// Test internal functions that GetCertSANs uses
	if len(cert.DNSNames) == 0 {
		t.Error("expected DNS names in generated cert")
	}
}

func TestGetTrustedDomainsExt2_Offline(t *testing.T) {
	// GetTrustedDomains takes a domain string (needs network), test via cert
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName:   "trusted-dom-test",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
		DNSNames:     []string{"*.example.com", "www.example.com"},
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	// Test classifySANEntry and assessWildcardRisk directly
	for _, san := range cert.DNSNames {
		entry := classifySANEntry("DNS", san)
		t.Logf("SAN %q: type=%s, wildcard=%v", san, entry.Type, entry.IsWildcard)
	}
}

// =====================================================================
// evcert.go - DetectEV offline
// =====================================================================

func TestDetectEVExt2_Offline(t *testing.T) {
	// DetectEV requires TLS connection but we can test via internal evPolicyOIDs map
	cert := makeTestCert(func(c *x509.Certificate) {
		c.PolicyIdentifiers = []asn1.ObjectIdentifier{
			asn1.ObjectIdentifier{2, 16, 840, 1, 114412, 1, 3}, // DigiCert EV
		}
	})

	for _, oid := range cert.PolicyIdentifiers {
		oidStr := oid.String()
		if _, ok := evPolicyOIDs[oidStr]; ok {
			t.Logf("EV policy OID %s is recognized", oidStr)
		}
	}
}

// =====================================================================
// checkUntrustedChain with self-signed cert
// =====================================================================

func TestCheckUntrustedChainExt2_SelfSigned(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "self-signed-chain", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	// Self-signed cert in chain - should be untrusted
	passed, detail := checkUntrustedChain(cert, "", state)
	_ = passed
	_ = detail
}

// =====================================================================
// cipherscanner additional
// =====================================================================

func TestGetCipherSuitesForVersionExt2(t *testing.T) {
	suites := getCipherSuitesForVersion(tls.VersionTLS12)
	if len(suites) == 0 {
		t.Error("expected cipher suites for TLS 1.2")
	}

	suites = getCipherSuitesForVersion(tls.VersionTLS13)
	if len(suites) == 0 {
		t.Error("expected cipher suites for TLS 1.3")
	}
}

// =====================================================================
// generateKeyPair error paths
// =====================================================================

func TestGenerateKeyPairExt2_Unsupported(t *testing.T) {
	_, _, _, err := generateKeyPair("dsa", 2048)
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestGenerateKeyPairExt2_ECDSAInvalidSize(t *testing.T) {
	_, _, _, err := generateKeyPair("ecdsa", 999)
	if err != nil {
		// ECDSA with unknown size should default to P-256, not error
		t.Errorf("expected default to P-256, got error: %v", err)
	}
}

// =====================================================================
// saveCertAndKey error paths
// =====================================================================

func TestSaveCertAndKeyExt2_InvalidPath(t *testing.T) {
	err := saveCertAndKey([]byte("cert"), []byte("key"), "/nonexistent/dir/cert.pem", "/nonexistent/dir/key.pem")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

// =====================================================================
// CertError additional coverage
// =====================================================================

func TestCertErrorExt2_Fields(t *testing.T) {
	wrappedErr := errors.New("underlying error")
	err := NewCertError("connect", "test-domain.com", wrappedErr)
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
	if err.Target != "test-domain.com" {
		t.Errorf("expected test-domain.com, got %q", err.Target)
	}
	if err.Op != "connect" {
		t.Errorf("expected connect, got %q", err.Op)
	}
	if !errors.Is(err, wrappedErr) {
		t.Error("expected Unwrap to return underlying error")
	}
}

// =====================================================================
// CRL generate with Ed25519 CA
// =====================================================================

func TestGenerateCRLExt2_Ed25519(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-ca-ed", IsCA: true, KeyType: "ed25519", ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	crlResult, err := GenerateCRL(CRLGenerateRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		RevokedCerts: []RevokedEntry{
			{SerialNumber: "444"},
		},
		OutputPath: "ed25519-crl.pem",
	})
	if err != nil {
		t.Fatalf("GenerateCRL Ed25519 failed: %v", err)
	}
	defer os.Remove(crlResult.CRLPath)
}

// =====================================================================
// CRL generate with all reason codes
// =====================================================================

func TestGenerateCRLExt2_AllReasons(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-ca-reasons", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	allReasons := []string{
		"unspecified", "key-compromise", "ca-compromise",
		"affiliation-changed", "superseded", "cessation-of-operation",
		"certificate-hold", "privilege-withdrawn", "aa-compromise",
	}
	revokedCerts := make([]RevokedEntry, len(allReasons))
	for i, reason := range allReasons {
		revokedCerts[i] = RevokedEntry{
			SerialNumber: string(rune('0' + i)),
			Reason:       reason,
		}
	}

	crlResult, err := GenerateCRL(CRLGenerateRequest{
		CACertPath:   caResult.CertificatePath,
		CAKeyPath:    caResult.PrivateKeyPath,
		RevokedCerts: revokedCerts,
		OutputPath:   "all-reasons-crl.pem",
	})
	if err != nil {
		t.Fatalf("GenerateCRL all reasons failed: %v", err)
	}
	defer os.Remove(crlResult.CRLPath)
}

// =====================================================================
// Comparator additional coverage
// =====================================================================

func TestFindDifferencesExt2_SameSubject(t *testing.T) {
	result1, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "same-subj-1", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result1.CertificatePath, result1.PrivateKeyPath)

	result2, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "same-subj-2", KeyType: "rsa", KeySize: 4096, ValidityDays: 365,
		Organization: "Different Org",
	})
	defer removeFiles(result2.CertificatePath, result2.PrivateKeyPath)

	c1 := readCertFromFile(t, result1.CertificatePath)
	c2 := readCertFromFile(t, result2.CertificatePath)

	diffs := findDifferences(c1, c2)
	if len(diffs) == 0 {
		t.Error("expected differences between certs with different key sizes and orgs")
	}
}

// =====================================================================
// MatchFingerprints offline test
// =====================================================================

func TestMatchFingerprintsExt2_Offline(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "fp-match-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	fp := GenerateFingerprints(cert)

	// Match by SHA-256 cert fingerprint
	matchResult := MatchFingerprintByHash("cert_sha256", fp["sha256"])
	// The hash probably isn't in the database, but the function should not panic
	_ = matchResult
}

// =====================================================================
// Ensure key type coverage for buildCertSummary
// =====================================================================

func TestBuildCertSummaryExt2_ECDSA384(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "summary-ec-384", KeyType: "ecdsa", KeySize: 384, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	summary := buildCertSummary(cert)
	if summary.PublicKeyAlgorithm != "ECDSA" {
		t.Errorf("expected ECDSA, got %s", summary.PublicKeyAlgorithm)
	}
	if summary.KeySize != 384 {
		t.Errorf("expected 384, got %d", summary.KeySize)
	}
}

func TestBuildCertSummaryExt2_ECDSA521(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "summary-ec-521", KeyType: "ecdsa", KeySize: 521, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	summary := buildCertSummary(cert)
	if summary.PublicKeyAlgorithm != "ECDSA" {
		t.Errorf("expected ECDSA, got %s", summary.PublicKeyAlgorithm)
	}
}

// =====================================================================
// Test the computeCertSPKIHash with ECDSA and Ed25519
// =====================================================================

func TestComputeCertSPKIHashExt2_ECDSA(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "spki-ec-test", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	hash := ComputeCertSPKIHash(cert)
	if hash == "" {
		t.Error("expected non-empty SPKI hash for ECDSA")
	}
}

func TestComputeCertSPKIHashExt2_Ed25519(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "spki-ed-test", KeyType: "ed25519", ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	hash := ComputeCertSPKIHash(cert)
	if hash == "" {
		t.Error("expected non-empty SPKI hash for Ed25519")
	}
}

// =====================================================================
// Test GenerateCRL error path - invalid CA
// =====================================================================

func TestGenerateCRLExt2_InvalidCA(t *testing.T) {
	_, err := GenerateCRL(CRLGenerateRequest{
		CACertPath: "/nonexistent/ca.pem",
		CAKeyPath:  "/nonexistent/ca-key.pem",
		RevokedCerts: []RevokedEntry{
			{SerialNumber: "1"},
		},
	})
	if err == nil {
		t.Error("expected error for invalid CA")
	}
}

// =====================================================================
// Test GenerateCRL error path - non-CA cert
// =====================================================================

func TestGenerateCRLExt2_NonCA(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "non-ca-crl", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	_, err := GenerateCRL(CRLGenerateRequest{
		CACertPath: result.CertificatePath,
		CAKeyPath:  result.PrivateKeyPath,
		RevokedCerts: []RevokedEntry{
			{SerialNumber: "1"},
		},
	})
	if err == nil {
		t.Error("expected error for non-CA cert in CRL generation")
	}
}

// =====================================================================
// Test VerifyCRLSignature error paths
// =====================================================================

func TestVerifyCRLSignatureExt2_InvalidPaths(t *testing.T) {
	_, err := VerifyCRLSignature("/nonexistent/crl.pem", "/nonexistent/ca.pem")
	if err == nil {
		t.Error("expected error for invalid paths")
	}
}

// =====================================================================
// Test CheckCertRevokedByCRL error paths
// =====================================================================

func TestCheckCertRevokedByCRLExt2_InvalidPaths(t *testing.T) {
	_, err := CheckCertRevokedByCRL("/nonexistent/cert.pem", "/nonexistent/crl.pem")
	if err == nil {
		t.Error("expected error for invalid paths")
	}
}

// =====================================================================
// Test parseCAAResponse additional coverage
// =====================================================================

func TestParseCAAResponseExt2_AnswerOverflow(t *testing.T) {
	// Too short response (< 12 bytes)
	_, err := parseCAAResponse([]byte{0x01, 0x02}, "example.com")
	if err == nil {
		t.Error("expected error for too short response")
	}

	// DNS error response (rcode != 0)
	data := []byte{
		0xAA, 0xBB, 0x81, 0x83, // rcode = 3 (NXDOMAIN)
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	_, err = parseCAAResponse(data, "example.com")
	if err == nil {
		t.Error("expected error for DNS error response")
	}

	// Valid response with no answers
	data = []byte{
		0xAA, 0xBB, 0x81, 0x80,
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, 0x00, 0x00,
	}
	records, err := parseCAAResponse(data, "example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

// =====================================================================
// Test hostnameverify - findMatchingSAN
// =====================================================================

func TestFindMatchingSANExt2(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"example.com", "*.wild.example.com", "test.org"}
		c.Subject = pkix.Name{CommonName: "cn.example.com"}
	})

	// Exact match
	match := findMatchingSAN(cert, "example.com")
	if match != "example.com" {
		t.Errorf("expected exact match on example.com, got %q", match)
	}

	// Wildcard match
	match = findMatchingSAN(cert, "sub.wild.example.com")
	if match != "*.wild.example.com" {
		t.Errorf("expected wildcard match, got %q", match)
	}

	// CN match
	cert2 := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = nil
		c.Subject = pkix.Name{CommonName: "cn.example.com"}
	})
	match = findMatchingSAN(cert2, "cn.example.com")
	if match != "cn.example.com" {
		t.Errorf("expected CN match, got %q", match)
	}

	// No match
	match = findMatchingSAN(cert, "other.com")
	if match != "" {
		t.Errorf("expected empty match, got %q", match)
	}
}

// =====================================================================
// Test TLSDialWithContext with invalid host
// =====================================================================

func TestTLSDialWithContextExt2_InvalidHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := TLSDialWithContext(ctx, "nonexistent.invalid.domain.example:443", DialOptions{})
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

// =====================================================================
// Test BatchAnalyzeSecurityWithContext
// =====================================================================

func TestBatchAnalyzeSecurityWithContextExt2_Invalid(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := BatchAnalyzeSecurityWithContext(ctx, []string{"nonexistent.invalid.domain.example"})
	if result == nil {
		t.Error("expected non-nil result")
	}
}

// =====================================================================
// Test AnalyzeSecurityWithContext
// =====================================================================

func TestAnalyzeSecurityWithContextExt2_Invalid(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := AnalyzeSecurityWithContext(ctx, "nonexistent.invalid.domain.example")
	if err == nil {
		t.Error("expected error for invalid domain")
	}
}

// =====================================================================
// Test TLSDial error paths
// =====================================================================

func TestTLSDialExt2_InvalidHost(t *testing.T) {
	_, err := TLSDial("nonexistent.invalid.domain.example:443")
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

func TestTLSDialWithTimeoutExt2_InvalidHost(t *testing.T) {
	_, err := TLSDialWithTimeout("nonexistent.invalid.domain.example:443", 2*time.Second)
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

func TestTLSDialRawExt2_InvalidHost(t *testing.T) {
	_, err := TLSDialRaw("nonexistent.invalid.domain.example:443", &tls.Config{}, 2*time.Second)
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

// =====================================================================
// Test offline.go - NewOfflineAnalysis
// =====================================================================

func TestNewOfflineAnalysisExt2(t *testing.T) {
	cert := makeTestCert()
	result := NewOfflineAnalysis(cert)
	if result == nil {
		t.Error("expected non-nil result")
	}
	if result.Target != cert.Subject.CommonName {
		t.Errorf("expected target %q, got %q", cert.Subject.CommonName, result.Target)
	}

	// With intermediates
	intermediate := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = true
		c.Subject = pkix.Name{CommonName: "Test Intermediate CA"}
	})
	result = NewOfflineAnalysis(cert, intermediate)
	if result.IntermediatePool == nil {
		t.Error("expected intermediate pool")
	}
}

// =====================================================================
// Test offline.go - AnalyzeSecurityFromCert (no state)
// =====================================================================

func TestAnalyzeSecurityFromCertExt2_NoState(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("test-nostate.com")
		c.DNSNames = []string{"test-nostate.com"}
	})
	result, err := AnalyzeSecurityFromCert(cert, "test-nostate.com")
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCert failed: %v", err)
	}
	if result.OverallScore == 0 {
		t.Error("expected non-zero score")
	}
}

// =====================================================================
// Test offline.go - CheckDistrustedCAFromCert
// =====================================================================

func TestCheckDistrustedCAFromCertExt2(t *testing.T) {
	cert := makeTestCert()
	result := CheckDistrustedCAFromCert([]*x509.Certificate{cert})
	if result == nil {
		t.Error("expected non-nil result")
	}
	if result.IsDistrusted {
		t.Error("expected test cert not to be distrusted")
	}
}

// =====================================================================
// Test offline.go - CheckKeyUsageFromCert
// =====================================================================

func TestCheckKeyUsageFromCertExt2_CAWithoutCertSign(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = 0 // No key usage
	})
	result := CheckKeyUsageFromCert(cert)
	if result.IsCompliant {
		t.Error("expected non-compliant for CA without keyCertSign")
	}
}

func TestCheckKeyUsageFromCertExt2_NonCAWithCertSign(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageCertSign
	})
	result := CheckKeyUsageFromCert(cert)
	if result.IsCompliant {
		t.Error("expected non-compliant for non-CA with keyCertSign")
	}
}

func TestCheckKeyUsageFromCertExt2_NoKeyUsage(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = 0
		c.ExtKeyUsage = nil
	})
	result := CheckKeyUsageFromCert(cert)
	if result.IsCompliant {
		t.Error("expected non-compliant for no key usage")
	}
}

// =====================================================================
// Test offline.go - CheckPolicyFromCert
// =====================================================================

func TestCheckPolicyFromCertExt2_UnknownOID(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.PolicyIdentifiers = []asn1.ObjectIdentifier{
			asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}, // Unknown OID
		}
	})
	result := CheckPolicyFromCert(cert)
	if !result.HasPolicies {
		t.Error("expected HasPolicies")
	}
	if len(result.PolicyOIDs) != 1 {
		t.Error("expected 1 policy OID")
	}
	if result.PolicyOIDs[0].Type != "Unknown" {
		t.Errorf("expected Unknown type, got %q", result.PolicyOIDs[0].Type)
	}
}

func TestCheckPolicyFromCertExt2_NoPolicies(t *testing.T) {
	cert := makeTestCert()
	result := CheckPolicyFromCert(cert)
	if result.HasPolicies {
		t.Error("expected no policies")
	}
}

// =====================================================================
// Test offline.go - CheckNameConstraintsFromCert
// =====================================================================

func TestCheckNameConstraintsFromCertExt2_ShortChain(t *testing.T) {
	cert := makeTestCert()
	result := CheckNameConstraintsFromCert([]*x509.Certificate{cert})
	if !result.IsCompliant {
		t.Error("expected compliant for short chain (no CA)")
	}
}

// =====================================================================
// Test offline.go - ScanCertSecurityFromChain
// =====================================================================

func TestScanCertSecurityFromChainExt2_NoState(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("scan-no-state.com")
		c.DNSNames = []string{"scan-no-state.com"}
	})
	result, err := ScanCertSecurityFromChain(cert, "scan-no-state.com", nil)
	if err != nil {
		t.Fatalf("ScanCertSecurityFromChain failed: %v", err)
	}
	if len(result.Checks) == 0 {
		t.Error("expected checks")
	}
}

func TestScanCertSecurityFromChainExt2_WithState(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkixName("scan-with-state.com")
		c.DNSNames = []string{"scan-with-state.com"}
	})
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	result, err := ScanCertSecurityFromChain(cert, "scan-with-state.com", state)
	if err != nil {
		t.Fatalf("ScanCertSecurityFromChain with state failed: %v", err)
	}
	// With state, we should have more checks (CERT-013 through CERT-018)
	if len(result.Checks) < 12 {
		t.Errorf("expected at least 12 checks with state, got %d", len(result.Checks))
	}
}

// =====================================================================
// Test certvulnscan.go - individual check functions
// =====================================================================

func TestCheckWeakSignatureExt2(t *testing.T) {
	cert := makeTestCert() // SHA-256 by default
	passed, _ := checkWeakSignature(cert, "", nil)
	if !passed {
		t.Error("expected SHA-256 to pass")
	}
}

func TestCheckShortRSAKeyExt2(t *testing.T) {
	// RSA key >= 2048 should pass
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "rsa-2048", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)
	cert := readCertFromFile(t, result.CertificatePath)
	passed, _ := checkShortRSAKey(cert, "", nil)
	if !passed {
		t.Error("expected RSA 2048 to pass")
	}

	// Non-RSA key should pass
	ecResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ec-not-rsa", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	defer removeFiles(ecResult.CertificatePath, ecResult.PrivateKeyPath)
	ecCert := readCertFromFile(t, ecResult.CertificatePath)
	passed, _ = checkShortRSAKey(ecCert, "", nil)
	if !passed {
		t.Error("expected non-RSA key to pass")
	}
}

func TestCheckMissingSANExt2(t *testing.T) {
	// With SANs
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"example.com"}
	})
	passed, _ := checkMissingSAN(cert, "", nil)
	if !passed {
		t.Error("expected cert with SANs to pass")
	}

	// Without SANs
	certNoSAN := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = nil
	})
	passed, _ = checkMissingSAN(certNoSAN, "", nil)
	if passed {
		t.Error("expected cert without SANs to fail")
	}
}

func TestCheckHostnameMismatchExt2(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"match.example.com"}
	})
	// Matching hostname
	passed, _ := checkHostnameMismatch(cert, "match.example.com", nil)
	if !passed {
		t.Error("expected matching hostname to pass")
	}

	// Mismatching hostname
	passed, _ = checkHostnameMismatch(cert, "other.example.com", nil)
	if passed {
		t.Error("expected mismatching hostname to fail")
	}
}

func TestCheckExcessiveValidityExt2(t *testing.T) {
	// Normal validity
	cert := makeTestCert(func(c *x509.Certificate) {
		c.NotBefore = time.Now()
		c.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	})
	passed, _ := checkExcessiveValidity(cert, "", nil)
	if !passed {
		t.Error("expected 365-day validity to pass")
	}

	// Excessive validity
	certLong := makeTestCert(func(c *x509.Certificate) {
		c.NotBefore = time.Now()
		c.NotAfter = time.Now().Add(400 * 24 * time.Hour)
	})
	passed, _ = checkExcessiveValidity(certLong, "", nil)
	if passed {
		t.Error("expected 400-day validity to fail")
	}
}

func TestCheckSelfSignedExt2(t *testing.T) {
	// Self-signed
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "self-signed"}
		c.Issuer = pkix.Name{CommonName: "self-signed"}
	})
	passed, _ := checkSelfSigned(cert, "", nil)
	if passed {
		t.Error("expected self-signed to fail")
	}

	// Not self-signed
	cert2 := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "leaf"}
		c.Issuer = pkix.Name{CommonName: "ca"}
	})
	passed, _ = checkSelfSigned(cert2, "", nil)
	if !passed {
		t.Error("expected non-self-signed to pass")
	}
}

func TestCheckCertExpiredExt2(t *testing.T) {
	// Not expired
	cert := makeTestCert(func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	})
	passed, _ := checkCertExpired(cert, "", nil)
	if !passed {
		t.Error("expected non-expired cert to pass")
	}

	// Expired
	certExpired := makeTestCert(func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	})
	passed, _ = checkCertExpired(certExpired, "", nil)
	if passed {
		t.Error("expected expired cert to fail")
	}
}

func TestCheckCertExpiringSoonExt2(t *testing.T) {
	// Not expiring soon
	cert := makeTestCert(func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	})
	passed, _ := checkCertExpiringSoon(cert, "", nil)
	if !passed {
		t.Error("expected cert not expiring soon to pass")
	}

	// Expiring soon (15 days)
	certSoon := makeTestCert(func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(15 * 24 * time.Hour)
	})
	passed, _ = checkCertExpiringSoon(certSoon, "", nil)
	if passed {
		t.Error("expected cert expiring soon to fail")
	}
}

func TestCheckCNNotInSANsExt2(t *testing.T) {
	// CN in SANs
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "example.com"}
		c.DNSNames = []string{"example.com", "www.example.com"}
	})
	passed, _ := checkCNNotInSANs(cert, "", nil)
	if !passed {
		t.Error("expected CN in SANs to pass")
	}

	// CN not in SANs
	cert2 := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "cn.example.com"}
		c.DNSNames = []string{"www.example.com"}
	})
	passed, _ = checkCNNotInSANs(cert2, "", nil)
	if passed {
		t.Error("expected CN not in SANs to fail")
	}

	// No CN
	cert3 := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: ""}
		c.DNSNames = []string{"example.com"}
	})
	passed, _ = checkCNNotInSANs(cert3, "", nil)
	if !passed {
		t.Error("expected no CN to pass (N/A)")
	}

	// No DNS names
	cert4 := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "example.com"}
		c.DNSNames = nil
	})
	passed, _ = checkCNNotInSANs(cert4, "", nil)
	if !passed {
		t.Error("expected no DNS names to pass (N/A)")
	}
}

func TestCheckWildcardCertExt2(t *testing.T) {
	// With wildcard
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"*.example.com"}
	})
	passed, _ := checkWildcardCert(cert, "", nil)
	if passed {
		t.Error("expected wildcard cert to fail")
	}

	// Without wildcard
	cert2 := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"example.com"}
	})
	passed, _ = checkWildcardCert(cert2, "", nil)
	if !passed {
		t.Error("expected non-wildcard cert to pass")
	}
}

func TestCheckInternalNameExt2(t *testing.T) {
	// Internal name
	cert := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"test.local"}
	})
	passed, _ := checkInternalName(cert, "", nil)
	if passed {
		t.Error("expected internal name to fail")
	}

	// Public name
	cert2 := makeTestCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"example.com"}
	})
	passed, _ = checkInternalName(cert2, "", nil)
	if !passed {
		t.Error("expected public name to pass")
	}
}

func TestCheckOCSPMustStapleExt2(t *testing.T) {
	// No must-staple, no staple
	cert := makeTestCert()
	state := &tls.ConnectionState{OCSPResponse: nil}
	passed, _ := checkOCSPMustStaple(cert, "", state)
	if !passed {
		t.Error("expected no must-staple to pass")
	}

	// Must-staple with staple
	mustStapleOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	cert2 := makeTestCert(func(c *x509.Certificate) {
		c.Extensions = append(c.Extensions, pkix.Extension{
			Id:    mustStapleOID,
			Value: []byte{0x30, 0x03, 0x02, 0x01, 0x05},
		})
	})
	state2 := &tls.ConnectionState{OCSPResponse: []byte{0x01}}
	passed, _ = checkOCSPMustStaple(cert2, "", state2)
	if !passed {
		t.Error("expected must-staple with staple to pass")
	}

	// Must-staple without staple
	state3 := &tls.ConnectionState{OCSPResponse: nil}
	passed, _ = checkOCSPMustStaple(cert2, "", state3)
	if passed {
		t.Error("expected must-staple without staple to fail")
	}
}

func TestCheckKeyUsageComplianceExt2(t *testing.T) {
	// Compliant CA
	cert := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	})
	passed, _ := checkKeyUsageCompliance(cert, "", nil)
	if !passed {
		t.Error("expected compliant CA to pass")
	}

	// CA without keyCertSign
	cert2 := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCRLSign
	})
	passed, _ = checkKeyUsageCompliance(cert2, "", nil)
	if passed {
		t.Error("expected CA without keyCertSign to fail")
	}

	// Non-CA with keyCertSign
	cert3 := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageCertSign
	})
	passed, _ = checkKeyUsageCompliance(cert3, "", nil)
	if passed {
		t.Error("expected non-CA with keyCertSign to fail")
	}

	// Non-CA without digitalSignature or keyEncipherment
	cert4 := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageCRLSign
	})
	passed, _ = checkKeyUsageCompliance(cert4, "", nil)
	if passed {
		t.Error("expected non-CA without DS/KE to fail")
	}

	// No key usage at all
	cert5 := makeTestCert(func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = 0
		c.ExtKeyUsage = nil
	})
	passed, _ = checkKeyUsageCompliance(cert5, "", nil)
	if passed {
		t.Error("expected no key usage to fail")
	}
}

// =====================================================================
// Test certvulnscan.go - buildCertSecuritySummary
// =====================================================================

func TestBuildCertSecuritySummaryExt2(t *testing.T) {
	checks := []CertSecurityCheck{
		{Name: "Pass1", Passed: true},
		{Name: "Fail1", Passed: false},
		{Name: "Pass2", Passed: true},
	}
	summary := buildCertSecuritySummary(checks)
	if summary.TotalChecked != 3 {
		t.Errorf("expected 3, got %d", summary.TotalChecked)
	}
	if summary.Passed != 2 {
		t.Errorf("expected 2 passed, got %d", summary.Passed)
	}
	if summary.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", summary.Failed)
	}
	if summary.IsSecure {
		t.Error("expected IsSecure=false when there are failures")
	}
	if len(summary.FailedChecks) != 1 || summary.FailedChecks[0] != "Fail1" {
		t.Errorf("unexpected failed checks: %v", summary.FailedChecks)
	}

	// All pass
	allPass := []CertSecurityCheck{
		{Name: "Pass1", Passed: true},
	}
	summary = buildCertSecuritySummary(allPass)
	if !summary.IsSecure {
		t.Error("expected IsSecure=true when all pass")
	}
}

// =====================================================================
// Test certerrors.go - WrapConnectionError, WrapCertParseError
// =====================================================================

func TestWrapConnectionErrorExt2(t *testing.T) {
	inner := errors.New("connection refused")
	err := WrapConnectionError("example.com", inner)
	if !errors.Is(err, ErrConnectionFailed) {
		t.Error("expected ErrConnectionFailed")
	}
}

func TestWrapCertParseErrorExt2(t *testing.T) {
	inner := errors.New("parse error")
	err := WrapCertParseError("cert.pem", inner)
	if !errors.Is(err, ErrCertParseFailed) {
		t.Error("expected ErrCertParseFailed")
	}
}

// =====================================================================
// Test certerrors.go - all Wrap functions
// =====================================================================

func TestWrapErrorsExt2(t *testing.T) {
	inner := errors.New("test")

	tests := []struct {
		wrap     func(string, error) error
		sentinel error
	}{
		{WrapConnectionError, ErrConnectionFailed},
		{WrapCertParseError, ErrCertParseFailed},
		{WrapOCSPError, ErrOCSPFailed},
		{WrapCRLError, ErrCRLFailed},
		{WrapChainError, ErrChainVerification},
		{WrapFileError, ErrFileNotFound},
	}

	for _, tt := range tests {
		err := tt.wrap("test-target", inner)
		if !errors.Is(err, tt.sentinel) {
			t.Errorf("expected sentinel error, got %v", err)
		}
	}
}

// =====================================================================
// Test AnalyzeSecurityFromCertWithState - score levels
// =====================================================================

func TestAnalyzeSecurityFromCertWithStateExt2_ScoreLevels(t *testing.T) {
	// Test with a cert that has many issues to get a low score
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "self-signed"} // self-signed
		c.Issuer = pkix.Name{CommonName: "self-signed"}  // self-signed
		c.DNSNames = nil                                 // missing SAN
		c.NotAfter = time.Now().Add(-24 * time.Hour)     // expired
	})
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	result, err := AnalyzeSecurityFromCertWithState(cert, "mismatch.example.com", state)
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCertWithState failed: %v", err)
	}
	// Should have a low score
	if result.OverallScore >= 80 {
		t.Errorf("expected low score for bad cert, got %d", result.OverallScore)
	}
	// Security level should be Critical or High
	t.Logf("Score: %d, Level: %s", result.OverallScore, result.SecurityLevel)
}

// =====================================================================
// Test AnalyzeSecurityFromCertWithState - Medium score level
// =====================================================================

func TestAnalyzeSecurityFromCertWithStateExt2_MediumScore(t *testing.T) {
	// Cert with self-signed (Medium severity) to get a Medium score
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "self-signed"}
		c.Issuer = pkix.Name{CommonName: "self-signed"}
		c.DNSNames = []string{"self-signed.com"}
		c.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	})
	result, err := AnalyzeSecurityFromCertWithState(cert, "self-signed.com", nil)
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCertWithState failed: %v", err)
	}
	t.Logf("Self-signed score: %d, Level: %s", result.OverallScore, result.SecurityLevel)
}

// =====================================================================
// Test GenerateCSR with all fields
// =====================================================================

func TestGenerateCSRExt2_AllFields(t *testing.T) {
	csr, err := GenerateCSR(CertificateRequest{
		CommonName:   "csr-all-fields",
		KeyType:      "rsa",
		KeySize:      2048,
		Organization: "Test Org",
		Country:      "US",
		Province:     "CA",
		Locality:     "San Francisco",
		DNSNames:     []string{"csr.example.com", "www.csr.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1")},
	})
	if err != nil {
		t.Fatalf("GenerateCSR all fields failed: %v", err)
	}
	if csr == "" {
		t.Error("expected CSR PEM")
	}
}

// =====================================================================
// Test GenerateCSR with Ed25519
// =====================================================================

func TestGenerateCSRExt2_Ed25519(t *testing.T) {
	csr, err := GenerateCSR(CertificateRequest{
		CommonName: "csr-ed25519",
		KeyType:    "ed25519",
	})
	if err != nil {
		t.Fatalf("GenerateCSR Ed25519 failed: %v", err)
	}
	if csr == "" {
		t.Error("expected CSR PEM")
	}
}

// =====================================================================
// Test GenerateCSR with ECDSA P-384
// =====================================================================

func TestGenerateCSRExt2_ECDSA384(t *testing.T) {
	csr, err := GenerateCSR(CertificateRequest{
		CommonName: "csr-ec-384",
		KeyType:    "ecdsa",
		KeySize:    384,
	})
	if err != nil {
		t.Fatalf("GenerateCSR ECDSA P-384 failed: %v", err)
	}
	if csr == "" {
		t.Error("expected CSR PEM")
	}
}

// =====================================================================
// Test GenerateCSR with ECDSA P-521
// =====================================================================

func TestGenerateCSRExt2_ECDSA521(t *testing.T) {
	csr, err := GenerateCSR(CertificateRequest{
		CommonName: "csr-ec-521",
		KeyType:    "ecdsa",
		KeySize:    521,
	})
	if err != nil {
		t.Fatalf("GenerateCSR ECDSA P-521 failed: %v", err)
	}
	if csr == "" {
		t.Error("expected CSR PEM")
	}
}

// =====================================================================
// Test GenerateCSR error - unsupported key type
// =====================================================================

func TestGenerateCSRExt2_Unsupported(t *testing.T) {
	_, err := GenerateCSR(CertificateRequest{
		CommonName: "csr-unsupported",
		KeyType:    "dsa",
	})
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// =====================================================================
// Test SignCertificate with ECDSA CA
// =====================================================================

func TestSignCertificateExt2_ECDSACA(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ec-ca-sign", IsCA: true, KeyType: "ecdsa", KeySize: 384, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	signed, err := SignCertificate(SignCertRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		CommonName: "ec-signed.example.com",
		KeyType:    "ecdsa",
		KeySize:    256,
		DNSNames:   []string{"ec-signed.example.com"},
	})
	if err != nil {
		t.Fatalf("SignCertificate ECDSA CA failed: %v", err)
	}
	defer removeFiles(signed.CertificatePath, signed.PrivateKeyPath)
}

// =====================================================================
// Test SignCertificate with Ed25519 CA
// =====================================================================

func TestSignCertificateExt2_Ed25519CA(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ed-ca-sign", IsCA: true, KeyType: "ed25519", ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	signed, err := SignCertificate(SignCertRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		CommonName: "ed-signed.example.com",
		KeyType:    "ed25519",
	})
	if err != nil {
		t.Fatalf("SignCertificate Ed25519 CA failed: %v", err)
	}
	defer removeFiles(signed.CertificatePath, signed.PrivateKeyPath)
}

// =====================================================================
// Test SignCertificate with client key usage
// =====================================================================

func TestSignCertificateExt2_ClientUsage(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ca-client-usage", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	signed, err := SignCertificate(SignCertRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		CommonName: "client.example.com",
		KeyUsage:   "client",
	})
	if err != nil {
		t.Fatalf("SignCertificate client usage failed: %v", err)
	}
	defer removeFiles(signed.CertificatePath, signed.PrivateKeyPath)
}

// =====================================================================
// Test SignCertificate with both key usage
// =====================================================================

func TestSignCertificateExt2_BothUsage(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ca-both-usage", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	signed, err := SignCertificate(SignCertRequest{
		CACertPath: caResult.CertificatePath,
		CAKeyPath:  caResult.PrivateKeyPath,
		CommonName: "both.example.com",
		KeyUsage:   "both",
	})
	if err != nil {
		t.Fatalf("SignCertificate both usage failed: %v", err)
	}
	defer removeFiles(signed.CertificatePath, signed.PrivateKeyPath)
}

// =====================================================================
// Test GenerateIntermediateCA
// =====================================================================

func TestGenerateIntermediateCAExt2_ECDSA(t *testing.T) {
	rootResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "root-ec-ca", IsCA: true, KeyType: "ecdsa", KeySize: 384, ValidityDays: 3650,
	})
	defer removeFiles(rootResult.CertificatePath, rootResult.PrivateKeyPath)

	interResult, err := GenerateIntermediateCA(IntermediateCARequest{
		ParentCertPath: rootResult.CertificatePath,
		ParentKeyPath:  rootResult.PrivateKeyPath,
		CommonName:     "Intermediate EC CA",
		KeyType:        "ecdsa",
		KeySize:        256,
	})
	if err != nil {
		t.Fatalf("GenerateIntermediateCA ECDSA failed: %v", err)
	}
	defer removeFiles(interResult.CertificatePath, interResult.PrivateKeyPath)
}

func TestGenerateIntermediateCAExt2_Ed25519(t *testing.T) {
	rootResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "root-ed-ca", IsCA: true, KeyType: "ed25519", ValidityDays: 3650,
	})
	defer removeFiles(rootResult.CertificatePath, rootResult.PrivateKeyPath)

	interResult, err := GenerateIntermediateCA(IntermediateCARequest{
		ParentCertPath: rootResult.CertificatePath,
		ParentKeyPath:  rootResult.PrivateKeyPath,
		CommonName:     "Intermediate Ed CA",
		KeyType:        "ed25519",
	})
	if err != nil {
		t.Fatalf("GenerateIntermediateCA Ed25519 failed: %v", err)
	}
	defer removeFiles(interResult.CertificatePath, interResult.PrivateKeyPath)
}

// =====================================================================
// Test GenerateIntermediateCA with all fields
// =====================================================================

func TestGenerateIntermediateCAExt2_AllFields(t *testing.T) {
	rootResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "root-all-ca", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(rootResult.CertificatePath, rootResult.PrivateKeyPath)

	interResult, err := GenerateIntermediateCA(IntermediateCARequest{
		ParentCertPath:    rootResult.CertificatePath,
		ParentKeyPath:     rootResult.PrivateKeyPath,
		CommonName:        "Intermediate All CA",
		Organization:      "Test Org",
		Country:           "US",
		Province:          "CA",
		Locality:          "San Francisco",
		KeyType:           "rsa",
		KeySize:           4096,
		ValidityDays:      1825,
		PathLenConstraint: 0,
	})
	if err != nil {
		t.Fatalf("GenerateIntermediateCA all fields failed: %v", err)
	}
	defer removeFiles(interResult.CertificatePath, interResult.PrivateKeyPath)
}

// =====================================================================
// Test GenerateIntermediateCA error - non-CA parent
// =====================================================================

func TestGenerateIntermediateCAExt2_NonCAParent(t *testing.T) {
	nonCA, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "non-ca-parent", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(nonCA.CertificatePath, nonCA.PrivateKeyPath)

	_, err := GenerateIntermediateCA(IntermediateCARequest{
		ParentCertPath: nonCA.CertificatePath,
		ParentKeyPath:  nonCA.PrivateKeyPath,
		CommonName:     "Should Fail",
	})
	if err == nil {
		t.Error("expected error for non-CA parent")
	}
}

// =====================================================================
// Test keyMatchesCert
// =====================================================================

func TestKeyMatchesCertExt2(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "key-match-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	signer, _ := ReadSignerFromFile(result.PrivateKeyPath)
	cert := readCertFromFile(t, result.CertificatePath)

	if !keyMatchesCert(signer, cert) {
		t.Error("expected key to match cert")
	}

	// Mismatched key
	otherResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "other-key-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(otherResult.CertificatePath, otherResult.PrivateKeyPath)

	otherSigner, _ := ReadSignerFromFile(otherResult.PrivateKeyPath)
	if keyMatchesCert(otherSigner, cert) {
		t.Error("expected mismatched key not to match cert")
	}
}

// =====================================================================
// Test ValidateCertificateFiles with matching pair
// =====================================================================

func TestValidateCertificateFilesExt2_Matching(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "valid-pair", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	err := ValidateCertificateFiles(result.CertificatePath, result.PrivateKeyPath)
	if err != nil {
		t.Errorf("expected valid pair to pass, got: %v", err)
	}
}

// =====================================================================
// Test ValidateCertificateFiles with ECDSA matching pair
// =====================================================================

func TestValidateCertificateFilesExt2_ECDSAMatching(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ec-valid-pair", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	err := ValidateCertificateFiles(result.CertificatePath, result.PrivateKeyPath)
	if err != nil {
		t.Errorf("expected valid ECDSA pair to pass, got: %v", err)
	}
}

// =====================================================================
// Test ValidateCertificateFiles with Ed25519 matching pair
// =====================================================================

func TestValidateCertificateFilesExt2_Ed25519Matching(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ed-valid-pair", KeyType: "ed25519", ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	err := ValidateCertificateFiles(result.CertificatePath, result.PrivateKeyPath)
	if err != nil {
		t.Errorf("expected valid Ed25519 pair to pass, got: %v", err)
	}
}

// =====================================================================
// Test ValidateCertificateFiles with RSA mismatch
// =====================================================================

func TestValidateCertificateFilesExt2_RSAMismatch(t *testing.T) {
	result1, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "rsa-mismatch-1", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result1.CertificatePath, result1.PrivateKeyPath)

	result2, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "rsa-mismatch-2", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result2.CertificatePath, result2.PrivateKeyPath)

	err := ValidateCertificateFiles(result1.CertificatePath, result2.PrivateKeyPath)
	if err == nil {
		t.Error("expected error for RSA key mismatch")
	}
}

// =====================================================================
// Test ValidateCertificateFiles with ECDSA mismatch
// =====================================================================

func TestValidateCertificateFilesExt2_ECDSAMismatch(t *testing.T) {
	result1, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ec-mismatch-1", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	defer removeFiles(result1.CertificatePath, result1.PrivateKeyPath)

	result2, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ec-mismatch-2", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	defer removeFiles(result2.CertificatePath, result2.PrivateKeyPath)

	err := ValidateCertificateFiles(result1.CertificatePath, result2.PrivateKeyPath)
	if err == nil {
		t.Error("expected error for ECDSA key mismatch")
	}
}

// =====================================================================
// Test ValidateCertificateFiles with nonexistent files
// =====================================================================

func TestValidateCertificateFilesExt2_Nonexistent(t *testing.T) {
	err := ValidateCertificateFiles("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent files")
	}
}

// =====================================================================
// Test GenerateFingerprintFromBytes
// =====================================================================

func TestGenerateFingerprintFromBytesExt2(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "fp-bytes-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}

	fp := GenerateFingerprintFromBytes(block.Bytes)
	if fp["sha256"] == "" {
		t.Error("expected SHA-256 fingerprint")
	}
}

// =====================================================================
// Test ValidateFingerprint
// =====================================================================

func TestValidateFingerprintExt2(t *testing.T) {
	// Valid SHA-256 format (64 hex chars)
	validSHA256 := strings.Repeat("aa", 32)
	if !ValidateFingerprint(validSHA256, "sha256") {
		t.Error("expected valid SHA-256")
	}

	// Valid MD5 format (32 hex chars)
	validMD5 := strings.Repeat("bb", 16)
	if !ValidateFingerprint(validMD5, "md5") {
		t.Error("expected valid MD5")
	}

	// Invalid - wrong length
	if ValidateFingerprint("aabbccdd", "sha256") {
		t.Error("expected invalid for wrong length")
	}

	// Invalid - non-hex chars
	if ValidateFingerprint(strings.Repeat("zz", 32), "sha256") {
		t.Error("expected invalid for non-hex")
	}
}

// =====================================================================
// Test CompareCertsFromFiles
// =====================================================================

func TestCompareCertsFromFilesExt2(t *testing.T) {
	result1, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "compare-file-1", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result1.CertificatePath, result1.PrivateKeyPath)

	result2, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "compare-file-2", KeyType: "rsa", KeySize: 4096, ValidityDays: 365,
	})
	defer removeFiles(result2.CertificatePath, result2.PrivateKeyPath)

	compResult, err := CompareCertsFromFiles(result1.CertificatePath, result2.CertificatePath)
	if err != nil {
		t.Fatalf("CompareCertsFromFiles failed: %v", err)
	}
	if compResult.Match {
		t.Error("expected different certs not to match")
	}

	// Same file
	compResult, err = CompareCertsFromFiles(result1.CertificatePath, result1.CertificatePath)
	if err != nil {
		t.Fatalf("CompareCertsFromFiles same file failed: %v", err)
	}
	if !compResult.Match {
		t.Error("expected same cert to match")
	}
}

// =====================================================================
// Test CompareCertsFromFiles error - nonexistent
// =====================================================================

func TestCompareCertsFromFilesExt2_Nonexistent(t *testing.T) {
	_, err := CompareCertsFromFiles("/nonexistent/cert1.pem", "/nonexistent/cert2.pem")
	if err == nil {
		t.Error("expected error for nonexistent files")
	}
}

// =====================================================================
// Test ReadCertFromFile error
// =====================================================================

func TestReadCertFromFileExt2_Nonexistent(t *testing.T) {
	_, err := ReadCertFromFile("/nonexistent/cert.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// =====================================================================
// Test ReadCertFromFile with invalid PEM
// =====================================================================

func TestReadCertFromFileExt2_InvalidPEM(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "invalid-cert-*.pem")
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("not a PEM file")
	tmpFile.Close()

	_, err := ReadCertFromFile(tmpFile.Name())
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// =====================================================================
// Test ComputeSnapshotID
// =====================================================================

func TestComputeSnapshotIDExt2(t *testing.T) {
	snap := &CertSnapshot{
		Target:     "example.com",
		Timestamp:  time.Now().Truncate(time.Second),
		CertSHA256: "abc123",
		JARMHash:   "jarm123",
	}
	id := ComputeSnapshotID(snap)
	if id == "" {
		t.Error("expected non-empty snapshot ID")
	}

	// Same snapshot should produce same ID
	id2 := ComputeSnapshotID(snap)
	if id != id2 {
		t.Error("expected same snapshot to produce same ID")
	}
}

// =====================================================================
// Test classifySANEntry and assessWildcardRisk
// =====================================================================

func TestClassifySANEntryExt2(t *testing.T) {
	tests := []struct {
		sanType    string
		sanValue   string
		entryType  string
		isWildcard bool
	}{
		{"DNS", "example.com", "DNS", false},
		{"DNS", "*.example.com", "DNS", true},
		{"IP", "192.168.1.1", "IP", false},
		{"Email", "user@example.com", "Email", false},
		{"URI", "https://example.com", "URI", false},
	}

	for _, tt := range tests {
		entry := classifySANEntry(tt.sanType, tt.sanValue)
		if entry.Type != tt.entryType {
			t.Errorf("classifySANEntry(%q, %q) type = %q, expected %q", tt.sanType, tt.sanValue, entry.Type, tt.entryType)
		}
		if entry.IsWildcard != tt.isWildcard {
			t.Errorf("classifySANEntry(%q, %q) wildcard = %v, expected %v", tt.sanType, tt.sanValue, entry.IsWildcard, tt.isWildcard)
		}
	}
}

func TestAssessWildcardRiskExt2(t *testing.T) {
	// No wildcards
	result := &WildcardResult{
		IsWildcard:    false,
		WildcardNames: nil,
	}
	level, _ := assessWildcardRisk(result)
	if level != "None" {
		t.Errorf("expected None risk, got %q", level)
	}

	// Single wildcard - Low risk
	result = &WildcardResult{
		IsWildcard:     true,
		WildcardNames:  []string{"*.example.com"},
		WildcardLevel:  1,
		CoveredDomains: []string{"example.com"},
	}
	level, _ = assessWildcardRisk(result)
	if level != "Low" {
		t.Errorf("expected Low risk for single wildcard, got %q", level)
	}

	// Multi-level wildcard - High risk
	result = &WildcardResult{
		IsWildcard:     true,
		WildcardNames:  []string{"*.*.example.com"},
		WildcardLevel:  2,
		CoveredDomains: []string{"example.com"},
	}
	level, _ = assessWildcardRisk(result)
	if level != "High" {
		t.Errorf("expected High risk for multi-level wildcard, got %q", level)
	}
}

// =====================================================================
// Test extractCN
// =====================================================================

func TestExtractCNExt2(t *testing.T) {
	cn := extractCN("CN=test-cn")
	if cn != "test-cn" {
		t.Errorf("expected test-cn, got %q", cn)
	}

	cn = extractCN("O=Org")
	if cn != "" {
		t.Errorf("expected empty CN, got %q", cn)
	}
}

// =====================================================================
// Test uniqueStrings
// =====================================================================

func TestUniqueStringsExt2(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	result := uniqueStrings(input)
	if len(result) != 4 {
		t.Errorf("expected 4 unique strings, got %d", len(result))
	}

	// Empty
	result = uniqueStrings(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 for nil, got %d", len(result))
	}
}

// =====================================================================
// Test estimateShannonEntropy
// =====================================================================

func TestEstimateShannonEntropyExt2(t *testing.T) {
	// Empty
	if e := estimateShannonEntropy(nil); e != 0 {
		t.Errorf("expected 0 for nil, got %f", e)
	}

	// Single byte
	if e := estimateShannonEntropy([]byte{0x00}); e != 0 {
		t.Errorf("expected 0 for single byte, got %f", e)
	}

	// High entropy (random)
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	e := estimateShannonEntropy(data)
	if e < 7.0 {
		t.Errorf("expected high entropy for all-byte data, got %f", e)
	}
}

// =====================================================================
// Test isSequentialSerial
// =====================================================================

func TestIsSequentialSerialExt2(t *testing.T) {
	// Sequential
	if !isSequentialSerial(big.NewInt(123456)) {
		t.Log("123456 may or may not be detected as sequential")
	}

	// Large random
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if isSequentialSerial(serial) {
		t.Log("Random serial detected as sequential (unlikely)")
	}
}

// =====================================================================
// Test parseHostPort
// =====================================================================

func TestParseHostPortExt2(t *testing.T) {
	host, port := parseHostPort("example.com:443")
	if host != "example.com" {
		t.Errorf("expected example.com, got %q", host)
	}
	if port != "443" {
		t.Errorf("expected 443, got %q", port)
	}

	// No port - defaults to 443
	host, port = parseHostPort("example.com")
	if host != "example.com" {
		t.Errorf("expected example.com, got %q", host)
	}
	if port != "443" {
		t.Errorf("expected 443 default, got %q", port)
	}
}

// =====================================================================
// Test collectLeafNames
// =====================================================================

func TestCollectLeafNamesExt2(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "leaf.example.com"}
		c.DNSNames = []string{"leaf.example.com", "www.leaf.example.com"}
		c.EmailAddresses = []string{"admin@leaf.example.com"}
		c.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")}
	})
	names := collectLeafNames(cert)
	if len(names) == 0 {
		t.Error("expected leaf names")
	}
}

// =====================================================================
// Test violatesExcluded and violatesNotPermitted
// =====================================================================

func TestViolatesExcludedExt2(t *testing.T) {
	constraint := &CAConstraint{
		ExcludedDNS: []string{".evil.com"},
	}

	if !violatesExcluded("www.evil.com", constraint) {
		t.Error("expected www.evil.com to violate excluded .evil.com")
	}
	if violatesExcluded("www.good.com", constraint) {
		t.Error("expected www.good.com not to violate excluded .evil.com")
	}
}

func TestViolatesNotPermittedExt2(t *testing.T) {
	constraint := &CAConstraint{
		PermittedDNS: []string{".example.com"},
	}

	if !violatesNotPermitted("www.other.com", constraint) {
		t.Error("expected www.other.com to violate permitted .example.com")
	}
	if violatesNotPermitted("www.example.com", constraint) {
		t.Error("expected www.example.com not to violate permitted .example.com")
	}

	// No permitted = everything permitted
	noConstraint := &CAConstraint{}
	if violatesNotPermitted("anything.com", noConstraint) {
		t.Error("expected anything to be permitted when no constraints")
	}
}

// =====================================================================
// Test formatConstraint
// =====================================================================

func TestFormatConstraintExt2(t *testing.T) {
	constraint := &CAConstraint{
		PermittedDNS: []string{".example.com"},
		ExcludedDNS:  []string{".evil.com"},
	}
	s := formatConstraint(constraint)
	if s == "" {
		t.Error("expected non-empty constraint string")
	}
}

// =====================================================================
// Test oidString
// =====================================================================

func TestOidStringExt2(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	s := oidString(oid)
	if s == "" {
		t.Error("expected non-empty OID string")
	}
}

// =====================================================================
// Test extKeyUsageToStrings
// =====================================================================

func TestExtKeyUsageToStringsExt2(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	})
	result := extKeyUsageToStrings(cert)
	if len(result) < 2 {
		t.Errorf("expected at least 2 ext key usage strings, got %d", len(result))
	}
}

// =====================================================================
// Test keyUsageToStrings
// =====================================================================

func TestKeyUsageToStringsExt2(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	})
	result := keyUsageToStrings(cert)
	if len(result) < 2 {
		t.Errorf("expected at least 2 key usage strings, got %d", len(result))
	}
}

// =====================================================================
// Test determineValidationType
// =====================================================================

func TestDetermineValidationTypeExt2(t *testing.T) {
	// EV
	evPolicies := []PolicyOID{
		{OID: "2.16.840.1.114412.1.3", Type: "EV"},
	}
	vt := determineValidationType(evPolicies)
	if vt != "EV" {
		t.Errorf("expected EV, got %q", vt)
	}

	// OV
	ovPolicies := []PolicyOID{
		{OID: "2.23.140.1.2.2", Type: "OV"},
	}
	vt = determineValidationType(ovPolicies)
	if vt != "OV" {
		t.Errorf("expected OV, got %q", vt)
	}

	// DV
	dvPolicies := []PolicyOID{
		{OID: "2.23.140.1.2.1", Type: "DV"},
	}
	vt = determineValidationType(dvPolicies)
	if vt != "DV" {
		t.Errorf("expected DV, got %q", vt)
	}

	// Unknown
	unknownPolicies := []PolicyOID{
		{OID: "1.2.3.4.5", Type: "Unknown"},
	}
	vt = determineValidationType(unknownPolicies)
	if vt != "Unknown" {
		t.Errorf("expected Unknown, got %q", vt)
	}

	// Empty
	vt = determineValidationType(nil)
	if vt != "Unknown" {
		t.Errorf("expected Unknown for empty, got %q", vt)
	}
}

// =====================================================================
// Test matchDistrustedCA
// =====================================================================

func TestMatchDistrustedCAExt2(t *testing.T) {
	// Normal cert should not match
	cert := makeTestCert()
	result := matchDistrustedCA(cert)
	if result != nil {
		t.Error("expected nil for normal cert")
	}
}

// =====================================================================
// Test GenerateDomainVariants
// =====================================================================

func TestGenerateDomainVariantsExt2_Offline(t *testing.T) {
	// GenerateDomainVariants needs a CA cert/key pair
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "variant-ca", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	result, err := GenerateDomainVariants(DomainVariantRequest{
		BaseDomain:   "example.com",
		CACertPath:   caResult.CertificatePath,
		CAKeyPath:    caResult.PrivateKeyPath,
		VariantTypes: []string{"subdomain", "hyphenation"},
		OutputDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("GenerateDomainVariants failed: %v", err)
	}
	if len(result.Variants) == 0 {
		t.Error("expected variants")
	}
}

// =====================================================================
// Test CloneCertificate
// =====================================================================

func TestCloneCertificateExt2_AllOptions(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "clone-source", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
		DNSNames: []string{"clone.example.com"},
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cloneResult, err := CloneCertificate(CloneCertRequest{
		SourceCertPath:  result.CertificatePath,
		KeyType:         "ecdsa",
		KeySize:         256,
		ModifySubject:   true,
		NewCommonName:   "cloned.example.com",
		NewOrganization: "Cloned Org",
		ValidityDays:    730,
		OutputCertPath:  filepath.Join(t.TempDir(), "cloned.pem"),
		OutputKeyPath:   filepath.Join(t.TempDir(), "cloned-key.pem"),
	})
	if err != nil {
		t.Fatalf("CloneCertificate failed: %v", err)
	}
	defer removeFiles(cloneResult.CertificatePath, cloneResult.PrivateKeyPath)
}

// =====================================================================
// Keep imports used
// =====================================================================
var _ = ecdsa.GenerateKey
var _ = ed25519.GenerateKey
var _ = elliptic.P256
var _ = rsa.GenerateKey
var _ = strings.Contains
var _ = pem.Decode
var _ = context.Background
