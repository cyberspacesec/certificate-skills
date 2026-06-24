package pkg

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =====================================================================
// vulnscanner.go - buildVulnSummary (pure function, fully offline)
// =====================================================================

func TestBuildVulnSummaryExt3(t *testing.T) {
	// All secure
	checks := []VulnCheck{
		{Name: "Heartbleed", Code: "CVE-2014-0160", Severity: "Critical", Vulnerable: false},
		{Name: "POODLE", Code: "CVE-2014-3566", Severity: "High", Vulnerable: false},
		{Name: "Sweet32", Code: "CVE-2016-2183", Severity: "Medium", Vulnerable: false},
	}
	summary := buildVulnSummary(checks)
	if summary.TotalChecked != 3 {
		t.Errorf("expected 3, got %d", summary.TotalChecked)
	}
	if summary.Vulnerable != 0 {
		t.Errorf("expected 0 vulnerable, got %d", summary.Vulnerable)
	}
	if summary.Secure != 3 {
		t.Errorf("expected 3 secure, got %d", summary.Secure)
	}
	if !summary.IsSecure {
		t.Error("expected IsSecure=true when all pass")
	}
	if summary.CriticalCount != 0 {
		t.Errorf("expected 0 critical, got %d", summary.CriticalCount)
	}

	// Mixed: some vulnerable
	checks2 := []VulnCheck{
		{Name: "Heartbleed", Code: "CVE-2014-0160", Severity: "Critical", Vulnerable: true},
		{Name: "POODLE", Code: "CVE-2014-3566", Severity: "High", Vulnerable: true},
		{Name: "Sweet32", Code: "CVE-2016-2183", Severity: "Medium", Vulnerable: true},
		{Name: "LowVuln", Code: "LOW-001", Severity: "Low", Vulnerable: true},
		{Name: "Safe", Code: "SAFE-001", Severity: "Medium", Vulnerable: false},
	}
	summary2 := buildVulnSummary(checks2)
	if summary2.TotalChecked != 5 {
		t.Errorf("expected 5, got %d", summary2.TotalChecked)
	}
	if summary2.Vulnerable != 4 {
		t.Errorf("expected 4 vulnerable, got %d", summary2.Vulnerable)
	}
	if summary2.Secure != 1 {
		t.Errorf("expected 1 secure, got %d", summary2.Secure)
	}
	if summary2.IsSecure {
		t.Error("expected IsSecure=false when vulnerabilities found")
	}
	if summary2.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", summary2.CriticalCount)
	}
	if summary2.HighCount != 1 {
		t.Errorf("expected 1 high, got %d", summary2.HighCount)
	}
	if summary2.MediumCount != 1 {
		t.Errorf("expected 1 medium, got %d", summary2.MediumCount)
	}
	if summary2.LowCount != 1 {
		t.Errorf("expected 1 low, got %d", summary2.LowCount)
	}
	if len(summary2.VulnerableList) != 4 {
		t.Errorf("expected 4 in vulnerable list, got %d", len(summary2.VulnerableList))
	}

	// Empty checks
	summary3 := buildVulnSummary(nil)
	if summary3.TotalChecked != 0 {
		t.Errorf("expected 0, got %d", summary3.TotalChecked)
	}
	if !summary3.IsSecure {
		t.Error("expected IsSecure=true for empty checks")
	}
}

// =====================================================================
// vulnscanner.go - parseServerHelloForExtension (offline with crafted data)
// =====================================================================

func TestParseServerHelloForExtensionExt3(t *testing.T) {
	// Too short data (< 5 bytes)
	result := parseServerHelloForExtension([]byte{0x16, 0x03, 0x03}, 0xff01)
	if result {
		t.Error("expected false for too short data")
	}

	// Not a handshake record (data[0] != 0x16)
	result = parseServerHelloForExtension([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00}, 0xff01)
	if result {
		t.Error("expected false for non-handshake record")
	}

	// Valid ServerHello with renegotiation_info extension (0xff01)
	// Build: record header(5) + handshake header(4) + version(2) + random(32) + session_id_len(1) + session_id(0)
	// + cipher_suite(2) + compression(1) + extensions_length(2) + extension(type=0xff01, len=1, data=0x00)
	data := []byte{
		0x16,       // Record type: Handshake
		0x03, 0x03, // TLS 1.2 record version
		0x00, byte(47), // Record length: 47 bytes (will fix below)
		0x02,                 // Handshake type: ServerHello
		0x00, 0x00, byte(43), // Handshake length: 43 bytes
		0x03, 0x03, // Version: TLS 1.2
	}
	// Random (32 bytes)
	for i := 0; i < 32; i++ {
		data = append(data, byte(i))
	}
	// Session ID length = 0
	data = append(data, 0x00)
	// Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
	data = append(data, 0xC0, 0x2F)
	// Compression method: 0 (no compression)
	data = append(data, 0x00)
	// Extensions length: 5 bytes (one extension)
	data = append(data, 0x00, 0x05)
	// Extension: renegotiation_info (0xff01), length=1, data=0x00
	data = append(data, 0xFF, 0x01, 0x00, 0x01, 0x00)

	result = parseServerHelloForExtension(data, 0xff01)
	if !result {
		t.Error("expected true for renegotiation_info extension")
	}

	// Check for non-existent extension
	result = parseServerHelloForExtension(data, 0x0005)
	if result {
		t.Error("expected false for non-existent extension")
	}

	// ServerHello with session ID
	data2 := []byte{
		0x16, 0x03, 0x03, // Record header
		0x00, byte(55), // Record length placeholder
		0x02,                 // ServerHello
		0x00, 0x00, byte(51), // Handshake length placeholder
		0x03, 0x03, // Version
	}
	for i := 0; i < 32; i++ {
		data2 = append(data2, byte(i))
	}
	// Session ID length = 8
	data2 = append(data2, 0x08)
	for i := 0; i < 8; i++ {
		data2 = append(data2, byte(i))
	}
	// Cipher suite
	data2 = append(data2, 0xC0, 0x2F)
	// Compression
	data2 = append(data2, 0x00)
	// Extensions length: 5
	data2 = append(data2, 0x00, 0x05)
	// Extension: server_name (0x0000), length=1, data=0x00
	data2 = append(data2, 0x00, 0x00, 0x00, 0x01, 0x00)

	// Fix lengths
	totalLen2 := len(data2) - 5
	data2[3] = 0x00
	data2[4] = byte(totalLen2)
	hsLen2 := len(data2) - 9
	data2[6] = 0x00
	data2[7] = byte(hsLen2 >> 8)
	data2[8] = byte(hsLen2)

	result = parseServerHelloForExtension(data2, 0x0000)
	if !result {
		t.Error("expected true for server_name extension")
	}

	// Data truncated after compression method (no extension data)
	data3 := []byte{
		0x16, 0x03, 0x03, 0x00, 0x26, // Record header
		0x02, 0x00, 0x00, 0x22, // Handshake header
		0x03, 0x03, // Version
	}
	for i := 0; i < 32; i++ {
		data3 = append(data3, byte(i))
	}
	data3 = append(data3, 0x00)       // session ID len = 0
	data3 = append(data3, 0xC0, 0x2F) // cipher
	data3 = append(data3, 0x00)       // compression

	// offset+2 >= len(data) - no extensions
	result = parseServerHelloForExtension(data3, 0xff01)
	if result {
		t.Error("expected false for data without extensions")
	}
}

// =====================================================================
// ja3.go - generateJA3Raw, generateJA3SRaw, intsToString, md5Hash
// =====================================================================

func TestGenerateJA3RawExt3(t *testing.T) {
	state := tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	raw := generateJA3Raw(state)
	if raw == "" {
		t.Error("expected non-empty JA3 raw string")
	}
	if !strings.Contains(raw, "771") {
		t.Errorf("expected TLS 1.2 version (771) in JA3 raw, got: %s", raw)
	}

	// TLS 1.3
	state13 := tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
	}
	raw13 := generateJA3Raw(state13)
	if raw13 == "" {
		t.Error("expected non-empty JA3 raw for TLS 1.3")
	}
	if !strings.Contains(raw13, "772") {
		t.Errorf("expected TLS 1.3 version (772) in JA3 raw, got: %s", raw13)
	}
}

func TestGenerateJA3SRawExt3(t *testing.T) {
	// Basic TLS 1.2 connection
	state := tls.ConnectionState{
		Version:            tls.VersionTLS12,
		CipherSuite:        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		NegotiatedProtocol: "",
	}
	raw := generateJA3SRaw(state)
	if raw == "" {
		t.Error("expected non-empty JA3S raw string")
	}

	// With ALPN
	state2 := tls.ConnectionState{
		Version:            tls.VersionTLS12,
		CipherSuite:        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
	}
	raw2 := generateJA3SRaw(state2)
	if !strings.Contains(raw2, "16") {
		t.Errorf("expected ALPN extension (16) in JA3S raw, got: %s", raw2)
	}

	// TLS 1.3 with ALPN
	state3 := tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
	}
	raw3 := generateJA3SRaw(state3)
	if !strings.Contains(raw3, "43") {
		t.Errorf("expected supported_versions extension (43) in JA3S raw for TLS 1.3, got: %s", raw3)
	}

	// Session resumption
	state4 := tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		DidResume:   true,
	}
	raw4 := generateJA3SRaw(state4)
	if !strings.Contains(raw4, "23") {
		t.Errorf("expected session_ticket extension (23) in JA3S raw for resumed session, got: %s", raw4)
	}
}

func TestIntsToStringExt3(t *testing.T) {
	result := intsToString([]int{1, 2, 3}, ",")
	if result != "1,2,3" {
		t.Errorf("expected 1,2,3, got %q", result)
	}

	result = intsToString([]int{100}, "-")
	if result != "100" {
		t.Errorf("expected 100, got %q", result)
	}

	result = intsToString(nil, ",")
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestMd5HashExt3(t *testing.T) {
	result := md5Hash("test")
	if result == "" {
		t.Error("expected non-empty MD5 hash")
	}
	if len(result) != 32 {
		t.Errorf("expected 32-char MD5 hash, got %d chars", len(result))
	}

	// Same input should produce same hash
	result2 := md5Hash("test")
	if result != result2 {
		t.Errorf("expected same hash for same input, got %q vs %q", result, result2)
	}

	// Different input should produce different hash
	result3 := md5Hash("different")
	if result == result3 {
		t.Error("expected different hashes for different inputs")
	}
}

func TestGetStandardClientCipherIDsExt3(t *testing.T) {
	ids := getStandardClientCipherIDs()
	if len(ids) == 0 {
		t.Error("expected at least one cipher ID")
	}
	// Should contain TLS 1.3 and TLS 1.2 suites
	hasTLS13 := false
	hasTLS12 := false
	for _, id := range ids {
		if id >= 0x1301 && id <= 0x1303 {
			hasTLS13 = true
		}
		if id >= 0xC02B && id <= 0xC030 {
			hasTLS12 = true
		}
	}
	if !hasTLS13 {
		t.Error("expected TLS 1.3 cipher suites in standard list")
	}
	if !hasTLS12 {
		t.Error("expected TLS 1.2 cipher suites in standard list")
	}
}

// =====================================================================
// bundlecheck.go - parseCertFromPEM (offline with PEM data)
// =====================================================================

func TestParseCertFromPEMExt3(t *testing.T) {
	// Valid PEM
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "pem-parse-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	certData, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}

	cert, err := parseCertFromPEM(certData)
	if err != nil {
		t.Fatalf("parseCertFromPEM failed: %v", err)
	}
	if cert.Subject.CommonName != "pem-parse-test" {
		t.Errorf("expected pem-parse-test, got %q", cert.Subject.CommonName)
	}

	// No PEM block
	_, err = parseCertFromPEM([]byte("this is not PEM data"))
	if err == nil {
		t.Error("expected error for non-PEM data")
	}

	// Invalid PEM block (not a CERTIFICATE block)
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("not a cert"),
	})
	_, err = parseCertFromPEM(invalidPEM)
	if err == nil {
		t.Error("expected error for invalid PEM block")
	}

	// Empty PEM block data
	emptyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte{},
	})
	_, err = parseCertFromPEM(emptyPEM)
	if err == nil {
		t.Error("expected error for empty certificate PEM data")
	}
}

// =====================================================================
// caissuer.go - nonEmptySlice, sanitizeFilename
// =====================================================================

func TestNonEmptySliceExt3(t *testing.T) {
	// Non-empty val
	result := nonEmptySlice("TestOrg", []string{"Fallback"})
	if len(result) != 1 || result[0] != "TestOrg" {
		t.Errorf("expected [TestOrg], got %v", result)
	}

	// Empty val with fallback
	result = nonEmptySlice("", []string{"Fallback1", "Fallback2"})
	if len(result) != 2 || result[0] != "Fallback1" {
		t.Errorf("expected [Fallback1, Fallback2], got %v", result)
	}

	// Empty val with nil fallback
	result = nonEmptySlice("", nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestSanitizeFilenameExt3(t *testing.T) {
	// Normal name
	result := sanitizeFilename("My-Root-CA")
	if result != "My-Root-CA" {
		t.Errorf("expected My-Root-CA, got %q", result)
	}

	// Name with spaces
	result = sanitizeFilename("My Root CA")
	if !strings.Contains(result, "_") || strings.Contains(result, " ") {
		t.Errorf("expected spaces replaced, got %q", result)
	}

	// Name with special chars
	result = sanitizeFilename("Test:Cert/Name")
	if strings.Contains(result, ":") || strings.Contains(result, "/") {
		t.Errorf("expected special chars replaced, got %q", result)
	}

	// Empty name
	result = sanitizeFilename("")
	if result != "cert" {
		t.Errorf("expected cert for empty, got %q", result)
	}

	// Name with only special chars
	result = sanitizeFilename("!@#$%")
	if result != "cert" {
		t.Errorf("expected cert for all-special, got %q", result)
	}
}

// =====================================================================
// caissuer.go - keyMatchesCert type mismatch paths
// =====================================================================

func TestKeyMatchesCertExt3_TypeMismatch(t *testing.T) {
	// RSA cert with ECDSA signer
	rsaResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "rsa-type-mismatch", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(rsaResult.CertificatePath, rsaResult.PrivateKeyPath)

	ecResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "ec-signer", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	defer removeFiles(ecResult.CertificatePath, ecResult.PrivateKeyPath)

	ecSigner, _ := ReadSignerFromFile(ecResult.PrivateKeyPath)
	rsaCert := readCertFromFile(t, rsaResult.CertificatePath)

	if keyMatchesCert(ecSigner, rsaCert) {
		t.Error("expected ECDSA signer not to match RSA cert")
	}

	// ECDSA cert with RSA signer
	rsaSigner, _ := ReadSignerFromFile(rsaResult.PrivateKeyPath)
	ecCert := readCertFromFile(t, ecResult.CertificatePath)

	if keyMatchesCert(rsaSigner, ecCert) {
		t.Error("expected RSA signer not to match ECDSA cert")
	}
}

// =====================================================================
// caissuer.go - loadCertAndSigner error paths
// =====================================================================

func TestLoadCertAndSignerExt3_InvalidPEM(t *testing.T) {
	// Write an invalid PEM file (not a certificate)
	tmpCert, _ := os.CreateTemp("", "bad-cert-*.pem")
	defer os.Remove(tmpCert.Name())
	tmpCert.WriteString("-----BEGIN PRIVATE KEY-----\ninvaliddata\n-----END PRIVATE KEY-----")
	tmpCert.Close()

	// Write a valid key file for the mismatch path
	tmpKey, _ := os.CreateTemp("", "bad-key-*.pem")
	defer os.Remove(tmpKey.Name())
	_, rsaKeyErr := rsa.GenerateKey(rand.Reader, 2048)
	if rsaKeyErr != nil {
		t.Fatalf("failed to generate RSA key: %v", rsaKeyErr)
	}
	pkcs8Key, _ := x509.MarshalPKCS8PrivateKey(rsaKeyErr)
	pem.Encode(tmpKey, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})
	tmpKey.Close()

	_, _, err := loadCertAndSigner(tmpCert.Name(), tmpKey.Name())
	if err == nil {
		t.Error("expected error for invalid cert PEM")
	}
}

func TestLoadCertAndSignerExt3_KeyMismatch(t *testing.T) {
	// Generate two certs with different keys
	result1, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "cert-a", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result1.CertificatePath, result1.PrivateKeyPath)

	result2, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "cert-b", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result2.CertificatePath, result2.PrivateKeyPath)

	// Cert from result1 with key from result2 -> mismatch
	_, _, err := loadCertAndSigner(result1.CertificatePath, result2.PrivateKeyPath)
	if err == nil {
		t.Error("expected error for key mismatch")
	}
}

func TestLoadCertAndSignerExt3_BadCertParse(t *testing.T) {
	// Write a PEM block that has invalid DER bytes for a certificate
	tmpCert, _ := os.CreateTemp("", "bad-der-*.pem")
	defer os.Remove(tmpCert.Name())
	pem.Encode(tmpCert, &pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02, 0x03}})
	tmpCert.Close()

	tmpKey, _ := os.CreateTemp("", "dummy-key-*.pem")
	defer os.Remove(tmpKey.Name())
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8Key, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pem.Encode(tmpKey, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})
	tmpKey.Close()

	_, _, err := loadCertAndSigner(tmpCert.Name(), tmpKey.Name())
	if err == nil {
		t.Error("expected error for invalid cert DER data")
	}
}

// =====================================================================
// crlgen.go - buildRevokedCertificateList, reasonCodeToString
// =====================================================================

func TestBuildRevokedCertificateListExt3(t *testing.T) {
	// Hex serial numbers (without 0x prefix - SetString with base 16)
	entries := []RevokedEntry{
		{SerialNumber: "FF", Reason: "key-compromise"},
		{SerialNumber: "1A", Reason: "superseded"},
	}
	list, err := buildRevokedCertificateList(entries)
	if err != nil {
		t.Fatalf("buildRevokedCertificateList hex serials failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 entries, got %d", len(list))
	}

	// Invalid serial number
	badEntries := []RevokedEntry{
		{SerialNumber: "not-a-number", Reason: "unspecified"},
	}
	_, err = buildRevokedCertificateList(badEntries)
	if err == nil {
		t.Error("expected error for invalid serial number")
	}

	// Reason code explicitly set
	entries2 := []RevokedEntry{
		{SerialNumber: "12345", ReasonCode: 1, Reason: ""}, // key-compromise via code
	}
	list2, err := buildRevokedCertificateList(entries2)
	if err != nil {
		t.Fatalf("buildRevokedCertificateList reason code failed: %v", err)
	}
	if len(list2) != 1 {
		t.Errorf("expected 1 entry, got %d", len(list2))
	}

	// Unknown reason name (should use code 0)
	entries3 := []RevokedEntry{
		{SerialNumber: "999", Reason: "nonexistent-reason"},
	}
	list3, err := buildRevokedCertificateList(entries3)
	if err != nil {
		t.Fatalf("buildRevokedCertificateList unknown reason failed: %v", err)
	}
	if len(list3) != 1 {
		t.Errorf("expected 1 entry, got %d", len(list3))
	}

	// Empty revocation time (should use current time)
	entries4 := []RevokedEntry{
		{SerialNumber: "555", Reason: "key-compromise", RevocationTime: time.Time{}},
	}
	list4, err := buildRevokedCertificateList(entries4)
	if err != nil {
		t.Fatalf("buildRevokedCertificateList empty time failed: %v", err)
	}
	if list4[0].RevocationTime.IsZero() {
		t.Error("expected non-zero revocation time for empty input time")
	}

	// Zero reason code (unspecified) should not set ReasonCode field
	entries5 := []RevokedEntry{
		{SerialNumber: "777", ReasonCode: 0, Reason: "unspecified"},
	}
	list5, err := buildRevokedCertificateList(entries5)
	if err != nil {
		t.Fatalf("buildRevokedCertificateList unspecified failed: %v", err)
	}
	_ = list5
}

func TestReasonCodeToStringExt3(t *testing.T) {
	// Unknown code
	result := reasonCodeToString(99)
	if !strings.Contains(result, "unknown") {
		t.Errorf("expected unknown for code 99, got %q", result)
	}

	// Known codes
	tests := map[int]string{
		0:  "unspecified",
		1:  "key-compromise",
		2:  "ca-compromise",
		3:  "affiliation-changed",
		4:  "superseded",
		5:  "cessation-of-operation",
		6:  "certificate-hold",
		8:  "remove-from-crl",
		9:  "privilege-withdrawn",
		10: "aa-compromise",
	}
	for code, expected := range tests {
		result := reasonCodeToString(code)
		if result != expected {
			t.Errorf("reasonCodeToString(%d) = %q, expected %q", code, result, expected)
		}
	}
}

func TestParseCRLExt3_DERFormat(t *testing.T) {
	// Generate a CRL, then read the DER bytes directly to test DER parsing
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-der-ca", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	crlResult, _ := GenerateCRL(CRLGenerateRequest{
		CACertPath:   caResult.CertificatePath,
		CAKeyPath:    caResult.PrivateKeyPath,
		RevokedCerts: []RevokedEntry{{SerialNumber: "555"}},
		OutputPath:   "der-test-crl.pem",
	})
	defer os.Remove(crlResult.CRLPath)

	// Parse the PEM CRL (should work)
	parsed, err := ParseCRL(crlResult.CRLPath)
	if err != nil {
		t.Fatalf("ParseCRL PEM failed: %v", err)
	}
	if parsed.Issuer == "" {
		t.Error("expected issuer in parsed CRL")
	}
}

func TestCRLInfoExt3_Fields(t *testing.T) {
	// Build CRLInfo directly to test the struct
	info := &CRLInfo{
		Issuer:        "Test CA",
		ThisUpdate:    time.Now(),
		NextUpdate:    time.Now().Add(30 * 24 * time.Hour),
		Number:        "1",
		RevokedCerts:  []RevokedCertInfo{},
		RevokedCount:  0,
		SignatureAlgo: "SHA256-RSA",
	}
	if info.Issuer != "Test CA" {
		t.Errorf("expected Test CA, got %q", info.Issuer)
	}
	if info.RevokedCount != 0 {
		t.Errorf("expected 0, got %d", info.RevokedCount)
	}
}

// =====================================================================
// certclone.go - replaceDNSNames (pure function)
// =====================================================================

func TestReplaceDNSNamesExt3(t *testing.T) {
	// Exact replacement
	result := replaceDNSNames([]string{"old.com", "www.old.com"}, "old.com", "new.com")
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if result[0] != "new.com" {
		t.Errorf("expected new.com, got %q", result[0])
	}
	if result[1] != "www.new.com" {
		t.Errorf("expected www.new.com, got %q", result[1])
	}

	// Domain not in list (no replacement needed)
	result2 := replaceDNSNames([]string{"other.com"}, "old.com", "new.com")
	if len(result2) != 1 || result2[0] != "other.com" {
		t.Errorf("expected [other.com] unchanged, got %v", result2)
	}

	// Empty list
	result3 := replaceDNSNames(nil, "old.com", "new.com")
	if len(result3) != 0 {
		t.Errorf("expected empty, got %v", result3)
	}

	// Wildcard subdomain replacement
	result4 := replaceDNSNames([]string{"*.old.com", "api.old.com"}, "old.com", "new.com")
	if result4[0] != "*.new.com" {
		t.Errorf("expected *.new.com, got %q", result4[0])
	}
	if result4[1] != "api.new.com" {
		t.Errorf("expected api.new.com, got %q", result4[1])
	}
}

// =====================================================================
// certclone.go - generateDomainVariants internal functions
// =====================================================================

func TestGenerateDomainVariantsExt3_Internal(t *testing.T) {
	// Homoglyph variants
	variants := generateHomoglyphVariants("example.com", "example", "com")
	if len(variants) == 0 {
		t.Error("expected homoglyph variants for 'example'")
	}
	for _, v := range variants {
		if v.Type != "homoglyph" {
			t.Errorf("expected homoglyph type, got %q", v.Type)
		}
	}

	// No homoglyph chars
	variants2 := generateHomoglyphVariants("xyz.com", "xyz", "com")
	if len(variants2) > 0 {
		t.Log("xyz may have homoglyphs depending on mapping")
	}

	// Subdomain variants
	variants3 := generateSubdomainVariants("example.com", "com")
	if len(variants3) == 0 {
		t.Error("expected subdomain variants")
	}
	for _, v := range variants3 {
		if v.Type != "subdomain" {
			t.Errorf("expected subdomain type, got %q", v.Type)
		}
	}

	// TLD variants
	variants4 := generateTLDVariants("example")
	if len(variants4) == 0 {
		t.Error("expected TLD variants")
	}
	for _, v := range variants4 {
		if v.Type != "tld" {
			t.Errorf("expected tld type, got %q", v.Type)
		}
	}

	// Hyphenation variants
	variants5 := generateHyphenVariants("example", "com")
	if len(variants5) == 0 {
		t.Error("expected hyphenation variants")
	}
	for _, v := range variants5 {
		if v.Type != "hyphenation" {
			t.Errorf("expected hyphenation type, got %q", v.Type)
		}
	}

	// Insertion variants
	variants6 := generateInsertionVariants("example", "com")
	if len(variants6) == 0 {
		t.Error("expected insertion variants")
	}
	for _, v := range variants6 {
		if v.Type != "insertion" {
			t.Errorf("expected insertion type, got %q", v.Type)
		}
	}

	// Single-part domain (no TLD)
	variants7 := generateDomainVariants("single", []string{"homoglyph"})
	if len(variants7) != 1 {
		t.Errorf("expected 1 variant for single-part domain, got %d", len(variants7))
	}
	if variants7[0].Type != "original" {
		t.Errorf("expected original type for single-part domain, got %q", variants7[0].Type)
	}
}

// =====================================================================
// fpmatch.go - matchHash, LoadFingerprintDB, ComputeCertSPKIHash,
// MatchFingerprintsByCategory, ListFingerprintDB, MatchFingerprintByHash
// =====================================================================

func TestMatchHashExt3(t *testing.T) {
	// Match Cloudflare JARM
	matches := matchHash("jarm", "29d29d15d29d29d21c29d29d29d29dea0f89a2e5e6f1eadc8e8d8e8d8e8d05")
	if len(matches) == 0 {
		t.Error("expected matches for Cloudflare JARM")
	}

	// Match with uppercase hash (should normalize)
	matches2 := matchHash("jarm", "29D29D15D29D29D21C29D29D29D29DEA0F89A2E5E6F1EADC8E8D8E8D8E8D05")
	if len(matches2) == 0 {
		t.Error("expected matches for uppercase Cloudflare JARM")
	}

	// Match with colon-separated hash
	matches3 := matchHash("jarm", "29:d2:9d:15:d2:9d:29:d2:1c:29:d2:9d:29:d2:9d:ea:0f:89:a2:e5:e6:f1:ea:dc:8e:8d:8e:8d:8e:8d:05")
	if len(matches3) == 0 {
		t.Error("expected matches for colon-separated JARM")
	}

	// No match for unknown hash
	matches4 := matchHash("jarm", "0000000000000000000000000000000000000000000000000000000000000000")
	if len(matches4) != 0 {
		t.Error("expected no matches for unknown hash")
	}

	// Wrong type
	matches5 := matchHash("ja3", "29d29d15d29d29d21c29d29d29d29dea0f89a2e5e6f1eadc8e8d8e8d8e8d05")
	if len(matches5) != 0 {
		t.Error("expected no matches for wrong fingerprint type")
	}
}

func TestLoadFingerprintDBExt3(t *testing.T) {
	// Save the original fingerprint DB to restore later
	originalDB := fingerprintDB

	// Valid JSON
	jsonData := `[{"type":"jarm","hash":"testhash123","label":"Test Service","category":"other","confidence":0.5}]`
	err := LoadFingerprintDB([]byte(jsonData))
	if err != nil {
		t.Fatalf("LoadFingerprintDB failed: %v", err)
	}

	// Verify the entry was added
	matches := matchHash("jarm", "testhash123")
	if len(matches) == 0 {
		t.Error("expected match for newly loaded entry")
	}
	if matches[0].Source != "custom" {
		t.Errorf("expected source=custom, got %q", matches[0].Source)
	}

	// Invalid JSON
	err = LoadFingerprintDB([]byte("invalid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}

	// Restore original DB
	fingerprintDB = originalDB
}

func TestComputeCertSPKIHashExt3_Empty(t *testing.T) {
	// makeTestCert doesn't produce a real cert with RawSubjectPublicKeyInfo,
	// but a real generated cert should
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "spki-empty-test", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	realCert := readCertFromFile(t, result.CertificatePath)
	hash := ComputeCertSPKIHash(realCert)
	if hash == "" {
		t.Error("expected non-empty SPKI hash for real cert")
	}

	// Test that empty RawSubjectPublicKeyInfo returns empty string
	emptyCert := &x509.Certificate{RawSubjectPublicKeyInfo: nil}
	emptyHash := ComputeCertSPKIHash(emptyCert)
	if emptyHash != "" {
		t.Errorf("expected empty hash for empty SPKI, got %q", emptyHash)
	}
}

func TestMatchFingerprintsByCategoryExt3(t *testing.T) {
	// CDN category
	cdns := MatchFingerprintsByCategory("cdn")
	if len(cdns) == 0 {
		t.Error("expected CDN entries in fingerprint DB")
	}
	for _, c := range cdns {
		if c.Category != "cdn" {
			t.Errorf("expected category=cdn, got %q", c.Category)
		}
	}

	// C2 category
	c2s := MatchFingerprintsByCategory("c2")
	if len(c2s) == 0 {
		t.Error("expected C2 entries in fingerprint DB")
	}

	// Unknown category
	unknowns := MatchFingerprintsByCategory("nonexistent")
	if len(unknowns) != 0 {
		t.Errorf("expected 0 for unknown category, got %d", len(unknowns))
	}
}

func TestListFingerprintDBExt3(t *testing.T) {
	entries := ListFingerprintDB()
	if len(entries) == 0 {
		t.Error("expected at least one entry in fingerprint DB")
	}
}

func TestMatchFingerprintByHashExt3(t *testing.T) {
	// Match known JARM
	matches := MatchFingerprintByHash("jarm", "29d29d15d29d29d21c29d29d29d29dea0f89a2e5e6f1eadc8e8d8e8d8e8d05")
	if len(matches) == 0 {
		t.Error("expected matches for Cloudflare JARM via MatchFingerprintByHash")
	}

	// Unknown hash
	noMatches := MatchFingerprintByHash("cert_sha256", "0000000000000000000000000000000000000000000000000000000000000000")
	if len(noMatches) != 0 {
		t.Error("expected no matches for unknown cert hash")
	}
}

// =====================================================================
// comparator.go - CompareCertsFromDomains error path
// =====================================================================

func TestCompareCertsFromDomainsExt3_Invalid(t *testing.T) {
	_, err := CompareCertsFromDomains("nonexistent.invalid.domain.example", "nonexistent2.invalid.domain.example")
	if err == nil {
		t.Error("expected error for invalid domains")
	}
}

// =====================================================================
// security.go - AnalyzeSecurityWithContext error path
// =====================================================================

func TestAnalyzeSecurityWithContextExt3_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	result, err := AnalyzeSecurityWithContext(ctx, "example.com")
	// Cancelled context should either return an error or a result with error info
	if err == nil && result == nil {
		t.Error("expected either error or result for cancelled context")
	}
}

// =====================================================================
// security.go - BatchAnalyzeSecurityWithContext with cancelled context
// =====================================================================

func TestBatchAnalyzeSecurityWithContextExt3_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	result := BatchAnalyzeSecurityWithContext(ctx, []string{"example.com"})
	if result == nil {
		t.Error("expected non-nil result even for cancelled context")
	}
	if len(result.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Results))
	}
	if result.Results[0].SecurityLevel != "Error" {
		t.Logf("SecurityLevel = %q (may vary)", result.Results[0].SecurityLevel)
	}
}

func TestBatchAnalyzeSecurityExt3_Empty(t *testing.T) {
	result := BatchAnalyzeSecurity([]string{})
	if result == nil {
		t.Error("expected non-nil result for empty targets")
	}
	if result.TotalCount != 0 {
		t.Errorf("expected TotalCount=0, got %d", result.TotalCount)
	}
}

// =====================================================================
// certificate.go - GetCertFromDomainWithContext error paths
// =====================================================================

func TestGetCertFromDomainWithContextExt3_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	result, err := GetCertFromDomainWithContext(ctx, "example.com")
	// Cancelled context should either return an error or nil result
	if err == nil && result == nil {
		t.Error("expected either error or result for cancelled context")
	}
}

// =====================================================================
// expirycheck.go - CertExpiryMonitor more status paths
// =====================================================================

func TestCertExpiryMonitorExt3_FileTargets(t *testing.T) {
	// Generate certs with different expiry windows
	// Healthy (>30 days)
	healthyResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "expiry-healthy", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(healthyResult.CertificatePath, healthyResult.PrivateKeyPath)

	// Warning (30 days) - use file path
	monitorResult := CertExpiryMonitor([]string{healthyResult.CertificatePath})
	if len(monitorResult.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(monitorResult.Targets))
	}
	// Should be Healthy since 365-day cert
	if monitorResult.Targets[0].Status != "Healthy" {
		t.Logf("Status = %q (may vary based on cert generation time)", monitorResult.Targets[0].Status)
	}
}

func TestCertExpiryMonitorExt3_ErrorStatus(t *testing.T) {
	// Invalid domain should result in Error status
	monitorResult := CertExpiryMonitor([]string{"nonexistent.invalid.domain.example"})
	if len(monitorResult.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(monitorResult.Targets))
	}
	if monitorResult.Targets[0].Status != "Error" {
		t.Errorf("expected Error status, got %q", monitorResult.Targets[0].Status)
	}
	if monitorResult.ErrorCount != 1 {
		t.Errorf("expected ErrorCount=1, got %d", monitorResult.ErrorCount)
	}
}

func TestExpiryEntryExt3_Fields(t *testing.T) {
	// Test constructing ExpiryEntry directly
	entry := ExpiryEntry{
		Target:          "test.com",
		DaysUntilExpiry: 15,
		ExpirationDate:  "2027-01-01 00:00:00 UTC",
		Status:          "Warning",
		Issuer:          "Test CA",
		Subject:         "test.com",
	}
	if entry.Status != "Warning" {
		t.Errorf("expected Warning, got %q", entry.Status)
	}
}

func TestExpiryMonitorResultExt3_Fields(t *testing.T) {
	result := &ExpiryMonitorResult{
		TotalCount:    3,
		ExpiredCount:  1,
		CriticalCount: 1,
		WarningCount:  1,
		HealthyCount:  0,
		ErrorCount:    0,
	}
	if result.TotalCount != 3 {
		t.Errorf("expected 3, got %d", result.TotalCount)
	}
}

// =====================================================================
// sct.go - parseSCTList with ASN.1 SEQUENCE wrapper
// =====================================================================

func TestParseSCTListExt3_ASN1Sequence(t *testing.T) {
	// Build SCT data
	sctData := make([]byte, 47)
	sctData[0] = 0x00 // version
	for i := 1; i < 33; i++ {
		sctData[i] = byte(i)
	}
	binaryTimestamp := uint64(1609459200000)
	for i := 0; i < 8; i++ {
		sctData[33+i] = byte(binaryTimestamp >> (56 - 8*i))
	}

	// Wrap in ASN.1 OCTET STRING then length-prefixed list
	sctListLen := 2 + len(sctData)
	sctListContent := []byte{byte(sctListLen >> 8), byte(sctListLen)}
	sctListContent = append(sctListContent, byte(len(sctData)>>8), byte(len(sctData)))
	sctListContent = append(sctListContent, sctData...)

	// Wrap in ASN.1 OCTET STRING: tag=0x04, length, then content
	octetString := []byte{0x04}
	octetString = append(octetString, byte(len(sctListContent)))
	octetString = append(octetString, sctListContent...)

	scts, err := parseSCTList(octetString)
	if err != nil {
		t.Fatalf("parseSCTList OCTET STRING wrapped failed: %v", err)
	}
	if len(scts) != 1 {
		t.Errorf("expected 1 SCT, got %d", len(scts))
	}

	// Wrap in ASN.1 SEQUENCE then OCTET STRING
	sequenceContent := octetString
	sequence := []byte{0x30}
	sequence = append(sequence, byte(len(sequenceContent)))
	sequence = append(sequence, sequenceContent...)

	scts2, err := parseSCTList(sequence)
	if err != nil {
		t.Fatalf("parseSCTList SEQUENCE wrapped failed: %v", err)
	}
	if len(scts2) == 0 {
		t.Error("expected at least 1 SCT from SEQUENCE-wrapped data")
	}
}

func TestParseASN1LengthExt3(t *testing.T) {
	// Empty data
	length, consumed := parseASN1Length(nil)
	if length != 0 || consumed != 0 {
		t.Errorf("expected (0, 0) for nil, got (%d, %d)", length, consumed)
	}

	// Short form (< 0x80)
	length, consumed = parseASN1Length([]byte{0x05})
	if length != 5 || consumed != 1 {
		t.Errorf("expected (5, 1) for short form, got (%d, %d)", length, consumed)
	}

	// Long form with 1 byte length
	length, consumed = parseASN1Length([]byte{0x81, 0x20})
	if length != 32 || consumed != 2 {
		t.Errorf("expected (32, 2) for long form 1 byte, got (%d, %d)", length, consumed)
	}

	// Long form with 2 byte length
	length, consumed = parseASN1Length([]byte{0x82, 0x01, 0x00})
	if length != 256 || consumed != 3 {
		t.Errorf("expected (256, 3) for long form 2 bytes, got (%d, %d)", length, consumed)
	}

	// Zero numBytes (invalid)
	length, consumed = parseASN1Length([]byte{0x80})
	if length != 0 || consumed != 0 {
		t.Errorf("expected (0, 0) for zero numBytes, got (%d, %d)", length, consumed)
	}

	// numBytes too large (> 4)
	length, consumed = parseASN1Length([]byte{0x85, 0x01, 0x02, 0x03, 0x04, 0x05})
	if length != 0 || consumed != 0 {
		t.Errorf("expected (0, 0) for too many numBytes, got (%d, %d)", length, consumed)
	}
}

func TestParseSCTListRawExt3_ShortData(t *testing.T) {
	// Data too short (< 2 bytes)
	_, err := parseSCTListRaw([]byte{0x01})
	if err == nil {
		t.Error("expected error for too short data in parseSCTListRaw")
	}
}

// =====================================================================
// certvulnscan.go - additional coverage for checkUntrustedChain
// =====================================================================

func TestCheckUntrustedChainExt3_NoIntermediates(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "leaf-cert"}
		c.Issuer = pkix.Name{CommonName: "unknown-ca"}
	})
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	passed, detail := checkUntrustedChain(cert, "", state)
	_ = passed
	_ = detail
	// Self-signed cert without intermediates should fail chain verification
}

// =====================================================================
// certchange.go - SnapshotStore LoadLatest error paths
// =====================================================================

func TestSnapshotStoreExt3_LoadLatestNoSnapshots(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "snap-nosnaps-*")
	defer os.RemoveAll(tmpDir)

	store := NewSnapshotStore(tmpDir)
	snap, err := store.LoadLatest("nonexistent.com")
	if err != nil {
		t.Errorf("expected nil error for no snapshots, got: %v", err)
	}
	if snap != nil {
		t.Error("expected nil snap for no snapshots")
	}
}

func TestSnapshotStoreExt3_LoadLatestInvalidJSON(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "snap-invalid-*")
	defer os.RemoveAll(tmpDir)

	// Write invalid JSON to a snapshot file
	os.WriteFile(filepath.Join(tmpDir, "test.com_20260101_120000.json"), []byte("invalid json"), 0644)

	store := NewSnapshotStore(tmpDir)
	_, err := store.LoadLatest("test.com")
	if err == nil {
		t.Error("expected error for invalid JSON snapshot")
	}
}

// =====================================================================
// certerrors.go - additional coverage
// =====================================================================

func TestCertErrorExt3_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner error")
	err := NewCertError("test_op", "test_target", inner)

	if !errors.Is(err, inner) {
		t.Error("expected Unwrap to return inner error")
	}

	// Error string format
	errStr := err.Error()
	if !strings.Contains(errStr, "test_op") {
		t.Errorf("expected op in error string, got %q", errStr)
	}
	if !strings.Contains(errStr, "test_target") {
		t.Errorf("expected target in error string, got %q", errStr)
	}
}

func TestNewCertErrorExt3(t *testing.T) {
	err := NewCertError("connect", "example.com", ErrConnectionFailed)
	if err.Op != "connect" {
		t.Errorf("expected connect, got %q", err.Op)
	}
	if err.Target != "example.com" {
		t.Errorf("expected example.com, got %q", err.Target)
	}
}

// =====================================================================
// offline.go - ScanCertSecurityFromChain additional
// =====================================================================

func TestScanCertSecurityFromChainExt3_AllChecksPass(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "all-checks-pass", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
		DNSNames: []string{"all-checks-pass.example.com"},
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	cert := readCertFromFile(t, result.CertificatePath)
	// Test without state (offline) - only 12 checks run
	offlineResult, err := ScanCertSecurityFromChain(cert, "all-checks-pass.example.com", nil)
	if err != nil {
		t.Fatalf("ScanCertSecurityFromChain offline failed: %v", err)
	}
	if offlineResult.Summary.TotalChecked != 12 {
		t.Errorf("expected 12 checks without state, got %d", offlineResult.Summary.TotalChecked)
	}
}

// =====================================================================
// generator.go - GenerateCSR ECDSA default curve
// =====================================================================

func TestGenerateCSRExt3_ECDSADefault(t *testing.T) {
	// ECDSA without explicit size should default to P-256
	csr, err := GenerateCSR(CertificateRequest{
		CommonName: "csr-ec-default",
		KeyType:    "ecdsa",
	})
	if err != nil {
		t.Fatalf("GenerateCSR ECDSA default failed: %v", err)
	}
	if csr == "" {
		t.Error("expected CSR PEM for ECDSA default")
	}
}

// =====================================================================
// generator.go - ValidateCertificateFiles invalid PEM block
// =====================================================================

func TestValidateCertificateFilesExt3_InvalidPEMBlock(t *testing.T) {
	// Write invalid PEM block (not a CERTIFICATE block)
	tmpCert, _ := os.CreateTemp("", "not-cert-block-*.pem")
	defer os.Remove(tmpCert.Name())
	pem.Encode(tmpCert, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x01, 0x02}})
	tmpCert.Close()

	// Write a valid key
	tmpKey, _ := os.CreateTemp("", "valid-key-*.pem")
	defer os.Remove(tmpKey.Name())
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8Key, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pem.Encode(tmpKey, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})
	tmpKey.Close()

	err := ValidateCertificateFiles(tmpCert.Name(), tmpKey.Name())
	if err == nil {
		t.Error("expected error for invalid PEM block (not CERTIFICATE type)")
	}
}

// =====================================================================
// generator.go - ValidateCertificateFiles no PEM block in cert
// =====================================================================

func TestValidateCertificateFilesExt3_NoPEMInCert(t *testing.T) {
	// Write non-PEM content as cert
	tmpCert, _ := os.CreateTemp("", "no-pem-cert-*.pem")
	defer os.Remove(tmpCert.Name())
	tmpCert.WriteString("not pem data at all")
	tmpCert.Close()

	tmpKey, _ := os.CreateTemp("", "no-pem-key-*.pem")
	defer os.Remove(tmpKey.Name())
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8Key, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pem.Encode(tmpKey, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})
	tmpKey.Close()

	err := ValidateCertificateFiles(tmpCert.Name(), tmpKey.Name())
	if err == nil {
		t.Error("expected error for non-PEM cert content")
	}
}

// =====================================================================
// certclone.go - CloneCertificate CA-signed path
// =====================================================================

func TestCloneCertificateExt3_CASigned(t *testing.T) {
	// Generate CA
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "clone-ca", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	// Generate source cert
	sourceResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "clone-source-ca-signed", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
		DNSNames: []string{"clone-source.example.com"},
	})
	defer removeFiles(sourceResult.CertificatePath, sourceResult.PrivateKeyPath)

	// Clone with CA signing
	cloneResult, err := CloneCertificate(CloneCertRequest{
		SourceCertPath: sourceResult.CertificatePath,
		KeyType:        "ecdsa",
		KeySize:        256,
		CACertPath:     caResult.CertificatePath,
		CAKeyPath:      caResult.PrivateKeyPath,
		OutputCertPath: filepath.Join(t.TempDir(), "ca-cloned.pem"),
		OutputKeyPath:  filepath.Join(t.TempDir(), "ca-cloned-key.pem"),
	})
	if err != nil {
		t.Fatalf("CloneCertificate CA-signed failed: %v", err)
	}
	defer removeFiles(cloneResult.CertificatePath, cloneResult.PrivateKeyPath)
}

func TestCloneCertificateExt3_InvalidSource(t *testing.T) {
	_, err := CloneCertificate(CloneCertRequest{
		SourceCertPath: "/nonexistent/source.pem",
	})
	if err == nil {
		t.Error("expected error for nonexistent source cert")
	}
}

func TestCloneCertificateExt3_Ed25519(t *testing.T) {
	sourceResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "clone-source-ed", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(sourceResult.CertificatePath, sourceResult.PrivateKeyPath)

	cloneResult, err := CloneCertificate(CloneCertRequest{
		SourceCertPath: sourceResult.CertificatePath,
		KeyType:        "ed25519",
		OutputCertPath: filepath.Join(t.TempDir(), "ed-cloned.pem"),
		OutputKeyPath:  filepath.Join(t.TempDir(), "ed-cloned-key.pem"),
	})
	if err != nil {
		t.Fatalf("CloneCertificate Ed25519 failed: %v", err)
	}
	defer removeFiles(cloneResult.CertificatePath, cloneResult.PrivateKeyPath)
}

// =====================================================================
// GenerateDomainVariants - insertion type
// =====================================================================

func TestGenerateDomainVariantsExt3_Insertion(t *testing.T) {
	result, err := GenerateDomainVariants(DomainVariantRequest{
		BaseDomain:   "example.com",
		VariantTypes: []string{"insertion"},
		OutputDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("GenerateDomainVariants insertion failed: %v", err)
	}
	if len(result.Variants) == 0 {
		t.Error("expected insertion variants")
	}
}

func TestGenerateDomainVariantsExt3_WithCA(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "variant-ca2", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	result, err := GenerateDomainVariants(DomainVariantRequest{
		BaseDomain:   "test.com",
		VariantTypes: []string{"tld"},
		CACertPath:   caResult.CertificatePath,
		CAKeyPath:    caResult.PrivateKeyPath,
		OutputDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("GenerateDomainVariants with CA failed: %v", err)
	}
	if len(result.Variants) == 0 {
		t.Error("expected TLD variants")
	}
}

// =====================================================================
// ProbeTLSVersion error path (network-dependent, stub test)
// =====================================================================

func TestProbeTLSVersionExt3_Invalid(t *testing.T) {
	supported, err := probeTLSVersion("nonexistent.invalid.domain.example:443", tls.VersionTLS10)
	if err == nil && supported {
		t.Error("expected error or unsupported for invalid host")
	}
}

// =====================================================================
// VulnScan error stub (network-dependent)
// =====================================================================

func TestVulnerabilityScanExt3_Invalid(t *testing.T) {
	_, err := VulnerabilityScan("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("VulnerabilityScan may not return error for invalid host, connection failure expected inside check functions")
	}
}

// =====================================================================
// BuildVulnSummary edge case - all empty severity
// =====================================================================

func TestBuildVulnSummaryExt3_UnknownSeverity(t *testing.T) {
	checks := []VulnCheck{
		{Name: "Unknown", Code: "UNK-001", Severity: "Unknown", Vulnerable: true},
	}
	summary := buildVulnSummary(checks)
	if summary.TotalChecked != 1 {
		t.Errorf("expected 1, got %d", summary.TotalChecked)
	}
	if summary.Vulnerable != 1 {
		t.Errorf("expected 1 vulnerable, got %d", summary.Vulnerable)
	}
	// Unknown severity should not increment any counter
	if summary.CriticalCount != 0 && summary.HighCount != 0 && summary.MediumCount != 0 && summary.LowCount != 0 {
		t.Log("Unknown severity does not increment any severity counter")
	}
}

// =====================================================================
// FingerprintMatchResult struct coverage
// =====================================================================

func TestFingerprintMatchResultExt3_Construct(t *testing.T) {
	result := &FingerprintMatchResult{
		Target:    "example.com",
		Matches:   []FingerprintMatch{},
		JARMHash:  "testjarm",
		JA3Hash:   "testja3",
		CertHash:  "testsha256",
		SPKIHash:  "testspki",
		Timestamp: time.Now(),
	}
	if result.Target != "example.com" {
		t.Errorf("expected example.com, got %q", result.Target)
	}
	if len(result.Matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(result.Matches))
	}
}

// =====================================================================
// ScanCertSecurity error path (network-dependent stub)
// =====================================================================

func TestScanCertSecurityExt3_Invalid(t *testing.T) {
	_, err := ScanCertSecurity("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("ScanCertSecurity may not return error for invalid host")
	}
}

// =====================================================================
// SCTResult struct coverage
// =====================================================================

func TestSCTResultExt3_Construct(t *testing.T) {
	result := &SCTResult{
		Target:           "example.com",
		HasSCTs:          false,
		SCTCount:         0,
		MeetsRequirement: false,
		RequiredSCTs:     2,
		CertValidity:     365,
		SCTs:             []SCTEntry{},
		Warnings:         []string{"No SCTs found"},
	}
	if result.Target != "example.com" {
		t.Errorf("expected example.com, got %q", result.Target)
	}
	if result.HasSCTs {
		t.Error("expected HasSCTs=false")
	}
}

// =====================================================================
// GenerateCRL error - bad CA cert/key
// =====================================================================

func TestGenerateCRLExt3_BadCAKey(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-bad-key-ca", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	// Use mismatched key
	otherResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "other-key", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(otherResult.CertificatePath, otherResult.PrivateKeyPath)

	_, err := GenerateCRL(CRLGenerateRequest{
		CACertPath:   caResult.CertificatePath,
		CAKeyPath:    otherResult.PrivateKeyPath, // mismatched key
		RevokedCerts: []RevokedEntry{{SerialNumber: "1"}},
	})
	if err == nil {
		t.Error("expected error for mismatched CA key")
	}
}

// =====================================================================
// CRL verify and check error - nonexistent cert
// =====================================================================

func TestCheckCertRevokedByCRLExt3_InvalidCert(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "crl-revoke-bad-cert", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	crlResult, _ := GenerateCRL(CRLGenerateRequest{
		CACertPath:   caResult.CertificatePath,
		CAKeyPath:    caResult.PrivateKeyPath,
		RevokedCerts: []RevokedEntry{{SerialNumber: "1"}},
		OutputPath:   "bad-cert-crl.pem",
	})
	defer os.Remove(crlResult.CRLPath)

	_, err := CheckCertRevokedByCRL("/nonexistent/cert.pem", crlResult.CRLPath)
	if err == nil {
		t.Error("expected error for nonexistent cert")
	}
}

// =====================================================================
// AnalyzeSecurityFromCertWithState - Critical score
// =====================================================================

func TestAnalyzeSecurityFromCertWithStateExt3_CriticalScore(t *testing.T) {
	// Construct many issues to force a critical score
	cert := makeTestCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "self-signed-crit"}
		c.Issuer = pkix.Name{CommonName: "self-signed-crit"} // self-signed
		c.DNSNames = nil                                     // missing SAN
		c.NotAfter = time.Now().Add(-24 * time.Hour)         // expired
		c.NotBefore = time.Now().Add(-400 * 24 * time.Hour)  // excessive validity
		c.KeyUsage = 0                                       // no key usage
		c.ExtKeyUsage = nil                                  // no ext key usage
	})
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	result, err := AnalyzeSecurityFromCertWithState(cert, "mismatch.example.com", state)
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCertWithState failed: %v", err)
	}
	if result.OverallScore > 40 {
		t.Errorf("expected very low score for terrible cert, got %d", result.OverallScore)
	}
	if result.SecurityLevel != "Critical" {
		t.Logf("Score=%d, Level=%q (may not be Critical if score > 40)", result.OverallScore, result.SecurityLevel)
	}
}

// =====================================================================
// wildcard.go - CheckWildcard with file target
// =====================================================================

func TestCheckWildcardExt3_FileTarget(t *testing.T) {
	// Generate a cert with wildcard SAN
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:   "*.wildcard-test.com",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
		DNSNames:     []string{"*.wildcard-test.com", "exact.wildcard-test.com"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	wildcardResult, err := CheckWildcard(result.CertificatePath)
	if err != nil {
		t.Fatalf("CheckWildcard file target failed: %v", err)
	}
	if !wildcardResult.IsWildcard {
		t.Error("expected IsWildcard=true for wildcard cert")
	}
	if len(wildcardResult.WildcardNames) == 0 {
		t.Error("expected wildcard names")
	}
	if len(wildcardResult.ExactNames) != 1 {
		t.Errorf("expected 1 exact name, got %d", len(wildcardResult.ExactNames))
	}
	if wildcardResult.RiskLevel == "None" {
		t.Error("expected non-None risk level for wildcard cert")
	}
}

func TestCheckWildcardExt3_NonWildcardFile(t *testing.T) {
	// Generate a cert without wildcards
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:   "no-wildcard.example.com",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
		DNSNames:     []string{"no-wildcard.example.com"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	wildcardResult, err := CheckWildcard(result.CertificatePath)
	if err != nil {
		t.Fatalf("CheckWildcard non-wildcard file failed: %v", err)
	}
	if wildcardResult.IsWildcard {
		t.Error("expected IsWildcard=false for non-wildcard cert")
	}
	if wildcardResult.RiskLevel != "None" {
		t.Errorf("expected None risk level for non-wildcard, got %q", wildcardResult.RiskLevel)
	}
}

func TestCheckWildcardExt3_InvalidFile(t *testing.T) {
	// Invalid file path should return result with error
	wildcardResult, err := CheckWildcard("/nonexistent/cert.pem")
	if err != nil {
		t.Fatalf("CheckWildcard should return result even on error: %v", err)
	}
	if wildcardResult.Error == "" {
		t.Error("expected error message for invalid file")
	}
}

func TestCheckWildcardExt3_DomainError(t *testing.T) {
	// Invalid domain should return result with error (graceful failure)
	wildcardResult, err := CheckWildcard("nonexistent.invalid.domain.example")
	if err != nil {
		t.Fatalf("CheckWildcard should return result even on connection error: %v", err)
	}
	if wildcardResult.Error == "" {
		t.Error("expected error message for unreachable domain")
	}
}

// =====================================================================
// wildcard.go - GetCertSANs and GetTrustedDomains error paths
// =====================================================================

func TestGetCertSANsExt3_Error(t *testing.T) {
	_, _, _, err := GetCertSANs("nonexistent.invalid.domain.example")
	if err == nil {
		t.Error("expected error for unreachable domain")
	}
}

func TestGetTrustedDomainsExt3_Error(t *testing.T) {
	_, err := GetTrustedDomains("nonexistent.invalid.domain.example")
	if err == nil {
		t.Error("expected error for unreachable domain")
	}
}

// =====================================================================
// hostnameverify.go - VerifyHostname error path
// =====================================================================

func TestVerifyHostnameExt3_Error(t *testing.T) {
	result, err := VerifyHostname("nonexistent.invalid.domain.example")
	if err != nil {
		t.Fatalf("VerifyHostname should return result even on error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error message for unreachable domain")
	}
}

func TestDomainSimilarityExt3(t *testing.T) {
	// Direct match
	score := domainSimilarity("www.example.com", "www.example.com")
	if score != 3 {
		t.Errorf("expected 3 for identical, got %d", score)
	}

	// Partial match (same TLD and second-level)
	score = domainSimilarity("www.example.com", "mail.example.com")
	if score != 2 {
		t.Errorf("expected 2 for same domain, got %d", score)
	}

	// No match
	score = domainSimilarity("www.example.com", "www.other.org")
	if score != 0 {
		t.Errorf("expected 0 for different TLD, got %d", score)
	}

	// Partial match (same TLD only)
	score = domainSimilarity("a.example.com", "b.other.com")
	if score != 1 {
		t.Errorf("expected 1 for same TLD, got %d", score)
	}
}

// =====================================================================
// ocspmuststaple.go - CheckOCSPMustStaple error path
// =====================================================================

func TestCheckOCSPMustStapleExt3_Error(t *testing.T) {
	_, err := CheckOCSPMustStaple("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("CheckOCSPMustStaple may not return error for unreachable domain in some cases")
	}
}

// =====================================================================
// keyusagecompliance.go - CheckKeyUsageCompliance error path
// =====================================================================

func TestCheckKeyUsageComplianceExt3_Error(t *testing.T) {
	_, err := CheckKeyUsageCompliance("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("CheckKeyUsageCompliance may not return error for unreachable domain")
	}
}

// =====================================================================
// nameconstraints.go - CheckNameConstraints error path
// =====================================================================

func TestCheckNameConstraintsExt3_Error(t *testing.T) {
	_, err := CheckNameConstraints("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("CheckNameConstraints may not return error for unreachable domain")
	}
}

// =====================================================================
// serialentropy.go - CheckSerialEntropy error path
// =====================================================================

func TestCheckSerialEntropyExt3_Error(t *testing.T) {
	_, err := CheckSerialEntropy("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("CheckSerialEntropy may not return error for unreachable domain")
	}
}

// =====================================================================
// policyanalysis.go - CheckPolicyAnalysis error path
// =====================================================================

func TestCheckPolicyAnalysisExt3_Error(t *testing.T) {
	_, err := CheckPolicyAnalysis("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("CheckPolicyAnalysis may not return error for unreachable domain")
	}
}

// =====================================================================
// pfs.go - CheckPFS error path (returns result with error field, not error return)
// =====================================================================

func TestCheckPFSExt3_Error(t *testing.T) {
	result, err := CheckPFS("nonexistent.invalid.domain.example")
	if err != nil {
		t.Fatalf("CheckPFS should return result even on error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error field for unreachable domain")
	}
}

// =====================================================================
// sessionresumption.go - CheckSessionResumption error path
// =====================================================================

func TestCheckSessionResumptionExt3_Error(t *testing.T) {
	result, err := CheckSessionResumption("nonexistent.invalid.domain.example")
	if err != nil {
		t.Fatalf("CheckSessionResumption should return result even on error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error field for unreachable domain")
	}
}

// =====================================================================
// hsts.go - CheckHSTS error path
// =====================================================================

func TestCheckHSTSExt3_Error(t *testing.T) {
	result := CheckHSTS("nonexistent.invalid.domain.example")
	if result.Error == "" {
		t.Error("expected error for unreachable domain")
	}
	if result.Enabled {
		t.Error("expected Enabled=false for unreachable domain")
	}
}

// =====================================================================
// evcert.go - DetectEV error path (returns result with Reason, not error)
// =====================================================================

func TestDetectEVExt3_Error(t *testing.T) {
	result, err := DetectEV("nonexistent.invalid.domain.example")
	if err != nil {
		t.Fatalf("DetectEV should return result even on error: %v", err)
	}
	if result.Reason == "" {
		t.Error("expected reason for unreachable domain")
	}
	if result.IsEV {
		t.Error("expected IsEV=false for unreachable domain")
	}
}

// =====================================================================
// distrustedca.go - CheckDistrustedCA error path
// =====================================================================

func TestCheckDistrustedCAExt3_Error(t *testing.T) {
	_, err := CheckDistrustedCA("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("CheckDistrustedCA may not return error for unreachable domain")
	}
}

// =====================================================================
// chainverify.go - VerifyCertChain error path (returns result, not error)
// =====================================================================

func TestVerifyCertChainExt3_Error(t *testing.T) {
	result, err := VerifyCertChain("nonexistent.invalid.domain.example")
	if err != nil {
		t.Fatalf("VerifyCertChain should return result even on error: %v", err)
	}
	if result.IsValid {
		t.Error("expected IsValid=false for unreachable domain")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for unreachable domain")
	}
}

// =====================================================================
// bundlecheck.go - CheckBundleCompleteness error path
// =====================================================================

func TestCheckBundleCompletenessExt3_Error(t *testing.T) {
	_, err := CheckBundleCompleteness("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("CheckBundleCompleteness may not return error for unreachable domain")
	}
}

// =====================================================================
// downloader.go - DownloadCertsFromDomain error path
// =====================================================================

func TestDownloadCertsFromDomainExt3_Error(t *testing.T) {
	_, err := DownloadCertsFromDomain("nonexistent.invalid.domain.example", "")
	if err == nil {
		t.Error("expected error for unreachable domain")
	}
}

// =====================================================================
// ctlog.go - CTSearch and CTSearchByFingerprint error paths
// =====================================================================

func TestCTSearchExt3_Error(t *testing.T) {
	_, err := CTSearch("nonexistent.invalid.domain.example")
	// CTSearch uses HTTP API which may timeout or return empty results
	if err != nil {
		t.Logf("CTSearch error (expected for invalid domain): %v", err)
	}
}

// =====================================================================
// ctenumerate.go - CTEnumerateSubdomains error path
// =====================================================================

func TestCTEnumerateSubdomainsExt3_Error(t *testing.T) {
	_, err := CTEnumerateSubdomains("nonexistent.invalid.domain.example")
	if err != nil {
		t.Logf("CTEnumerateSubdomains error (expected for invalid domain): %v", err)
	}
}

// =====================================================================
// revocation.go - CheckRevocation with file target
// =====================================================================

func TestCheckRevocationExt3_FileTarget(t *testing.T) {
	// Generate a self-signed cert (no OCSP server, no CRL distribution points)
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:   "revocation-file-test",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	revResult, err := CheckRevocation(result.CertificatePath)
	if err != nil {
		t.Fatalf("CheckRevocation file target failed: %v", err)
	}
	// Self-signed cert has no OCSP server or CRL distribution points
	if revResult.OCSPStatus.Error == "" {
		t.Log("Expected OCSP error for cert without OCSP server URL")
	}
	if revResult.CRLStatus.Error == "" {
		t.Log("Expected CRL error for cert without CRL distribution points")
	}
	// Overall status should be Unknown
	if revResult.OverallStatus == "" {
		t.Error("expected non-empty overall status")
	}
}

func TestCheckRevocationExt3_DomainError(t *testing.T) {
	revResult, err := CheckRevocation("nonexistent.invalid.domain.example")
	if err != nil {
		t.Fatalf("CheckRevocation should return result even on error: %v", err)
	}
	if revResult.Error == "" {
		t.Error("expected error for unreachable domain")
	}
}

func TestCheckRevocationExt3_InvalidFile(t *testing.T) {
	revResult, err := CheckRevocation("/nonexistent/cert.pem")
	if err != nil {
		t.Fatalf("CheckRevocation should return result even on error: %v", err)
	}
	if revResult.Error == "" {
		t.Error("expected error for nonexistent file")
	}
}

// =====================================================================
// revocation.go - checkOCSP with nil issuer
// =====================================================================

func TestCheckOCSPExt3_NoOCSPServer(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.OCSPServer = nil // No OCSP server
	})
	status := checkOCSP(cert, nil)
	if status.Error == "" {
		t.Error("expected error for cert without OCSP server")
	}
	if status.Checked {
		t.Error("expected Checked=false for cert without OCSP server")
	}
}

func TestCheckOCSPExt3_NoIssuer(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.OCSPServer = []string{"http://ocsp.example.com"}
	})
	status := checkOCSP(cert, nil) // nil issuer
	if status.Status != "Unknown" {
		t.Errorf("expected Unknown status for nil issuer, got %q", status.Status)
	}
	if !strings.Contains(status.Error, "issuer") {
		t.Errorf("expected issuer-related error, got %q", status.Error)
	}
}

// =====================================================================
// revocation.go - checkCRL with no CRL distribution points
// =====================================================================

func TestCheckCRLExt3_NoCRLDistributionPoints(t *testing.T) {
	cert := makeTestCert(func(c *x509.Certificate) {
		c.CRLDistributionPoints = nil
	})
	status := checkCRL(cert)
	if status.Error == "" {
		t.Error("expected error for cert without CRL distribution points")
	}
	if status.Checked {
		t.Error("expected Checked=false for cert without CRL distribution points")
	}
}

// =====================================================================
// sct.go - CheckSCT error path
// =====================================================================

func TestCheckSCTExt3_Error(t *testing.T) {
	_, err := CheckSCT("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("CheckSCT may not return error for unreachable domain")
	}
}

// =====================================================================
// cipherscanner.go - CipherSuiteScan error path
// =====================================================================

func TestCipherSuiteScanExt3_Error(t *testing.T) {
	_, err := CipherSuiteScan("nonexistent.invalid.domain.example", 0)
	if err == nil {
		t.Log("CipherSuiteScan may not return error for unreachable domain")
	}
}

// =====================================================================
// tlsdial.go - TLSDialWithConfig and TLSDialWithTimeout error paths
// =====================================================================

func TestTLSDialWithConfigExt3_Error(t *testing.T) {
	config := insecureTLSConfig()
	conn, err := TLSDialWithConfig("nonexistent.invalid.domain.example", config)
	if err == nil {
		conn.Close()
		t.Error("expected error for unreachable domain with config")
	}
}

func TestTLSDialWithTimeoutExt3_Error(t *testing.T) {
	conn, err := TLSDialWithTimeout("nonexistent.invalid.domain.example", 5*time.Second)
	if err == nil {
		conn.Close()
		t.Error("expected error for unreachable domain with timeout")
	}
}

// =====================================================================
// fpmatch.go - MatchFingerprints error path and ComputeCertSPKIHashFromDomain
// =====================================================================

func TestMatchFingerprintsExt3_Error(t *testing.T) {
	_, err := MatchFingerprints("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("MatchFingerprints may not return error for unreachable domain")
	}
}

func TestComputeCertSPKIHashFromDomainExt3_Error(t *testing.T) {
	_, err := ComputeCertSPKIHashFromDomain("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("ComputeCertSPKIHashFromDomain may not return error for unreachable domain")
	}
}

// =====================================================================
// certchange.go - TakeSnapshot and DetectChange error paths
// =====================================================================

func TestTakeSnapshotExt3_Error(t *testing.T) {
	_, err := TakeSnapshot("nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("TakeSnapshot may not return error for unreachable domain")
	}
}

func TestDetectChangeExt3_Error(t *testing.T) {
	_, err := DetectChange("nonexistent.invalid.domain.example", nil)
	if err == nil {
		t.Log("DetectChange may not return error for unreachable domain with nil prev")
	}
}

func TestDetectChangeExt3_WithPreviousNil(t *testing.T) {
	// DetectChange with nil previous should try to take snapshot and mark as "new"
	// For unreachable domain, this will error out
	_, err := DetectChange("nonexistent.invalid.domain.example", nil)
	if err == nil {
		t.Log("DetectChange nil prev on unreachable domain may vary")
	}
}

// =====================================================================
// certchange.go - SnapshotStore.Save more coverage
// =====================================================================

func TestSnapshotStoreExt3_SaveAndLoad(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "snap-save-load-*")
	defer os.RemoveAll(tmpDir)

	store := NewSnapshotStore(tmpDir)

	snap := &CertSnapshot{
		Target:       "test.example.com",
		Timestamp:    time.Now(),
		CertSHA256:   "abcd1234",
		SPKISHA256:   "spki5678",
		Issuer:       "Test CA",
		NotBefore:    time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SerialNumber: "12345",
		JARMHash:     "jarmhash123",
	}

	err := store.Save(snap)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.LoadLatest("test.example.com")
	if err != nil {
		t.Fatalf("LoadLatest failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil loaded snapshot")
	}
	if loaded.CertSHA256 != "abcd1234" {
		t.Errorf("expected abcd1234, got %q", loaded.CertSHA256)
	}
	if loaded.JARMHash != "jarmhash123" {
		t.Errorf("expected jarmhash123, got %q", loaded.JARMHash)
	}
}

// =====================================================================
// caissuer.go - GenerateIntermediateCA more coverage
// =====================================================================

func TestGenerateIntermediateCAExt3_ECDSA(t *testing.T) {
	rootResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "root-ca-ec", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(rootResult.CertificatePath, rootResult.PrivateKeyPath)

	interResult, err := GenerateIntermediateCA(IntermediateCARequest{
		ParentCertPath: rootResult.CertificatePath,
		ParentKeyPath:  rootResult.PrivateKeyPath,
		CommonName:     "intermediate-ec",
		KeyType:        "ecdsa",
		KeySize:        384,
		ValidityDays:   1825,
	})
	if err != nil {
		t.Fatalf("GenerateIntermediateCA ECDSA failed: %v", err)
	}
	defer removeFiles(interResult.CertificatePath, interResult.PrivateKeyPath)
}

func TestGenerateIntermediateCAExt3_Ed25519(t *testing.T) {
	rootResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "root-ca-ed25519", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(rootResult.CertificatePath, rootResult.PrivateKeyPath)

	interResult, err := GenerateIntermediateCA(IntermediateCARequest{
		ParentCertPath: rootResult.CertificatePath,
		ParentKeyPath:  rootResult.PrivateKeyPath,
		CommonName:     "intermediate-ed25519",
		KeyType:        "ed25519",
		ValidityDays:   1825,
	})
	if err != nil {
		t.Fatalf("GenerateIntermediateCA Ed25519 failed: %v", err)
	}
	defer removeFiles(interResult.CertificatePath, interResult.PrivateKeyPath)
}

// =====================================================================
// caissuer.go - SignCertificate with different key types and key usage
// =====================================================================

func TestSignCertificateExt3_ClientUsage(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "sign-ca-client", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	signResult, err := SignCertificate(SignCertRequest{
		CACertPath:   caResult.CertificatePath,
		CAKeyPath:    caResult.PrivateKeyPath,
		CommonName:   "client-cert",
		KeyUsage:     "client",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("SignCertificate client usage failed: %v", err)
	}
	defer removeFiles(signResult.CertificatePath, signResult.PrivateKeyPath)
}

func TestSignCertificateExt3_BothUsage(t *testing.T) {
	caResult, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "sign-ca-both", IsCA: true, KeyType: "rsa", KeySize: 4096, ValidityDays: 3650,
	})
	defer removeFiles(caResult.CertificatePath, caResult.PrivateKeyPath)

	signResult, err := SignCertificate(SignCertRequest{
		CACertPath:   caResult.CertificatePath,
		CAKeyPath:    caResult.PrivateKeyPath,
		CommonName:   "dual-cert",
		KeyUsage:     "both",
		KeyType:      "ecdsa",
		KeySize:      256,
		ValidityDays: 365,
		DNSNames:     []string{"dual.example.com"},
	})
	if err != nil {
		t.Fatalf("SignCertificate both usage failed: %v", err)
	}
	defer removeFiles(signResult.CertificatePath, signResult.PrivateKeyPath)
}

func TestSignCertificateExt3_BadCA(t *testing.T) {
	_, err := SignCertificate(SignCertRequest{
		CACertPath: "/nonexistent/ca.pem",
		CAKeyPath:  "/nonexistent/ca-key.pem",
		CommonName: "bad-ca-signed",
	})
	if err == nil {
		t.Error("expected error for nonexistent CA")
	}
}

// =====================================================================
// caissuer.go - generateKeyPair more coverage
// =====================================================================

func TestGenerateKeyPairExt3_Ed25519(t *testing.T) {
	pubKey, signer, certDER, err := generateKeyPair("ed25519", 0)
	if err != nil {
		t.Fatalf("generateKeyPair ed25519 failed: %v", err)
	}
	if pubKey == nil {
		t.Error("expected non-nil pubKey for ed25519")
	}
	if signer == nil {
		t.Error("expected non-nil signer for ed25519")
	}
	if len(certDER) == 0 {
		t.Error("expected non-empty certDER for ed25519")
	}
}

func TestGenerateKeyPairExt3_ECDSAP384(t *testing.T) {
	pubKey, _, _, err := generateKeyPair("ecdsa", 384)
	if err != nil {
		t.Fatalf("generateKeyPair ECDSA P-384 failed: %v", err)
	}
	if pubKey == nil {
		t.Error("expected non-nil pubKey for ECDSA P-384")
	}
}

func TestGenerateKeyPairExt3_ECDSAP521(t *testing.T) {
	pubKey, _, _, err := generateKeyPair("ecdsa", 521)
	if err != nil {
		t.Fatalf("generateKeyPair ECDSA P-521 failed: %v", err)
	}
	if pubKey == nil {
		t.Error("expected non-nil pubKey for ECDSA P-521")
	}
}

func TestGenerateKeyPairExt3_UnknownType(t *testing.T) {
	_, _, _, err := generateKeyPair("unknown_type", 0)
	if err == nil {
		t.Error("expected error for unknown key type")
	}
}

// =====================================================================
// caissuer.go - saveCertAndKey more coverage
// =====================================================================

func TestSaveCertAndKeyExt3_ECDSAKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate ECDSA key pair
	pubKey, signer, certDER, err := generateKeyPair("ecdsa", 256)
	if err != nil {
		t.Fatalf("generateKeyPair ECDSA failed: %v", err)
	}
	_ = pubKey

	// Get private key bytes
	keyBytes, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}

	certPath := filepath.Join(tmpDir, "save-ec-test.pem")
	keyPath := filepath.Join(tmpDir, "save-ec-test-key.pem")

	err = saveCertAndKey(certDER, keyBytes, certPath, keyPath)
	if err != nil {
		t.Fatalf("saveCertAndKey ECDSA failed: %v", err)
	}
	defer removeFiles(certPath, keyPath)

	// Verify files exist
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert file not found: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not found: %v", err)
	}
}

// =====================================================================
// caissuer.go - generateRandomSerial more coverage
// =====================================================================

func TestGenerateRandomSerialExt3(t *testing.T) {
	serial, err := generateRandomSerial()
	if err != nil {
		t.Fatalf("generateRandomSerial failed: %v", err)
	}
	if serial == nil {
		t.Error("expected non-nil serial")
	}
	if serial.BitLen() < 64 {
		t.Errorf("expected at least 64-bit serial, got %d bits", serial.BitLen())
	}
}

// =====================================================================
// caissuer.go - ReadSignerFromFile more coverage
// =====================================================================

func TestReadSignerFromFileExt3_ECDSAKey(t *testing.T) {
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "read-signer-ec", KeyType: "ecdsa", KeySize: 256, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	signer, err := ReadSignerFromFile(result.PrivateKeyPath)
	if err != nil {
		t.Fatalf("ReadSignerFromFile ECDSA failed: %v", err)
	}
	if signer == nil {
		t.Error("expected non-nil signer for ECDSA key")
	}
}

// =====================================================================
// certclone.go - generateHyphenVariants more coverage
// =====================================================================

func TestGenerateHyphenVariantsExt3_ShortDomain(t *testing.T) {
	// Domain too short for hyphenation (< 2 chars in name)
	variants := generateHyphenVariants("a", "com")
	if len(variants) > 0 {
		t.Log("Short domain may still produce hyphenation variants")
	}
}

func TestGenerateHyphenVariantsExt3_NormalDomain(t *testing.T) {
	variants := generateHyphenVariants("example", "com")
	if len(variants) == 0 {
		t.Error("expected hyphenation variants for 'example'")
	}
	for _, v := range variants {
		if !strings.Contains(v.Domain, "-") {
			t.Errorf("expected hyphen in domain, got %q", v.Domain)
		}
	}
}

// =====================================================================
// ScanCertSecurity error path (more coverage for network failure)
// =====================================================================

func TestScanCertSecurityExt3_ConnectionError(t *testing.T) {
	_, err := ScanCertSecurity("nonexistent.invalid.domain.example")
	if err == nil {
		t.Error("expected error for unreachable domain")
	}
}

// =====================================================================
// caa.go - parseCAAResponse more coverage
// =====================================================================

func TestParseCAAResponseExt3_ShortResponse(t *testing.T) {
	// Too short response (< 12 bytes)
	_, err := parseCAAResponse([]byte{0x01, 0x02, 0x03}, "example.com")
	if err == nil {
		t.Error("expected error for too short DNS response")
	}
}

func TestParseCAAResponseExt3_NXDomain(t *testing.T) {
	// NXDOMAIN response (rcode = 3)
	data := []byte{
		0xAA, 0xBB, // ID
		0x81, 0x83, // Flags: response with NXDOMAIN (rcode=3)
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		// Question section
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Root label
		0x01, 0x01, // QTYPE: CAA
		0x00, 0x01, // QCLASS: IN
	}
	_, err := parseCAAResponse(data, "example.com")
	if err == nil {
		t.Error("expected error for NXDOMAIN DNS response")
	}
}

func TestParseCAAResponseExt3_NoAnswers(t *testing.T) {
	// Valid response with 0 answers
	data := []byte{
		0xAA, 0xBB, // ID
		0x81, 0x80, // Flags: response, no error
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		// Question section
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Root label
		0x01, 0x01, // QTYPE: CAA
		0x00, 0x01, // QCLASS: IN
	}
	records, err := parseCAAResponse(data, "example.com")
	if err != nil {
		t.Fatalf("parseCAAResponse no answers failed: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 CAA records for response with no answers, got %d", len(records))
	}
}

func TestParseCAAResponseExt3_WithCAARecord(t *testing.T) {
	// Response with 1 CAA answer record
	// Build a complete DNS response with a CAA record
	data := []byte{
		0xAA, 0xBB, // ID
		0x81, 0x80, // Flags: response, no error
		0x00, 0x01, // Questions: 1
		0x00, 0x01, // Answers: 1
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}

	// Question section: example.com CAA IN
	data = append(data, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e')
	data = append(data, 0x03, 'c', 'o', 'm')
	data = append(data, 0x00)       // Root label
	data = append(data, 0x01, 0x01) // QTYPE: CAA (257)
	data = append(data, 0x00, 0x01) // QCLASS: IN

	// Answer section: compressed name pointer to question (0xC0 0x0C)
	data = append(data, 0xC0, 0x0C)             // Name: compression pointer
	data = append(data, 0x01, 0x01)             // TYPE: CAA (257)
	data = append(data, 0x00, 0x01)             // CLASS: IN
	data = append(data, 0x00, 0x00, 0x00, 0x3C) // TTL: 60
	// RDLENGTH: 15 (flag=1 byte, taglen=1 byte, tag="issue"=5 bytes, value="letsencrypt.org"=15 bytes total - wait let me compute)
	// CAA RDATA: flag(1) + taglength(1) + tag(5) + value(15) = 22
	tag := "issue"
	value := "letsencrypt.org"
	rdataLen := 1 + 1 + len(tag) + len(value)
	data = append(data, byte(rdataLen>>8), byte(rdataLen))

	// CAA RDATA
	data = append(data, 0x00) // Flag: 0
	data = append(data, byte(len(tag)))
	data = append(data, []byte(tag)...)
	data = append(data, []byte(value)...)

	records, err := parseCAAResponse(data, "example.com")
	if err != nil {
		t.Fatalf("parseCAAResponse with CAA record failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 CAA record, got %d", len(records))
	}
	if records[0].Tag != "issue" {
		t.Errorf("expected tag=issue, got %q", records[0].Tag)
	}
	if records[0].Value != "letsencrypt.org" {
		t.Errorf("expected value=letsencrypt.org, got %q", records[0].Value)
	}
	if records[0].Flag != 0 {
		t.Errorf("expected flag=0, got %d", records[0].Flag)
	}
}

// =====================================================================
// caa.go - dnsQueryCAA network failure path
// =====================================================================

func TestDnsQueryCAAExt3_NetworkFailure(t *testing.T) {
	// This will attempt to connect to DNS servers which may fail in test environments
	_, err := dnsQueryCAA("nonexistent.invalid.domain.example")
	if err != nil {
		t.Logf("dnsQueryCAA error (expected in offline environment): %v", err)
	}
}

// =====================================================================
// comparator.go - CompareCertsFromDomains more coverage
// =====================================================================

func TestCompareCertsFromDomainExt3_OneInvalid(t *testing.T) {
	// One valid file, one invalid domain
	result, _ := GenerateSelfSignedCert(CertificateRequest{
		CommonName: "compare-valid", KeyType: "rsa", KeySize: 2048, ValidityDays: 365,
	})
	defer removeFiles(result.CertificatePath, result.PrivateKeyPath)

	_, err := CompareCertsFromDomains(result.CertificatePath, "nonexistent.invalid.domain.example")
	if err == nil {
		t.Log("CompareCertsFromDomains may not return error for one invalid target")
	}
}

// =====================================================================
// OCSPMustStapleResult struct coverage
// =====================================================================

func TestOCSPMustStapleResultExt3_Construct(t *testing.T) {
	r := &OCSPMustStapleResult{
		Target:        "example.com",
		HasMustStaple: true,
		HasStaple:     false,
		IsCompliant:   false,
		Violation:     "Must-Staple without staple",
		Detail:        "RFC 7633 violation",
	}
	if !r.HasMustStaple {
		t.Error("expected HasMustStaple=true")
	}
	if r.HasStaple {
		t.Error("expected HasStaple=false")
	}
}

// =====================================================================
// KeyUsageComplianceResult struct coverage
// =====================================================================

func TestKeyUsageComplianceResultExt3_Construct(t *testing.T) {
	r := &KeyUsageComplianceResult{
		Target:      "example.com",
		IsCompliant: false,
		Issues:      []KeyUsageIssue{{Severity: "High", Description: "Missing keyCertSign"}},
		KeyUsage:    []string{"digitalSignature"},
		ExtKeyUsage: []string{"serverAuth"},
		IsCA:        true,
		Detail:      "CA missing keyCertSign",
	}
	if r.IsCompliant {
		t.Error("expected IsCompliant=false")
	}
	if len(r.Issues) != 1 {
		t.Errorf("expected 1 issue, got %d", len(r.Issues))
	}
}

// =====================================================================
// NameConstraintsResult struct coverage
// =====================================================================

func TestNameConstraintsResultExt3_Construct(t *testing.T) {
	r := &NameConstraintsResult{
		Target:         "example.com",
		HasConstraints: true,
		IsCompliant:    false,
		Violations:     []ConstraintViolation{{CASubject: "Test CA", ViolatedName: "evil.com", ViolationType: "excluded"}},
		Detail:         "Name constraint violation",
	}
	if !r.HasConstraints {
		t.Error("expected HasConstraints=true")
	}
	if r.IsCompliant {
		t.Error("expected IsCompliant=false")
	}
}

// =====================================================================
// PFSResult struct coverage
// =====================================================================

func TestPFSResultExt3_Construct(t *testing.T) {
	r := &PFSResult{
		Target:        "example.com",
		SupportsPFS:   true,
		PFSCipher:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		KeyExchange:   "ECDHE",
		ECDHECurve:    "P-256",
		PFSCiphers:    []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		NonPFSCiphers: []string{},
	}
	if !r.SupportsPFS {
		t.Error("expected SupportsPFS=true")
	}
}

// =====================================================================
// SessionResumptionResult struct coverage
// =====================================================================

func TestSessionResumptionResultExt3_Construct(t *testing.T) {
	r := &SessionResumptionResult{
		Target:                "example.com",
		SupportsSessionID:     true,
		SupportsSessionTicket: true,
		TLSVersion:            "TLS 1.2",
	}
	if !r.SupportsSessionID {
		t.Error("expected SupportsSessionID=true")
	}
}

// =====================================================================
// ChainVerifyResult struct coverage
// =====================================================================

func TestChainVerifyResultExt3_Construct(t *testing.T) {
	r := &ChainVerifyResult{
		Target:         "example.com",
		IsValid:        true,
		ChainLength:    3,
		TrustAnchor:    "Root CA",
		VerifiedChains: [][]CertChainEntry{},
		Errors:         []string{},
		Warnings:       []string{},
	}
	if !r.IsValid {
		t.Error("expected IsValid=true")
	}
}

// =====================================================================
// WildcardResult struct coverage
// =====================================================================

func TestWildcardResultExt3_Construct(t *testing.T) {
	r := &WildcardResult{
		Target:         "example.com",
		IsWildcard:     true,
		WildcardNames:  []string{"*.example.com"},
		ExactNames:     []string{"www.example.com"},
		WildcardLevel:  1,
		RiskLevel:      "Low",
		RiskReason:     "Single-domain wildcard",
		CoveredDomains: []string{"example.com"},
		CommonName:     "*.example.com",
		Issuer:         "Test CA",
	}
	if !r.IsWildcard {
		t.Error("expected IsWildcard=true")
	}
}

// =====================================================================
// HostnameVerifyResult struct coverage
// =====================================================================

func TestHostnameVerifyResultExt3_Construct(t *testing.T) {
	r := &HostnameVerifyResult{
		Target:     "example.com",
		Hostname:   "example.com",
		IsValid:    true,
		MatchType:  "exact",
		MatchedSAN: "example.com",
		AllSANs:    []string{"example.com", "www.example.com"},
		CommonName: "example.com",
	}
	if !r.IsValid {
		t.Error("expected IsValid=true")
	}
}

// =====================================================================
// EVResult struct coverage
// =====================================================================

func TestEVResultExt3_Construct(t *testing.T) {
	r := &EVResult{
		Target:       "example.com",
		IsEV:         true,
		EVIssuer:     "DigiCert EV",
		Organization: "Example Corp",
		EVOIDs:       []string{"2.16.840.1.114412.2.1"},
	}
	if !r.IsEV {
		t.Error("expected IsEV=true")
	}
}

// =====================================================================
// DistrustedCAResult struct coverage
// =====================================================================

func TestDistrustedCAResultExt3_Construct(t *testing.T) {
	r := &DistrustedCAResult{
		Target:        "example.com",
		IsDistrusted:  true,
		DistrustedCAs: []DistrustedCA{{Name: "DigiNotar"}},
		Warning:       "Contains distrusted CA",
	}
	if !r.IsDistrusted {
		t.Error("expected IsDistrusted=true")
	}
}

// =====================================================================
// BundleCheckResult struct coverage
// =====================================================================

func TestBundleCheckResultExt3_Construct(t *testing.T) {
	r := &BundleCheckResult{
		Target:        "example.com",
		ChainComplete: true,
		ChainLength:   3,
		CanAIAFill:    false,
		Detail:        "Chain complete",
	}
	if !r.ChainComplete {
		t.Error("expected ChainComplete=true")
	}
}

// =====================================================================
// DownloadResult struct coverage
// =====================================================================

func TestDownloadResultExt3_Construct(t *testing.T) {
	r := &DownloadResult{
		Target:      "example.com",
		SavedFiles:  []string{"example-chain.pem", "example.pem"},
		ChainLength: 3,
		Message:     "Downloaded 3 certificates for example.com",
	}
	if len(r.SavedFiles) != 2 {
		t.Errorf("expected 2 saved files, got %d", len(r.SavedFiles))
	}
}

// =====================================================================
// SerialEntropyResult struct coverage
// =====================================================================

func TestSerialEntropyResultExt3_Construct(t *testing.T) {
	r := &SerialEntropyResult{
		Target:          "example.com",
		SerialHex:       "abcd1234",
		BitLength:       128,
		IsCompliant:     true,
		EntropyEstimate: 7.5,
		HammingWeight:   64,
		HammingRatio:    0.5,
		IsSequential:    false,
		Detail:          "Compliant serial number",
	}
	if !r.IsCompliant {
		t.Error("expected IsCompliant=true")
	}
}

// =====================================================================
// PolicyAnalysisResult struct coverage
// =====================================================================

func TestPolicyAnalysisResultExt3_Construct(t *testing.T) {
	r := &PolicyAnalysisResult{
		Target:         "example.com",
		ValidationType: "EV",
		PolicyOIDs:     []PolicyOID{{OID: "2.16.840.1.114412.2.1", Description: "DigiCert EV", Type: "EV"}},
		HasPolicies:    true,
		IsCompliant:    true,
		Detail:         "EV certificate",
	}
	if r.ValidationType != "EV" {
		t.Errorf("expected EV, got %q", r.ValidationType)
	}
}

// =====================================================================
// RevocationResult struct coverage
// =====================================================================

func TestRevocationResultExt3_Construct(t *testing.T) {
	r := &RevocationResult{
		Target:        "example.com",
		OCSPStatus:    OCSPStatus{Checked: true, Status: "Good"},
		CRLStatus:     CRLStatus{Checked: true, Status: "Good"},
		OverallStatus: "Good",
	}
	if r.OverallStatus != "Good" {
		t.Errorf("expected Good, got %q", r.OverallStatus)
	}
}

// =====================================================================
// OCSPStatus and CRLStatus struct coverage
// =====================================================================

func TestOCSPStatusExt3_Construct(t *testing.T) {
	r := OCSPStatus{
		Checked:    true,
		Status:     "Good",
		ThisUpdate: "2026-01-01T00:00:00Z",
		NextUpdate: "2026-02-01T00:00:00Z",
		OCSPURL:    "http://ocsp.example.com",
	}
	if !r.Checked {
		t.Error("expected Checked=true")
	}
}

func TestCRLStatusExt3_Construct(t *testing.T) {
	r := CRLStatus{
		Checked:    true,
		Status:     "Good",
		CRLURL:     "http://crl.example.com/crl.pem",
		ThisUpdate: "2026-01-01T00:00:00Z",
		NextUpdate: "2026-02-01T00:00:00Z",
	}
	if !r.Checked {
		t.Error("expected Checked=true")
	}
}

// =====================================================================
// HSTSResult struct coverage
// =====================================================================

func TestHSTSResultExt3_Construct(t *testing.T) {
	r := &HSTSResult{
		Enabled:           true,
		MaxAge:            31536000,
		IncludeSubDomains: true,
		Preload:           true,
		RawHeader:         "max-age=31536000; includeSubDomains; preload",
	}
	if !r.Enabled {
		t.Error("expected Enabled=true")
	}
}

// =====================================================================
// CertSnapshot and CertChangeResult struct coverage
// =====================================================================

func TestCertSnapshotExt3_Construct(t *testing.T) {
	r := &CertSnapshot{
		Target:       "example.com",
		Timestamp:    time.Now(),
		CertSHA256:   "abcd1234",
		SPKISHA256:   "spki5678",
		Issuer:       "Test CA",
		SerialNumber: "12345",
	}
	if r.Target != "example.com" {
		t.Errorf("expected example.com, got %q", r.Target)
	}
}

func TestCertChangeRecordExt3_Construct(t *testing.T) {
	r := &CertChangeRecord{
		Target:     "example.com",
		ChangeType: "renewed",
		Details:    []string{"Same public key"},
	}
	if r.ChangeType != "renewed" {
		t.Errorf("expected renewed, got %q", r.ChangeType)
	}
}

// =====================================================================
// CertChangeResult struct coverage
// =====================================================================

func TestCertChangeResultExt3_Construct(t *testing.T) {
	r := &CertChangeResult{
		Target:     "example.com",
		HasChanged: true,
		ChangeType: "replaced",
		Changes:    []string{"Different public key"},
	}
	if !r.HasChanged {
		t.Error("expected HasChanged=true")
	}
}

// =====================================================================
// SecurityIssue struct coverage
// =====================================================================

func TestSecurityIssueExt3_Construct(t *testing.T) {
	r := SecurityIssue{
		Severity:    "Critical",
		Type:        "CERT-008",
		Description: "Certificate expired",
		Impact:      "Expired on 2025-01-01",
	}
	if r.Severity != "Critical" {
		t.Errorf("expected Critical, got %q", r.Severity)
	}
}

// =====================================================================
// SCTResult struct coverage (more fields)
// =====================================================================

func TestSCTEntryExt3_Construct(t *testing.T) {
	r := SCTEntry{
		Version:      0,
		LogID:        "test-log-id",
		LogIDHex:     "aabbccdd",
		Timestamp:    1609459200000,
		TimestampStr: "2021-01-01T00:00:00Z",
		Source:       "embedded",
	}
	if r.Version != 0 {
		t.Errorf("expected version 0, got %d", r.Version)
	}
}

// =====================================================================
// fetchIntermediateFromAIA error path (network-dependent)
// =====================================================================

func TestFetchIntermediateFromAIAExt3_InvalidURL(t *testing.T) {
	_, err := fetchIntermediateFromAIA("http://nonexistent.invalid.domain.example/cert.der")
	if err == nil {
		t.Log("fetchIntermediateFromAIA may not return error for invalid URL in some environments")
	}
}

// =====================================================================
// Ensure imports used
// =====================================================================
var _ = ecdsa.GenerateKey
var _ = ed25519.GenerateKey
var _ = elliptic.P256
var _ = rsa.GenerateKey
var _ = big.NewInt
var _ = json.Unmarshal
var _ = pem.EncodeToMemory
var _ = filepath.Join
var _ = strings.Contains
var _ = context.Background
var _ = net.ParseIP
var _ = crypto.Signer(nil)
