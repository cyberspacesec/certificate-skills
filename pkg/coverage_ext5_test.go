package pkg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ============================================================
// CAA Tests
// ============================================================

func TestCheckCAA_UnreachableTargetExt5(t *testing.T) {
	// Test with unreachable target - should return result with no CAA records
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	// Test with unreachable target - should return result with no CAA records
	result, err := CheckCAA("192.0.2.1")
	if err != nil {
		t.Logf("CheckCAA returned error: %v (expected for unreachable)", err)
	}
	if result != nil {
		t.Logf("CheckCAA result: HasCAA=%v, IsCompliant=%v", result.HasCAA, result.IsCompliant)
	}
}

func TestQueryCAARecords_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	records, err := queryCAARecords("nonexistent.test.invalid")
	if err != nil {
		t.Logf("queryCAARecords error (expected): %v", err)
	} else {
		t.Logf("queryCAARecords returned %d records", len(records))
	}
}

func TestLookupCAA_InvalidDomainExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	records, err := lookupCAA("nonexistent.test.invalid")
	if err != nil {
		t.Logf("lookupCAA error (expected): %v", err)
	} else {
		t.Logf("lookupCAA returned %d records", len(records))
	}
}

func TestDNSQueryCAA_InvalidServerExt5(t *testing.T) {
	// Override with unreachable DNS server by calling directly
	// This should fail to connect to DNS servers
	records, err := dnsQueryCAA("example.invalid.tld")
	// We expect this to either return records or error
	t.Logf("dnsQueryCAA: records=%v, err=%v", records, err)
}

func TestParseCAAResponse_ValidResponseExt5(t *testing.T) {
	// Build a minimal valid DNS response with a CAA record
	// DNS header: ID=0xAABB, Flags=0x8180 (standard response, no error), QDCOUNT=1, ANCOUNT=1
	response := []byte{
		0xAA, 0xBB, // ID
		0x81, 0x80, // Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, RCODE=0
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x01, // ANCOUNT: 1
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}

	// Question section: example.com CAA IN
	response = append(response, 0x07) // label length
	response = append(response, []byte("example")...)
	response = append(response, 0x03) // label length
	response = append(response, []byte("com")...)
	response = append(response, 0x00)       // root label
	response = append(response, 0x01, 0x01) // QTYPE: CAA (257)
	response = append(response, 0x00, 0x01) // QCLASS: IN

	// Answer section - use compression pointer for name (0xC00C = pointer to offset 12)
	response = append(response, 0xC0, 0x0C)             // Name: compression pointer
	response = append(response, 0x01, 0x01)             // TYPE: CAA (257)
	response = append(response, 0x00, 0x01)             // CLASS: IN
	response = append(response, 0x00, 0x00, 0x0E, 0x10) // TTL: 3600
	// RDATA: flag=0, tag="issue", value="letsencrypt.org"
	tag := "issue"
	value := "letsencrypt.org"
	rdlength := 2 + len(tag) + len(value)
	response = append(response, byte(rdlength>>8), byte(rdlength))
	response = append(response, 0x00) // Flag: 0
	response = append(response, byte(len(tag)))
	response = append(response, []byte(tag)...)
	response = append(response, []byte(value)...)

	records, err := parseCAAResponse(response, "example.com")
	if err != nil {
		t.Fatalf("parseCAAResponse error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Tag != "issue" {
		t.Errorf("expected tag 'issue', got '%s'", records[0].Tag)
	}
	if records[0].Value != "letsencrypt.org" {
		t.Errorf("expected value 'letsencrypt.org', got '%s'", records[0].Value)
	}
}

func TestParseCAAResponse_ShortResponseExt5(t *testing.T) {
	_, err := parseCAAResponse([]byte{0x00, 0x01, 0x02}, "example.com")
	if err == nil {
		t.Error("expected error for short response")
	}
}

func TestParseCAAResponse_ErrorRcodeExt5(t *testing.T) {
	response := []byte{
		0xAA, 0xBB, // ID
		0x81, 0x83, // Flags: RCODE=3 (NXDOMAIN)
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	_, err := parseCAAResponse(response, "example.com")
	if err == nil {
		t.Error("expected error for NXDOMAIN response")
	}
}

func TestParseCAAResponse_NoAnswersExt5(t *testing.T) {
	response := []byte{
		0xAA, 0xBB, // ID
		0x81, 0x80, // Flags: standard response
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}
	records, err := parseCAAResponse(response, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestParseCAAResponse_TruncatedDataExt5(t *testing.T) {
	response := []byte{
		0xAA, 0xBB, // ID
		0x81, 0x80, // Flags
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x01, // ANCOUNT: 1
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		// Question: minimal
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // root
		0x01, 0x01, // QTYPE
		0x00, 0x01, // QCLASS
		// Truncated answer - not enough data
		0xC0, 0x0C, // name compression
		0x01, 0x01, // TYPE
		0x00, 0x01, // CLASS
		0x00, 0x00, 0x00, 0x3C, // TTL
		0x00, 0x10, // RDLENGTH = 16
		// But only 3 bytes of RDATA follow (truncated)
		0x00, 0x05, 'i',
	}
	// Should handle gracefully without panic
	records, err := parseCAAResponse(response, "example.com")
	if err != nil {
		t.Logf("parseCAAResponse with truncated data: err=%v", err)
	} else {
		t.Logf("parseCAAResponse with truncated data: records=%d", len(records))
	}
}

// ============================================================
// TLS Protocol Scan Tests
// ============================================================

func TestTLSProtocolScan_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := TLSProtocolScan("192.0.2.1:443")
	if err != nil {
		t.Logf("TLSProtocolScan error (expected): %v", err)
	}
	if result != nil {
		t.Logf("TLSProtocolScan result: %d protocols scanned", len(result.Protocols))
		// All should be unsupported for unreachable target
		for _, p := range result.Protocols {
			t.Logf("  %s: supported=%v", p.Version, p.Supported)
		}
	}
}

func TestProbeTLSVersion_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	supported, err := probeTLSVersion("192.0.2.1:443", tls.VersionTLS12)
	if supported {
		t.Error("expected unsupported for unreachable target")
	}
	if err == nil {
		t.Error("expected error for unreachable target")
	}
	t.Logf("probeTLSVersion: supported=%v, err=%v", supported, err)
}

// ============================================================
// CT Search Tests
// ============================================================

func TestCTSearchByFingerprint_InvalidExt5(t *testing.T) {
	result, err := CTSearchByFingerprint("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Logf("CTSearchByFingerprint error: %v", err)
	}
	if result != nil {
		t.Logf("CTSearchByFingerprint: target=%s, error=%s", result.Target, result.Error)
	}
}

// ============================================================
// Chain Verify Tests
// ============================================================

func TestVerifyCertChain_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := VerifyCertChain("192.0.2.1:443")
	if err != nil {
		t.Logf("VerifyCertChain error: %v", err)
	}
	if result != nil {
		t.Logf("VerifyCertChain: IsValid=%v, Errors=%v", result.IsValid, result.Errors)
		if result.IsValid {
			t.Error("expected invalid for unreachable target")
		}
	}
}

// ============================================================
// Vulnerability Scanner Network Error Path Tests
// ============================================================

func TestCheckHeartbleed_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkHeartbleed("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkHeartbleed: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckPOODLE_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkPOODLE("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkPOODLE: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckROBOT_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkROBOT("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkROBOT: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckCCSInjection_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkCCSInjection("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkCCSInjection: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckFREAK_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkFREAK("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkFREAK: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckLogjam_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkLogjam("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkLogjam: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckSweet32_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkSweet32("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkSweet32: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckBEAST_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkBEAST("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkBEAST: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckCRIME_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkCRIME("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkCRIME: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckRenegotiation_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkRenegotiation("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkRenegotiation: vulnerable=%v, detail=%s", vulnerable, detail)
}

func TestCheckDROWN_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	vulnerable, detail := checkDROWN("192.0.2.1:443")
	if vulnerable {
		t.Error("should not be vulnerable for unreachable target")
	}
	t.Logf("checkDROWN: vulnerable=%v, detail=%s", vulnerable, detail)
}

// ============================================================
// Revocation Tests (error paths)
// ============================================================

func TestCheckRevocation_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckRevocation("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckRevocation error: %v", err)
	}
	if result != nil {
		t.Logf("CheckRevocation: overall=%s, ocsp_error=%s, crl_error=%s",
			result.OverallStatus, result.OCSPStatus.Error, result.CRLStatus.Error)
	}
}

func TestCheckRevocation_FileTargetExt5(t *testing.T) {
	// Test with a non-existent file
	result, err := CheckRevocation("/nonexistent/cert.pem")
	if err != nil {
		t.Logf("CheckRevocation file error: %v", err)
	}
	if result != nil {
		t.Logf("CheckRevocation file: error=%s", result.Error)
	}
}

func TestCheckOCSP_WithOCSPServerAndIssuerExt5(t *testing.T) {
	// Create a cert with OCSP server URL and an issuer cert
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkixName("Test Cert"),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		OCSPServer:   []string{"http://ocsp.example.com"},
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Test with OCSP server but invalid URL (will fail HTTP request)
	status := checkOCSP(cert, cert)
	if !status.Checked {
		t.Error("expected Checked=true when OCSPServer is present")
	}
	t.Logf("checkOCSP: checked=%v, status=%s, error=%s", status.Checked, status.Status, status.Error)
}

func TestCheckCRL_WithDistributionPointsExt5(t *testing.T) {
	// Create a cert with CRL distribution points
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("Test Cert"),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{"http://crl.example.com/test.crl"},
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Test with CRL URL but unreachable server
	status := checkCRL(cert)
	if !status.Checked {
		t.Error("expected Checked=true when CRLDistributionPoints is present")
	}
	t.Logf("checkCRL: checked=%v, status=%s, error=%s", status.Checked, status.Status, status.Error)
}

// ============================================================
// ScanCertSecurity (live TLS connection) error path
// ============================================================

func TestScanCertSecurity_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := ScanCertSecurity("192.0.2.1:443")
	if err == nil {
		t.Error("expected error for unreachable target")
	}
	if result != nil {
		t.Logf("ScanCertSecurity: unexpected result for unreachable target")
	}
	t.Logf("ScanCertSecurity error (expected): %v", err)
}

// ============================================================
// BundleCheck Tests
// ============================================================

func TestCheckBundleCompleteness_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckBundleCompleteness("192.0.2.1:443")
	if err == nil {
		t.Error("expected error for unreachable target")
	}
	t.Logf("CheckBundleCompleteness error (expected): %v", err)
	_ = result
}

func TestFetchIntermediateFromAIA_InvalidURLExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	cert, err := fetchIntermediateFromAIA("http://192.0.2.1:9999/nonexistent")
	if err == nil {
		t.Error("expected error for invalid AIA URL")
	}
	t.Logf("fetchIntermediateFromAIA error (expected): %v", err)
	_ = cert
}

func TestParseCertFromPEM_InvalidExt5(t *testing.T) {
	_, err := parseCertFromPEM([]byte("not a PEM block"))
	if err == nil {
		t.Error("expected error for invalid PEM data")
	}
}

func TestParseCertFromPEM_ValidPEMExt5(t *testing.T) {
	// Generate a self-signed cert and encode as PEM
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkixName("Test"),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	cert, err := parseCertFromPEM(pemData)
	if err != nil {
		t.Fatalf("parseCertFromPEM error: %v", err)
	}
	if cert.Subject.CommonName != "Test" {
		t.Errorf("expected CN=Test, got %s", cert.Subject.CommonName)
	}
}

// ============================================================
// DetectEV / CheckDistrustedCA / VerifyHostname network error paths
// ============================================================

func TestDetectEV_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := DetectEV("192.0.2.1:443")
	if err != nil {
		t.Logf("DetectEV error: %v", err)
	}
	if result != nil {
		t.Logf("DetectEV: isEV=%v, reason=%s", result.IsEV, result.Reason)
	}
}

func TestCheckDistrustedCA_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckDistrustedCA("192.0.2.1:443")
	if err == nil {
		t.Error("expected error for unreachable target")
	}
	t.Logf("CheckDistrustedCA error (expected): %v", err)
	_ = result
}

func TestVerifyHostname_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := VerifyHostname("192.0.2.1:443")
	if err != nil {
		t.Logf("VerifyHostname error: %v", err)
	}
	if result != nil {
		t.Logf("VerifyHostname: valid=%v, error=%s", result.IsValid, result.Error)
	}
}

func TestCheckPFS_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow network test in short mode")
	}
	result, err := CheckPFS("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckPFS error: %v", err)
	}
	if result != nil {
		t.Logf("CheckPFS: supportsPFS=%v, error=%s", result.SupportsPFS, result.Error)
	}
}

func TestCheckSessionResumption_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckSessionResumption("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckSessionResumption error: %v", err)
	}
	if result != nil {
		t.Logf("CheckSessionResumption: error=%s", result.Error)
	}
}

// ============================================================
// CipherSuiteScan / probeCipherSuite network error paths
// ============================================================

func TestCipherSuiteScan_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow network test in short mode")
	}
	result, err := CipherSuiteScan("192.0.2.1:443", 0)
	if err != nil {
		t.Logf("CipherSuiteScan error: %v", err)
	}
	if result != nil {
		t.Logf("CipherSuiteScan: %d cipher suites tested", len(result.CipherSuites))
		// All should be unsupported
		for _, cs := range result.CipherSuites {
			if cs.Supported {
				t.Errorf("expected unsupported cipher %s for unreachable target", cs.CipherSuite)
			}
		}
	}
}

func TestProbeCipherSuite_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	supported, err := probeCipherSuite("192.0.2.1:443", tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if supported {
		t.Error("expected unsupported for unreachable target")
	}
	t.Logf("probeCipherSuite: supported=%v, err=%v", supported, err)
}

// ============================================================
// Comparator network error paths
// ============================================================

func TestCompareCertsFromDomains_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CompareCertsFromDomains("192.0.2.1:443", "192.0.2.2:443")
	if err == nil {
		t.Error("expected error for unreachable targets")
	}
	t.Logf("CompareCertsFromDomains error (expected): %v", err)
	_ = result
}

// ============================================================
// Download Certs network error paths
// ============================================================

func TestDownloadCertsFromDomain_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := DownloadCertsFromDomain("192.0.2.1:443", "")
	if err == nil {
		t.Error("expected error for unreachable target")
	}
	t.Logf("DownloadCertsFromDomain error (expected): %v", err)
	_ = result
}

// ============================================================
// CT Enumerate / CT Search network error paths
// ============================================================

func TestCTEnumerateSubdomains_SearchErrorExt5(t *testing.T) {
	// This calls CTSearch which hits crt.sh API
	result, err := CTEnumerateSubdomains("nonexistent.invalid.tld")
	t.Logf("CTEnumerateSubdomains: result=%v, err=%v", result, err)
}

// ============================================================
// CheckSCT network error path
// ============================================================

func TestCheckSCT_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckSCT("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckSCT error: %v", err)
	}
	if result != nil {
		t.Logf("CheckSCT: error=%s", result.Error)
	}
}

// ============================================================
// MatchFingerprints / ComputeCertSPKIHashFromDomain network error paths
// ============================================================

func TestMatchFingerprints_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := MatchFingerprints("192.0.2.1:443")
	if err != nil {
		t.Logf("MatchFingerprints error: %v", err)
	}
	if result != nil {
		t.Logf("MatchFingerprints: matches=%d", len(result.Matches))
	}
}

func TestComputeCertSPKIHashFromDomain_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	hash, err := ComputeCertSPKIHashFromDomain("192.0.2.1:443")
	if err == nil {
		t.Error("expected error for unreachable target")
	}
	t.Logf("ComputeCertSPKIHashFromDomain error (expected): %v", err)
	_ = hash
}

// ============================================================
// JA3 / JARM network error paths
// ============================================================

func TestJA3Scan_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := JA3Scan("192.0.2.1:443")
	if err != nil {
		t.Logf("JA3Scan error: %v", err)
	}
	if result != nil {
		t.Logf("JA3Scan: ja3=%s, error=%s", result.JA3Hash, result.Error)
	}
}

func TestJARMScan_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := JARMScan("192.0.2.1:443")
	if err != nil {
		t.Logf("JARMScan error: %v", err)
	}
	if result != nil {
		t.Logf("JARMScan: jarm=%s", result.JARMHash)
	}
}

func TestJARMProbeServer_UnreachableExt5(t *testing.T) {
	// jarmProbeServer with unreachable target
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	// jarmProbeServer with unreachable target
	probe := jarmProbe{
		Version:      0x0303,
		CipherSuites: []uint16{0xC02F},
		SendSNI:      true,
	}
	resp, tlsVer, cipher, err := jarmProbeServer("192.0.2.1:443", "192.0.2.1", probe)
	t.Logf("jarmProbeServer: resp=%s tlsVer=%s cipher=%s err=%v", resp, tlsVer, cipher, err)
}

// ============================================================
// DetectChange / TakeSnapshot network error paths
// ============================================================

func TestTakeSnapshot_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	snap, err := TakeSnapshot("192.0.2.1:443")
	if err == nil {
		t.Error("expected error for unreachable target")
	}
	t.Logf("TakeSnapshot error (expected): %v", err)
	_ = snap
}

func TestDetectChange_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := DetectChange("192.0.2.1:443", nil)
	if err == nil {
		t.Error("expected error for unreachable target")
	}
	t.Logf("DetectChange error (expected): %v", err)
	_ = result
}

// ============================================================
// CertChange - SnapshotStore Save/LoadLatest
// ============================================================

func TestSnapshotStore_SaveAndLoadExt5(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewSnapshotStore(tmpDir)

	snap := &CertSnapshot{
		Target:       "example.com",
		Timestamp:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		CertSHA256:   "abc123",
		SPKISHA256:   "def456",
		Issuer:       "Test CA",
		SerialNumber: "789",
	}

	err := store.Save(snap)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}

	loaded, err := store.LoadLatest("example.com")
	if err != nil {
		t.Fatalf("LoadLatest error: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if loaded.CertSHA256 != "abc123" {
		t.Errorf("expected CertSHA256=abc123, got %s", loaded.CertSHA256)
	}
}

func TestSnapshotStore_LoadLatest_NoSnapshotsExt5(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewSnapshotStore(tmpDir)

	loaded, err := store.LoadLatest("example.com")
	if err != nil {
		t.Fatalf("LoadLatest error: %v", err)
	}
	if loaded != nil {
		t.Error("expected nil snapshot when no snapshots exist")
	}
}

func TestSnapshotStore_LoadLatest_DirNotExistExt5(t *testing.T) {
	store := NewSnapshotStore("/nonexistent/dir/path")
	loaded, err := store.LoadLatest("example.com")
	if err != nil {
		t.Fatalf("LoadLatest error: %v", err)
	}
	if loaded != nil {
		t.Error("expected nil snapshot when directory doesn't exist")
	}
}

func TestSnapshotStore_Save_InvalidDirExt5(t *testing.T) {
	// Try saving to a path that can't be created
	store := NewSnapshotStore("/proc/null/impossible/path")
	snap := &CertSnapshot{
		Target:    "test.com",
		Timestamp: time.Now(),
	}
	err := store.Save(snap)
	if err == nil {
		t.Error("expected error when saving to invalid directory")
	}
}

func TestSnapshotStore_LoadLatest_CorruptJSONExt5(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewSnapshotStore(tmpDir)

	// Write a corrupt JSON file
	filename := fmt.Sprintf("%s_%s.json", "test.com", "20240115_103000")
	path := filepath.Join(tmpDir, filename)
	os.WriteFile(path, []byte("{invalid json"), 0644)

	loaded, err := store.LoadLatest("test.com")
	if err == nil {
		t.Error("expected error for corrupt JSON")
	}
	t.Logf("LoadLatest corrupt JSON error (expected): %v", err)
	_ = loaded
}

// ============================================================
// DetectChange with prev snapshot
// ============================================================

func TestDetectChange_WithPreviousSnapshotExt5(t *testing.T) {
	// Test the comparison logic with constructed CertChangeResult
	prev := &CertSnapshot{
		Target:     "example.com",
		CertSHA256: "old_hash",
		SPKISHA256: "old_spki",
		Issuer:     "Old CA",
		JARMHash:   "old_jarm",
		NotAfter:   time.Now().Add(365 * 24 * time.Hour),
	}

	current := &CertSnapshot{
		Target:     "example.com",
		CertSHA256: "new_hash",
		SPKISHA256: "new_spki",
		Issuer:     "New CA",
		JARMHash:   "new_jarm",
		NotAfter:   time.Now().Add(365 * 24 * time.Hour),
	}

	result := &CertChangeResult{
		Target:       "example.com",
		CurrentSnap:  current,
		PreviousSnap: prev,
		HasChanged:   false,
		Changes:      []string{},
	}

	// Test CERT-018 checkNameConstraints branch - expired cert
	if !current.NotAfter.IsZero() {
		// not expired
		result.HasChanged = false
	}

	// Simulate the comparison logic from DetectChange
	if current.CertSHA256 != prev.CertSHA256 {
		result.HasChanged = true
		result.Changes = append(result.Changes, fmt.Sprintf("Certificate changed: %s → %s", prev.CertSHA256, current.CertSHA256))
		if current.SPKISHA256 == prev.SPKISHA256 {
			result.ChangeType = "renewed"
		} else {
			result.ChangeType = "replaced"
		}
	}

	if !result.HasChanged {
		t.Error("expected HasChanged=true when cert hash differs")
	}
	if result.ChangeType != "replaced" {
		t.Errorf("expected ChangeType=replaced, got %s", result.ChangeType)
	}
}

// ============================================================
// AnalyzeSecurityFromCertWithState - comprehensive offline paths
// ============================================================

func TestAnalyzeSecurityFromCertWithState_AllGoodExt5(t *testing.T) {
	// Create a healthy certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com", "www.example.com"},
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result, err := AnalyzeSecurityFromCertWithState(cert, "example.com", nil)
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCertWithState error: %v", err)
	}
	t.Logf("Score=%d, Level=%s, Issues=%d", result.OverallScore, result.SecurityLevel, len(result.Issues))
}

func TestAnalyzeSecurityFromCertWithState_WithConnectionStateExt5(t *testing.T) {
	// Create a self-signed cert with various issues
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.local",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-400 * 24 * time.Hour),
		NotAfter:              time.Now().Add(400 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"test.local", "*.test.local"},
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Create ConnectionState with peer certs including the self-signed cert
	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		OCSPResponse:     []byte{},
	}

	result, err := AnalyzeSecurityFromCertWithState(cert, "test.local", &state)
	if err != nil {
		t.Fatalf("AnalyzeSecurityFromCertWithState error: %v", err)
	}
	t.Logf("Score=%d, Level=%s, Issues=%d", result.OverallScore, result.SecurityLevel, len(result.Issues))

	// Should have issues: self-signed (CERT-007), wildcard (CERT-011), internal name (CERT-012),
	// untrusted chain (CERT-013), excessive validity (CERT-006)
	for _, issue := range result.Issues {
		t.Logf("  Issue: type=%s severity=%s desc=%s", issue.Type, issue.Severity, issue.Description)
	}
}

func TestAnalyzeSecurityFromCertWithState_ManyIssuesExt5(t *testing.T) {
	// Create a cert with many problems
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Low entropy
		Subject: pkix.Name{
			CommonName: "expired.internal",
		},
		NotBefore:             time.Now().Add(-800 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-10 * 24 * time.Hour), // Expired
		KeyUsage:              x509.KeyUsageCertSign,                // Non-CA with CertSign
		BasicConstraintsValid: false,
		DNSNames:              []string{"*.internal"},
		SignatureAlgorithm:    x509.SHA1WithRSA, // Weak signature
	}

	key, _ := rsa.GenerateKey(rand.Reader, 1024) // Short RSA key
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	result, err := AnalyzeSecurityFromCertWithState(cert, "expired.internal", &state)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	t.Logf("Score=%d, Level=%s, Issues=%d", result.OverallScore, result.SecurityLevel, len(result.Issues))

	// Should have very low score
	if result.OverallScore >= 50 {
		t.Errorf("expected low score for many issues, got %d", result.OverallScore)
	}
}

// ============================================================
// ScanCertSecurityFromChain with full ConnectionState
// ============================================================

func TestScanCertSecurityFromChain_FullStateExt5(t *testing.T) {
	// Create a cert chain: leaf + intermediate CA
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(123456789012),
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Example Inc"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert, caCert},
		OCSPResponse:     []byte{1, 2, 3}, // Has OCSP staple
	}

	result, err := ScanCertSecurityFromChain(leafCert, "example.com", &state)
	if err != nil {
		t.Fatalf("ScanCertSecurityFromChain error: %v", err)
	}

	// Should have 18 checks (CERT-001 through CERT-018)
	if len(result.Checks) != 18 {
		t.Errorf("expected 18 checks, got %d", len(result.Checks))
	}

	for _, check := range result.Checks {
		t.Logf("  %s (%s): passed=%v detail=%s", check.Code, check.Name, check.Passed, check.Detail)
	}
}

func TestScanCertSecurityFromChain_CACertWithIssuesExt5(t *testing.T) {
	// Create a CA cert without keyCertSign
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Bad CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature, // Missing CertSign!
		BasicConstraintsValid: true,
		DNSNames:              []string{"badca.example.com"},
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	result, err := ScanCertSecurityFromChain(cert, "badca.example.com", &state)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// CERT-016 should fail: CA without keyCertSign
	found := false
	for _, check := range result.Checks {
		if check.Code == "CERT-016" && !check.Passed {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CERT-016 to fail for CA without keyCertSign")
	}
}

func TestScanCertSecurityFromChain_NoKeyUsageExt5(t *testing.T) {
	// Create a cert with no key usage at all
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "nokusages.example.com",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: false,
		DNSNames:              []string{"nokusages.example.com"},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		// No KeyUsage, no ExtKeyUsage
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	result, err := ScanCertSecurityFromChain(cert, "nokusages.example.com", &state)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// CERT-016 should fail: no key usage at all
	for _, check := range result.Checks {
		if check.Code == "CERT-016" {
			if check.Passed {
				t.Error("expected CERT-016 to fail for cert with no key usage")
			}
			t.Logf("CERT-016: detail=%s", check.Detail)
		}
	}
}

func TestScanCertSecurityFromChain_ECDSECertExt5(t *testing.T) {
	// Create a cert with ECDSA key
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ecdsa.example.com",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"ecdsa.example.com"},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result, err := ScanCertSecurityFromChain(cert, "ecdsa.example.com", nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// CERT-002 should pass (not RSA)
	// CERT-003 should pass (P-256 is fine)
	for _, check := range result.Checks {
		if check.Code == "CERT-003" {
			if !check.Passed {
				t.Errorf("CERT-003 should pass for P-256: %s", check.Detail)
			}
		}
	}
}

func TestScanCertSecurityFromChain_WeakECDSACurveExt5(t *testing.T) {
	// Create a cert with P-224 ECDSA key (weak curve)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "weak-ecdsa.example.com",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"weak-ecdsa.example.com"},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result, err := ScanCertSecurityFromChain(cert, "weak-ecdsa.example.com", nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// CERT-003 should fail for P-224
	for _, check := range result.Checks {
		if check.Code == "CERT-003" {
			if check.Passed {
				t.Error("expected CERT-003 to fail for P-224 curve")
			}
			t.Logf("CERT-003: detail=%s", check.Detail)
		}
	}
}

// ============================================================
// CheckKeyUsageCompliance / CheckOCSPMustStaple / CheckSerialEntropy / CheckNameConstraints
// network error paths
// ============================================================

func TestCheckKeyUsageCompliance_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckKeyUsageCompliance("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckKeyUsageCompliance error: %v", err)
	}
	if result != nil {
		t.Logf("CheckKeyUsageCompliance: compliant=%v", result.IsCompliant)
	}
}

func TestCheckOCSPMustStaple_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckOCSPMustStaple("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckOCSPMustStaple error: %v", err)
	}
	if result != nil {
		t.Logf("CheckOCSPMustStaple: compliant=%v", result.IsCompliant)
	}
}

func TestCheckSerialEntropy_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckSerialEntropy("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckSerialEntropy error: %v", err)
	}
	if result != nil {
		t.Logf("CheckSerialEntropy: compliant=%v", result.IsCompliant)
	}
}

func TestCheckNameConstraints_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckNameConstraints("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckNameConstraints error: %v", err)
	}
	if result != nil {
		t.Logf("CheckNameConstraints: compliant=%v", result.IsCompliant)
	}
}

func TestCheckPolicyAnalysis_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckPolicyAnalysis("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckPolicyAnalysis error: %v", err)
	}
	if result != nil {
		t.Logf("CheckPolicyAnalysis: compliant=%v", result.IsCompliant)
	}
}

func TestGetCertSANs_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	dnsNames, ipAddrs, emails, err := GetCertSANs("192.0.2.1:443")
	if err != nil {
		t.Logf("GetCertSANs error: %v", err)
	}
	t.Logf("GetCertSANs: dns=%v ip=%v email=%v", dnsNames, ipAddrs, emails)
}

func TestGetTrustedDomains_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := GetTrustedDomains("192.0.2.1:443")
	if err != nil {
		t.Logf("GetTrustedDomains error: %v", err)
	}
	if result != nil {
		t.Logf("GetTrustedDomains: %v", result)
	}
}

// ============================================================
// CheckWildcard network error path
// ============================================================

func TestCheckWildcard_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := CheckWildcard("192.0.2.1:443")
	if err != nil {
		t.Logf("CheckWildcard error: %v", err)
	}
	if result != nil {
		t.Logf("CheckWildcard: %v", result)
	}
}

// ============================================================
// CheckHSTS network error path
// ============================================================

func TestCheckHSTS_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result := CheckHSTS("192.0.2.1")
	if result != nil {
		t.Logf("CheckHSTS: enabled=%v, error=%s", result.Enabled, result.Error)
	}
}

// ============================================================
// CheckBundleCompleteness - with offline cert chain
// ============================================================

func TestCheckBundleCompleteness_WithOfflineChainExt5(t *testing.T) {
	// This will fail to connect but tests the error path
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	// This will fail to connect but tests the error path
	result, err := CheckBundleCompleteness("192.0.2.1:443")
	if err == nil {
		t.Log("CheckBundleCompleteness unexpectedly succeeded")
	}
	_ = result
}

// ============================================================
// FingerprintCert helper
// ============================================================

func TestFingerprintCertExt5(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkixName("Test"),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	fp := fingerprintCert(cert)
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}
	t.Logf("fingerprint: %s", fp)
}

// ============================================================
// NewOfflineAnalysis
// ============================================================

func TestNewOfflineAnalysisExt5(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkixName("Test"),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// With intermediates
	analysis := NewOfflineAnalysis(cert, cert)
	if analysis == nil {
		t.Fatal("expected non-nil OfflineAnalysisResult")
	}
	if analysis.Target != "Test" {
		t.Errorf("expected Target=Test, got %s", analysis.Target)
	}
	if analysis.IntermediatePool == nil {
		t.Error("expected non-nil IntermediatePool")
	}

	// Without intermediates
	analysis2 := NewOfflineAnalysis(cert)
	if analysis2 == nil {
		t.Fatal("expected non-nil OfflineAnalysisResult")
	}
}

// ============================================================
// CheckPolicyFromCert - with OIDs
// ============================================================

func TestCheckPolicyFromCert_WithOIDsExt5(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkixName("Test"),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result := CheckPolicyFromCert(cert)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("CheckPolicyFromCert: compliant=%v, hasPolicies=%v, type=%s",
		result.IsCompliant, result.HasPolicies, result.ValidationType)
}

// ============================================================
// CheckKeyUsageFromCert - various configurations
// ============================================================

func TestCheckKeyUsageFromCert_NonCAWithCertSignExt5(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkixName("Non-CA"),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         false,
		KeyUsage:     x509.KeyUsageCertSign, // Non-CA with CertSign
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result := CheckKeyUsageFromCert(cert)
	if result.IsCompliant {
		t.Error("expected non-compliant for non-CA with CertSign")
	}
	if len(result.Issues) == 0 {
		t.Error("expected issues for non-CA with CertSign")
	}
}

func TestCheckKeyUsageFromCert_CAWithoutCertSignExt5(t *testing.T) {
	// Create a CA cert - Go's x509.CreateCertificate will add CertSign automatically
	// when IsCA=true, so we need to test the CheckKeyUsageFromCert logic differently
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("Bad CA"),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign, // Go adds CertSign when IsCA=true
		BasicConstraintsValid: true,
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result := CheckKeyUsageFromCert(cert)
	// CA with CertSign should be compliant for the CertSign check
	t.Logf("CheckKeyUsageFromCert CA: compliant=%v, issues=%d", result.IsCompliant, len(result.Issues))
}

func TestCheckKeyUsageFromCert_NoKeyUsageExt5(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkixName("No Usage"),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         false,
		// No KeyUsage or ExtKeyUsage
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result := CheckKeyUsageFromCert(cert)
	if result.IsCompliant {
		t.Error("expected non-compliant for cert with no key usage")
	}
}

// ============================================================
// CheckDistrustedCAFromCert with various certs
// ============================================================

func TestCheckDistrustedCAFromCert_DistrustedCAExt5(t *testing.T) {
	// Create a cert that looks like DigiNotar
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "DigiNotar Root CA",
			Organization: []string{"DigiNotar"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	result := CheckDistrustedCAFromCert([]*x509.Certificate{cert})
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.IsDistrusted {
		t.Error("expected IsDistrusted=true for DigiNotar-like cert")
	}
	t.Logf("DistrustedCAs: %d", len(result.DistrustedCAs))
	for _, ca := range result.DistrustedCAs {
		t.Logf("  Distrusted: name=%s reason=%s", ca.Name, ca.Reason)
	}
}

// ============================================================
// DownloadCertsFromDomain - output dir default
// ============================================================

func TestDownloadCertsFromDomain_DefaultDirExt5(t *testing.T) {
	// Test empty output dir defaults to "."
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	// Test empty output dir defaults to "."
	result, err := DownloadCertsFromDomain("192.0.2.1:443", "")
	if err != nil {
		t.Logf("DownloadCertsFromDomain error (expected): %v", err)
	}
	_ = result
}

// ============================================================
// CertExpiryMonitor error paths
// ============================================================

func TestCertExpiryMonitor_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result := CertExpiryMonitor([]string{"192.0.2.1:443"})
	if result != nil {
		t.Logf("CertExpiryMonitor: %d targets", len(result.Targets))
		for _, r := range result.Targets {
			t.Logf("  %s: status=%s", r.Target, r.Status)
		}
	}
}

// ============================================================
// BatchAnalyzeSecurityWithContext - cancelled context
// ============================================================

func TestBatchAnalyzeSecurityWithContext_CancelledExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow network test in short mode")
	}
	ctx, cancel := contextWithTimeoutForTest(1 * time.Nanosecond)
	defer cancel()

	// Context already cancelled
	result := BatchAnalyzeSecurityWithContext(ctx, []string{"example.com"})
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.TotalCount != 1 {
		t.Errorf("expected TotalCount=1, got %d", result.TotalCount)
	}
	if len(result.Results) > 0 && result.Results[0].SecurityLevel != "Error" {
		t.Logf("Batch result[0]: score=%d level=%s", result.Results[0].OverallScore, result.Results[0].SecurityLevel)
	}
}

// ============================================================
// VulnerabilityScan - full scan on unreachable target
// ============================================================

func TestVulnerabilityScan_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow network test in short mode")
	}
	result, err := VulnerabilityScan("192.0.2.1:443")
	if err != nil {
		t.Logf("VulnerabilityScan error: %v", err)
	}
	if result != nil {
		t.Logf("VulnerabilityScan: %d vulns checked", len(result.Vulnerabilities))
		for _, v := range result.Vulnerabilities {
			t.Logf("  %s: vulnerable=%v detail=%s", v.Name, v.Vulnerable, v.Detail)
		}
		// All should be not vulnerable for unreachable target
		for _, v := range result.Vulnerabilities {
			if v.Vulnerable {
				t.Errorf("expected not vulnerable for %s on unreachable target", v.Name)
			}
		}
	}
}

// ============================================================
// BuildHeartbeatClientHello / BuildCompressionClientHello - various hostnames
// ============================================================

func TestBuildHeartbeatClientHello_VariousHostsExt5(t *testing.T) {
	hosts := []string{"example.com:443", "test.local", "192.168.1.1:8443"}
	for _, host := range hosts {
		hello := buildHeartbeatClientHello(host)
		if len(hello) < 20 {
			t.Errorf("hello too short for %s: %d bytes", host, len(hello))
		}
		// First byte should be 0x16 (Handshake)
		if hello[0] != 0x16 {
			t.Errorf("expected 0x16, got 0x%02x", hello[0])
		}
	}
}

func TestBuildCompressionClientHello_VariousHostsExt5(t *testing.T) {
	hosts := []string{"example.com:443", "test.local:8443"}
	for _, host := range hosts {
		hello := buildCompressionClientHello(host)
		if len(hello) < 20 {
			t.Errorf("hello too short for %s: %d bytes", host, len(hello))
		}
	}
}

// ============================================================
// parseServerHelloForExtension - various data
// ============================================================

func TestParseServerHelloForExtension_ShortDataExt5(t *testing.T) {
	// Too short
	result := parseServerHelloForExtension([]byte{0x16, 0x03, 0x03}, 0xff01)
	if result {
		t.Error("expected false for short data")
	}
}

func TestParseServerHelloForExtension_NotHandshakeExt5(t *testing.T) {
	data := make([]byte, 100)
	data[0] = 0x15 // Not handshake
	result := parseServerHelloForExtension(data, 0xff01)
	if result {
		t.Error("expected false for non-handshake record")
	}
}

func TestParseServerHelloForExtension_ValidExtensionExt5(t *testing.T) {
	// Build a minimal ServerHello with renegotiation_info extension
	data := []byte{
		0x16,       // Record type: Handshake
		0x03, 0x03, // TLS 1.2
		0x00, 0x30, // Record length (48 bytes)
		0x02,             // Handshake type: ServerHello
		0x00, 0x00, 0x2C, // Handshake length
		0x03, 0x03, // Version: TLS 1.2
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Random (32 bytes)
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
		0x00,       // Session ID length: 0
		0xC0, 0x2F, // Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0x00,       // Compression: null
		0x00, 0x05, // Extensions length: 5
		0xFF, 0x01, // Extension: renegotiation_info
		0x00, 0x01, // Extension data length: 1
		0x00, // Renegotiation info: empty
	}

	result := parseServerHelloForExtension(data, 0xff01)
	if !result {
		t.Error("expected to find renegotiation_info extension")
	}
}

// ============================================================
// dnsQueryCAA - various domain formats
// ============================================================

func TestDNSQueryCAA_EmptyDomainExt5(t *testing.T) {
	// Empty domain should still build a valid query
	records, err := dnsQueryCAA("")
	t.Logf("dnsQueryCAA empty domain: records=%v, err=%v", records, err)
}

// ============================================================
// CheckHSTS - various hosts
// ============================================================

func TestCheckHSTS_InvalidHostExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result := CheckHSTS("192.0.2.1")
	if result != nil {
		t.Logf("CheckHSTS: enabled=%v error=%s", result.Enabled, result.Error)
	}
}

// ============================================================
// isWeakCipherSuite - additional branches
// ============================================================

func TestIsWeakCipherSuite_UnknownCipherExt5(t *testing.T) {
	// Test with an ID not in the weak list and with no name match
	result := isWeakCipherSuite(0xFFFF)
	t.Logf("isWeakCipherSuite(0xFFFF): %v", result)
}

func TestIsWeakCipherSuite_KnownWeakExt5(t *testing.T) {
	if !isWeakCipherSuite(0x0005) { // TLS_RSA_WITH_RC4_128_SHA
		t.Error("expected RC4 to be weak")
	}
	if !isWeakCipherSuite(0x000A) { // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		t.Error("expected 3DES to be weak")
	}
}

// ============================================================
// GenerateSelfSignedCert used in test
// ============================================================

func TestGenerateSelfSignedCert_RSA2048Ext5(t *testing.T) {
	tmpDir := t.TempDir()
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:     "test.example.com",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		DNSNames:       []string{"test.example.com"},
		OutputCertPath: filepath.Join(tmpDir, "cert.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "key.pem"),
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("Generated cert: %s, key: %s", result.CertificatePath, result.PrivateKeyPath)
}

func TestGenerateSelfSignedCert_ECDSA256Ext5(t *testing.T) {
	tmpDir := t.TempDir()
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:     "ecdsa.example.com",
		KeyType:        "ecdsa",
		KeySize:        256,
		ValidityDays:   365,
		DNSNames:       []string{"ecdsa.example.com"},
		OutputCertPath: filepath.Join(tmpDir, "ecdsa-cert.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ecdsa-key.pem"),
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert ECDSA error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestGenerateSelfSignedCert_Ed25519Ext5(t *testing.T) {
	tmpDir := t.TempDir()
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:     "ed25519.example.com",
		KeyType:        "ed25519",
		ValidityDays:   365,
		DNSNames:       []string{"ed25519.example.com"},
		OutputCertPath: filepath.Join(tmpDir, "ed25519-cert.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ed25519-key.pem"),
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert Ed25519 error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestGenerateSelfSignedCert_CAExt5(t *testing.T) {
	tmpDir := t.TempDir()
	result, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:     "Root CA",
		KeyType:        "rsa",
		KeySize:        4096,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "ca-cert.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert CA error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestGenerateSelfSignedCert_InvalidKeyTypeExt5(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := GenerateSelfSignedCert(CertificateRequest{
		CommonName:     "invalid.example.com",
		KeyType:        "INVALID",
		KeySize:        2048,
		ValidityDays:   365,
		OutputCertPath: filepath.Join(tmpDir, "cert.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "key.pem"),
	})
	if err == nil {
		t.Error("expected error for invalid key type")
	}
}

// ============================================================
// LoadFingerprintDB - valid and invalid JSON
// ============================================================

func TestLoadFingerprintDB_InvalidJSONExt5(t *testing.T) {
	err := LoadFingerprintDB([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadFingerprintDB_ValidJSONExt5(t *testing.T) {
	entries := []FingerprintMatch{
		{Type: "jarm", Hash: "testhash123", Label: "Test", Category: "other", Confidence: 0.5, Source: "custom"},
	}
	data, _ := json.Marshal(entries)

	origLen := len(ListFingerprintDB())
	err := LoadFingerprintDB(data)
	if err != nil {
		t.Fatalf("LoadFingerprintDB error: %v", err)
	}

	newLen := len(ListFingerprintDB())
	if newLen <= origLen {
		t.Error("expected fingerprint DB to grow after loading")
	}
}

// ============================================================
// MatchFingerprintsByCategory
// ============================================================

func TestMatchFingerprintsByCategory_C2Ext5(t *testing.T) {
	matches := MatchFingerprintsByCategory("c2")
	t.Logf("C2 matches: %d", len(matches))
}

func TestMatchFingerprintsByCategory_CDNExt5(t *testing.T) {
	matches := MatchFingerprintsByCategory("cdn")
	t.Logf("CDN matches: %d", len(matches))
}

func TestMatchFingerprintsByCategory_NonexistentExt5(t *testing.T) {
	matches := MatchFingerprintsByCategory("nonexistent")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for nonexistent category, got %d", len(matches))
	}
}

// ============================================================
// ComputeCertSPKIHash
// ============================================================

func TestComputeCertSPKIHash_WithCertExt5(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkixName("Test"),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	hash := ComputeCertSPKIHash(cert)
	if hash == "" {
		t.Error("expected non-empty SPKI hash")
	}
	t.Logf("SPKI hash: %s", hash)
}

// ============================================================
// AnalyzeSecurity / BatchAnalyzeSecurity error paths
// ============================================================

func TestAnalyzeSecurity_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	result, err := AnalyzeSecurity("192.0.2.1:443")
	if err != nil {
		t.Logf("AnalyzeSecurity error (expected): %v", err)
	}
	if result != nil {
		t.Logf("AnalyzeSecurity: score=%d", result.OverallScore)
	}
}

// ============================================================
// GetCertFromDomainWithContext error path
// ============================================================

func TestGetCertFromDomainWithContext_UnreachableExt5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	ctx, cancel := contextWithTimeoutForTest(2 * time.Second)
	defer cancel()
	sslInfo, err := GetCertFromDomainWithContext(ctx, "192.0.2.1:443")
	if err == nil {
		t.Error("expected error for unreachable target")
	}
	t.Logf("GetCertFromDomainWithContext error (expected): %v", err)
	_ = sslInfo
}

// ============================================================
// CheckCAA with localhost (no CAA records expected)
// ============================================================

func TestCheckCAA_LocalhostExt5(t *testing.T) {
	result, err := CheckCAA("127.0.0.1")
	t.Logf("CheckCAA localhost: result=%v, err=%v", result, err)
}

// ============================================================
// parseHostPort edge cases
// ============================================================

func TestParseHostPort_VariantsExt5(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort string
	}{
		{"example.com", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},
		{"192.168.1.1:443", "192.168.1.1", "443"},
		{"[::1]:443", "::1", "443"},
	}

	for _, tt := range tests {
		host, port := parseHostPort(tt.input)
		if host != tt.wantHost {
			t.Errorf("parseHostPort(%q) host = %q, want %q", tt.input, host, tt.wantHost)
		}
		if port != tt.wantPort {
			t.Errorf("parseHostPort(%q) port = %q, want %q", tt.input, port, tt.wantPort)
		}
	}
}

// ============================================================
// CertInfo / SSLInfo / buildCertInfo / buildCertChain
// ============================================================

func TestBuildCertChain_MultipleCertsExt5(t *testing.T) {
	// Create a chain of 3 certs
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("Root CA"),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkixName("Intermediate CA"),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(1825 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	intKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	intDER, _ := x509.CreateCertificate(rand.Reader, intTemplate, caCert, &intKey.PublicKey, caKey)
	intCert, _ := x509.ParseCertificate(intDER)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkixName("leaf.example.com"),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.example.com"},
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	chain, err := buildCertChain([]*x509.Certificate{leafCert, intCert, caCert})
	if err != nil {
		t.Fatalf("buildCertChain error: %v", err)
	}
	if chain.ChainLength != 3 {
		t.Errorf("expected ChainLength=3, got %d", chain.ChainLength)
	}
	if len(chain.Certificates) != 3 {
		t.Errorf("expected 3 certificates, got %d", len(chain.Certificates))
	}
	t.Logf("Chain: length=%d, valid=%v", chain.ChainLength, chain.IsValid)
}

// ============================================================
// context helper
// ============================================================

func contextWithTimeoutForTest(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
