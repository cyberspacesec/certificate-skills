package pkg

import (
	"crypto/tls"
	"testing"
)

func TestIsWeakCipherSuite(t *testing.T) {
	tests := []struct {
		id       uint16
		expected bool
	}{
		{0x0005, true},  // TLS_RSA_WITH_RC4_128_SHA
		{0x000A, true},  // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		{0x0002, true},  // TLS_RSA_WITH_NULL_SHA
		{0x0003, true},  // TLS_RSA_EXPORT_WITH_RC4_40_MD5
		{0x0009, true},  // TLS_RSA_WITH_DES_CBC_SHA
		{0x003B, true},  // TLS_RSA_WITH_NULL_SHA256
		{0x2F, false},   // TLS_RSA_WITH_AES_128_CBC_SHA (not in weak list, not matching keywords)
		{0xC02B, false}, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (secure)
		{0xC02F, false}, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secure)
	}

	for _, tc := range tests {
		result := isWeakCipherSuite(tc.id)
		if result != tc.expected {
			t.Errorf("isWeakCipherSuite(0x%04X) = %v, want %v", tc.id, result, tc.expected)
		}
	}
}

func TestGetCipherSuitesForVersion_TLS12(t *testing.T) {
	ciphers := getCipherSuitesForVersion(tls.VersionTLS12)
	if len(ciphers) == 0 {
		t.Error("Expected non-empty cipher list for TLS 1.2")
	}
	// Should include both secure and weak ciphers for testing
	foundSecure := false
	foundWeak := false
	for _, id := range ciphers {
		if isWeakCipherSuite(id) {
			foundWeak = true
		} else {
			foundSecure = true
		}
	}
	if !foundSecure {
		t.Error("Expected at least one secure cipher in TLS 1.2 list")
	}
	if !foundWeak {
		t.Error("Expected at least one weak cipher in TLS 1.2 list for testing")
	}
}

func TestGetCipherSuitesForVersion_TLS13(t *testing.T) {
	ciphers := getCipherSuitesForVersion(tls.VersionTLS13)
	if len(ciphers) != 3 {
		t.Errorf("Expected 3 TLS 1.3 ciphers, got %d", len(ciphers))
	}
	// TLS 1.3 ciphers should not be weak
	for _, id := range ciphers {
		if isWeakCipherSuite(id) {
			t.Errorf("TLS 1.3 cipher 0x%04X should not be weak", id)
		}
	}
}

func TestCipherScanResult_Fields(t *testing.T) {
	result := &CipherScanResult{
		Target:     "example.com:443",
		TLSVersion: "TLS 1.2",
		CipherSuites: []CipherSuiteResult{
			{CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ID: 0xC02F, Supported: true, Secure: true},
			{CipherSuite: "TLS_RSA_WITH_RC4_128_SHA", ID: 0x0005, Supported: false, Secure: false, Error: "not supported"},
		},
	}
	if result.Target != "example.com:443" {
		t.Error("Target mismatch")
	}
	if len(result.CipherSuites) != 2 {
		t.Error("Expected 2 cipher suites")
	}
}

func TestCipherScanSummary_Fields(t *testing.T) {
	summary := CipherScanSummary{
		TotalTested:    10,
		SupportedCount: 5,
		SecureCount:    4,
		WeakCount:      1,
		IsSecure:       false,
	}
	if summary.IsSecure {
		t.Error("Should not be secure when WeakCount > 0")
	}
}

func TestCipherSuiteScanLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CipherSuiteScan("google.com:443", tls.VersionTLS12)
	if err != nil {
		t.Fatalf("CipherSuiteScan failed: %v", err)
	}
	if len(result.CipherSuites) == 0 {
		t.Error("Expected at least one cipher suite")
	}
	t.Logf("Tested %d ciphers, supported=%d secure=%d weak=%d",
		result.Summary.TotalTested, result.Summary.SupportedCount,
		result.Summary.SecureCount, result.Summary.WeakCount)
}
