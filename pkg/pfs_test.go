package pkg

import (
	"testing"
)

func TestIsPFSCipher(t *testing.T) {
	tests := []struct {
		cipher string
		pfs    bool
	}{
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", true},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", true},
		{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", true},
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", false},
		{"TLS_RSA_WITH_AES_256_CBC_SHA", false},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", true},
	}

	for _, tc := range tests {
		result := isPFSCipher(tc.cipher)
		if result != tc.pfs {
			t.Errorf("isPFSCipher(%q) = %v, want %v", tc.cipher, result, tc.pfs)
		}
	}
}

func TestExtractKeyExchange(t *testing.T) {
	tests := []struct {
		cipher string
		kx     string
	}{
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE"},
		{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE"},
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", "None (static key exchange)"},
	}

	for _, tc := range tests {
		result := extractKeyExchange(tc.cipher)
		if result != tc.kx {
			t.Errorf("extractKeyExchange(%q) = %v, want %v", tc.cipher, result, tc.kx)
		}
	}
}

func TestCheckPFSLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckPFS("google.com:443")
	if err != nil {
		t.Fatalf("CheckPFS failed: %v", err)
	}
	if result.Error != "" {
		t.Logf("PFS check error (may be network-related): %s", result.Error)
		return
	}
	if !result.SupportsPFS {
		t.Error("Expected google.com to support PFS")
	}
	if result.KeyExchange != "ECDHE" && result.KeyExchange != "DHE" {
		t.Errorf("Expected PFS key exchange, got: %s", result.KeyExchange)
	}
}
