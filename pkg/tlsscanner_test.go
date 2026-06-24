package pkg

import (
	"crypto/tls"
	"testing"
)

func TestGetTLSVersionName(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0300, "Unknown (0x0300)"}, // SSL 3.0 not in switch
		{0x0200, "Unknown (0x0200)"}, // Truly unknown version
	}

	for _, tc := range tests {
		result := getTLSVersionName(tc.version)
		if result != tc.expected {
			t.Errorf("getTLSVersionName(0x%04X) = %q, want %q", tc.version, result, tc.expected)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		strings  []string
		expected string
	}{
		{[]string{"", "hello", "world"}, "hello"},
		{[]string{"first", "second"}, "first"},
		{[]string{"", "", "last"}, "last"},
		{[]string{"", "", ""}, ""},
		{[]string{}, ""},
	}

	for _, tc := range tests {
		result := firstNonEmpty(tc.strings...)
		if result != tc.expected {
			t.Errorf("firstNonEmpty(%v) = %q, want %q", tc.strings, result, tc.expected)
		}
	}
}

func TestTLSProtocolVersions(t *testing.T) {
	if len(tlsProtocolVersions) != 5 {
		t.Errorf("Expected 5 TLS protocol versions, got %d", len(tlsProtocolVersions))
	}

	// Check that insecure versions are marked as such
	for _, pv := range tlsProtocolVersions {
		if pv.Version == tls.VersionSSL30 || pv.Version == tls.VersionTLS10 || pv.Version == tls.VersionTLS11 {
			if pv.Secure {
				t.Errorf("%s should be marked as insecure", pv.Name)
			}
		}
		if pv.Version == tls.VersionTLS12 || pv.Version == tls.VersionTLS13 {
			if !pv.Secure {
				t.Errorf("%s should be marked as secure", pv.Name)
			}
		}
	}
}

func TestTLSProtocolScanResult_Fields(t *testing.T) {
	result := &TLSProtocolScanResult{
		Target: "example.com:443",
		Protocols: []TLSProtocolResult{
			{Version: "TLS 1.2", VersionCode: tls.VersionTLS12, Supported: true},
			{Version: "TLS 1.3", VersionCode: tls.VersionTLS13, Supported: true},
		},
		Summary: TLSProtocolSummary{
			SupportedVersions:   []string{"TLS 1.2", "TLS 1.3"},
			UnsupportedVersions: []string{"SSL 3.0", "TLS 1.0", "TLS 1.1"},
			IsSecure:            true,
		},
	}
	if result.Target != "example.com:443" {
		t.Error("Target mismatch")
	}
	if !result.Summary.IsSecure {
		t.Error("Should be secure with only TLS 1.2+1.3")
	}
}

func TestTLSProtocolScanLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := TLSProtocolScan("google.com:443")
	if err != nil {
		t.Fatalf("TLSProtocolScan failed: %v", err)
	}
	if len(result.Protocols) == 0 {
		t.Error("Expected at least one protocol result")
	}
	t.Logf("Supported=%v Secure=%v", result.Summary.SupportedVersions, result.Summary.IsSecure)
}
