package pkg

import (
	"testing"
)

func TestParseCAAResponse(t *testing.T) {
	// Test with a minimal DNS response with no answers
	data := []byte{
		0xAA, 0xBB, // ID
		0x81, 0x83, // Flags: response, NXDOMAIN
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		// Question section
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Root label
		0x01, 0x01, // QTYPE: CAA
		0x00, 0x01, // QCLASS: IN
	}

	records, err := parseCAAResponse(data, "example.com")
	if err != nil {
		t.Logf("parseCAAResponse returned error (expected for NXDOMAIN): %v", err)
	}
	if len(records) != 0 {
		t.Errorf("Expected 0 CAA records for NXDOMAIN, got %d", len(records))
	}
}

func TestExtractCAName(t *testing.T) {
	tests := []struct {
		issuer string
		want   string
	}{
		{"CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc", "DigiCert Inc"},
		{"O=Let's Encrypt,CN=R3", "Let's Encrypt"},
		{"CN=Test CA", "Test CA"},
		{"", ""},
	}

	for _, tc := range tests {
		got := extractCAName(tc.issuer)
		if got != tc.want {
			t.Errorf("extractCAName(%q) = %q, want %q", tc.issuer, got, tc.want)
		}
	}
}

func TestSkipDNSName(t *testing.T) {
	// Simple name: 7example3com0
	data := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x01, 0x02}
	offset := skipDNSName(data, 0)
	if offset != 13 {
		t.Errorf("Expected offset 13 after skipping DNS name, got %d", offset)
	}
}

func TestCheckCAALive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckCAA("google.com")
	if err != nil {
		t.Fatalf("CheckCAA failed: %v", err)
	}
	t.Logf("HasCAA=%v IsCompliant=%v Records=%d", result.HasCAA, result.IsCompliant, len(result.Records))
}
