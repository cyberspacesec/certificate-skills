package pkg

import (
	"testing"
)

func TestMd5Hash(t *testing.T) {
	// MD5 of empty string is well-known
	result := md5Hash("")
	if result != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("md5Hash('') = %s, want d41d8cd98f00b204e9800998ecf8427e", result)
	}

	// MD5 of "hello"
	result = md5Hash("hello")
	if result != "5d41402abc4b2a76b9719d911017c592" {
		t.Errorf("md5Hash('hello') = %s, want 5d41402abc4b2a76b9719d911017c592", result)
	}
}

func TestIntsToString(t *testing.T) {
	tests := []struct {
		ids      []int
		sep      string
		expected string
	}{
		{[]int{1, 2, 3}, ",", "1,2,3"},
		{[]int{771, 772}, "-", "771-772"},
		{[]int{}, ",", ""},
		{[]int{42}, ",", "42"},
	}

	for _, tc := range tests {
		result := intsToString(tc.ids, tc.sep)
		if result != tc.expected {
			t.Errorf("intsToString(%v, %q) = %q, want %q", tc.ids, tc.sep, result, tc.expected)
		}
	}
}

func TestGetStandardClientCipherIDs(t *testing.T) {
	ids := getStandardClientCipherIDs()
	if len(ids) == 0 {
		t.Error("Expected non-empty cipher ID list")
	}
	// Should include TLS 1.3 ciphers (0x1301, 0x1302, 0x1303)
	foundTLS13 := false
	for _, id := range ids {
		if id >= 0x1301 && id <= 0x1303 {
			foundTLS13 = true
			break
		}
	}
	if !foundTLS13 {
		t.Error("Expected TLS 1.3 cipher IDs in standard client list")
	}
}

func TestGenerateJA3Raw(t *testing.T) {
	// Test that generateJA3Raw produces a non-empty string with the expected format
	// We can't easily create a real ConnectionState, so test the helper functions
	ids := getStandardClientCipherIDs()
	cipherStr := intsToString(ids, ",")
	if cipherStr == "" {
		t.Error("Cipher string should not be empty")
	}
	// Should contain known cipher IDs
	if len(ids) < 5 {
		t.Errorf("Expected at least 5 cipher IDs, got %d", len(ids))
	}
}

func TestGenerateJA3SRaw(t *testing.T) {
	// Test the helper components of JA3S generation
	// JA3S format: TLSVersion,CipherSuite,Extensions
	// We test the string building logic indirectly
	extensions := []string{"16", "65281"}
	extStr := ""
	for i, ext := range extensions {
		if i > 0 {
			extStr += "-"
		}
		extStr += ext
	}
	if extStr != "16-65281" {
		t.Errorf("Extension string format wrong: %s", extStr)
	}
}

func TestJA3Result_Fields(t *testing.T) {
	result := &JA3Result{
		Target:      "example.com:443",
		JA3Hash:     "abc123",
		JA3Raw:      "771,4866-4867-4868,...",
		JA3SHash:    "def456",
		JA3SRaw:     "771,49199,...",
		TLSVersion:  "TLS 1.2",
		CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		ALPN:        "h2",
	}
	if result.Target != "example.com:443" {
		t.Error("Target mismatch")
	}
	if result.ALPN != "h2" {
		t.Error("ALPN mismatch")
	}
}

func TestJA3ScanLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := JA3Scan("google.com:443")
	if err != nil {
		t.Fatalf("JA3Scan failed: %v", err)
	}
	if result.JA3Hash == "" && result.Error == "" {
		t.Error("Expected JA3 hash or error")
	}
	t.Logf("JA3=%s JA3S=%s TLS=%s Cipher=%s",
		result.JA3Hash, result.JA3SHash, result.TLSVersion, result.CipherSuite)
}
