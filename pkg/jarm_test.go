package pkg

import (
	"encoding/hex"
	"testing"
)

func TestBuildJARMRawHash(t *testing.T) {
	tests := []struct {
		name      string
		responses []string
	}{
		{"all empty", []string{"", "", ""}},
		{"mixed", []string{"abc", "", "def"}},
		{"all filled", []string{"aaa", "bbb", "ccc"}},
	}

	for _, tc := range tests {
		result := buildJARMRawHash(tc.responses)
		// Each response contributes 64 hex chars (SHA-256)
		expectedLen := len(tc.responses) * 64
		if len(result) != expectedLen {
			t.Errorf("buildJARMRawHash(%s): expected length %d, got %d", tc.name, expectedLen, len(result))
		}
	}
}

func TestBuildJARMRawHash_EmptyResponse(t *testing.T) {
	responses := []string{"", ""}
	result := buildJARMRawHash(responses)
	// Empty responses should produce 64 '0' chars each
	if len(result) != 128 {
		t.Errorf("Expected 128 chars for 2 empty responses, got %d", len(result))
	}
	// Each empty response should be 64 zeros
	for i := 0; i < 64; i++ {
		if result[i] != '0' {
			t.Errorf("Expected '0' at position %d for empty response, got '%c'", i, result[i])
			break
		}
	}
}

func TestBuildJARMFingerprint(t *testing.T) {
	responses := []string{"aaa", "bbb", "ccc"}
	result := buildJARMFingerprint(responses)
	// Fingerprint should be 60 chars (30 from forward hash + 30 from reverse hash)
	if len(result) != 60 {
		t.Errorf("Expected 60-char fingerprint, got %d chars", len(result))
	}
	// Should be valid hex
	_, err := hex.DecodeString(result)
	if err != nil {
		t.Errorf("Fingerprint should be valid hex: %v", err)
	}
}

func TestBuildJARMFingerprint_Deterministic(t *testing.T) {
	// Note: buildJARMFingerprint sorts the input slice in-place (reverse),
	// so the second call gets a different order. Copy the slice to test.
	responses1 := []string{"aaa", "bbb", "ccc"}
	responses2 := []string{"aaa", "bbb", "ccc"} // fresh copy
	fp1 := buildJARMFingerprint(responses1)
	fp2 := buildJARMFingerprint(responses2)
	if fp1 != fp2 {
		t.Error("Same inputs should produce same fingerprint")
	}
}

func TestJARMResult_Fields(t *testing.T) {
	result := &JARMResult{
		Target:      "example.com:443",
		JARMHash:    "abc123def456",
		RawHash:     "rawhashdata",
		TLSVersion:  "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
	}
	if result.Target != "example.com:443" {
		t.Error("Target mismatch")
	}
	if result.JARMHash != "abc123def456" {
		t.Error("JARMHash mismatch")
	}
}

func TestJARMProbeCount(t *testing.T) {
	if len(jarmProbes) != 10 {
		t.Errorf("Expected 10 JARM probes, got %d", len(jarmProbes))
	}
}

func TestJARMScanLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := JARMScan("google.com:443")
	if err != nil {
		t.Fatalf("JARMScan failed: %v", err)
	}
	if result.JARMHash == "" && result.Error == "" {
		t.Error("Expected JARM hash or error")
	}
	t.Logf("JARM=%s TLS=%s Cipher=%s", result.JARMHash, result.TLSVersion, result.CipherSuite)
}
