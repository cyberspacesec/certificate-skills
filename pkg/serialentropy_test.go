package pkg

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestEstimateShannonEntropy_SE(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		minEnt float64
		maxEnt float64
	}{
		{"all zeros", []byte{0, 0, 0, 0}, 0, 0.01},
		{"single byte", []byte{0xAA, 0xAA, 0xAA, 0xAA}, 0, 0.01},
		{"two bytes", []byte{0x00, 0xFF, 0x00, 0xFF}, 0.9, 1.1},
		{"random", []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
			0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}, 3.0, 5.0},
	}

	for _, tc := range tests {
		result := estimateShannonEntropy(tc.data)
		if result < tc.minEnt || result > tc.maxEnt {
			t.Errorf("estimateShannonEntropy(%s) = %.2f, want [%.2f, %.2f]",
				tc.name, result, tc.minEnt, tc.maxEnt)
		}
	}
}

func TestEstimateShannonEntropy_Empty(t *testing.T) {
	result := estimateShannonEntropy([]byte{})
	if result != 0 {
		t.Errorf("Expected 0 entropy for empty data, got %.2f", result)
	}
}

func TestLog2_SE(t *testing.T) {
	tests := []struct {
		x        float64
		expected float64
	}{
		{1, 0},
		{2, 1},
		{4, 2},
		{8, 3},
		{0, 0},  // edge case
		{-1, 0}, // edge case
	}

	for _, tc := range tests {
		result := log2(tc.x)
		if tc.x > 0 && result != tc.expected {
			t.Errorf("log2(%f) = %f, want %f", tc.x, result, tc.expected)
		}
	}
}

func TestAnalyzeSerialNumberFromCert_SE(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes([]byte{
			0x4a, 0x8b, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17,
			0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f,
		}),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	result := AnalyzeSerialNumberFromCert(cert)
	if result == nil {
		t.Fatal("Result should not be nil")
	}
	if result.SerialHex == "" {
		t.Error("SerialHex should not be empty")
	}
	if result.BitLength < 64 {
		t.Logf("Bit length %d (may be lower for test cert)", result.BitLength)
	}
	if result.HammingWeight == 0 {
		t.Error("HammingWeight should not be 0 for non-zero serial")
	}
	if result.HammingRatio < 0 || result.HammingRatio > 1 {
		t.Errorf("HammingRatio should be [0,1], got %.3f", result.HammingRatio)
	}
}

func TestSerialEntropyResult_Fields(t *testing.T) {
	result := &SerialEntropyResult{
		Target:          "example.com",
		SerialHex:       "4a8bc2d3e4f5061728394a5b6c7d8e9f",
		BitLength:       128,
		IsCompliant:     true,
		EntropyEstimate: 4.0,
		HammingWeight:   64,
		HammingRatio:    0.5,
		IsSequential:    false,
	}
	if !result.IsCompliant {
		t.Error("Should be compliant")
	}
	if result.IsSequential {
		t.Error("Should not be sequential")
	}
}

func TestCheckSerialEntropyLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckSerialEntropy("google.com:443")
	if err != nil {
		t.Fatalf("CheckSerialEntropy failed: %v", err)
	}
	t.Logf("BitLength=%d Compliant=%v Entropy=%.2f Sequential=%v",
		result.BitLength, result.IsCompliant, result.EntropyEstimate, result.IsSequential)
}
