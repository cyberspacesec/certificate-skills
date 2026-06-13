package pkg

import (
	"testing"
)

func TestVerifyCertChainLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := VerifyCertChain("google.com:443")
	if err != nil {
		t.Fatalf("VerifyCertChain failed: %v", err)
	}
	if !result.IsValid {
		t.Errorf("Expected google.com chain to be valid, got errors: %v", result.Errors)
	}
	if result.ChainLength == 0 {
		t.Error("Expected non-zero chain length")
	}
	if len(result.VerifiedChains) == 0 {
		t.Error("Expected at least one verified chain")
	}
	t.Logf("Chain length: %d, Verified chains: %d", result.ChainLength, len(result.VerifiedChains))
}

func TestVerifyCertChainInvalidHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := VerifyCertChain("nonexistent.invalid.example.com:443")
	if err != nil {
		// Connection failure is expected
		return
	}
	if result.IsValid {
		t.Error("Expected invalid chain for nonexistent host")
	}
}
