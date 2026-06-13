package pkg

import (
	"os"
	"testing"
)

func TestCertExpiryMonitorLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result := CertExpiryMonitor([]string{"google.com", "github.com"})
	if result.TotalCount != 2 {
		t.Errorf("Expected TotalCount=2, got %d", result.TotalCount)
	}
	if result.ErrorCount > 0 {
		t.Logf("Errors: %d (may be network-related)", result.ErrorCount)
	}
	// At least one should be healthy
	if result.HealthyCount+result.WarningCount+result.CriticalCount+result.ExpiredCount == 0 && result.ErrorCount == 2 {
		t.Error("Expected at least one target to have a valid check")
	}
	t.Logf("Results: Expired=%d Critical=%d Warning=%d Healthy=%d Error=%d",
		result.ExpiredCount, result.CriticalCount, result.WarningCount, result.HealthyCount, result.ErrorCount)
}

func TestCertExpiryMonitorEmpty(t *testing.T) {
	result := CertExpiryMonitor([]string{})
	if result.TotalCount != 0 {
		t.Errorf("Expected TotalCount=0, got %d", result.TotalCount)
	}
}

func TestCertExpiryMonitorFileTarget(t *testing.T) {
	// Generate a temporary cert and check expiry
	req := CertificateRequest{
		CommonName:   "test-expiry-monitor",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
	}
	genResult, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}
	defer os.Remove(genResult.CertificatePath)
	defer os.Remove(genResult.PrivateKeyPath)

	result := CertExpiryMonitor([]string{genResult.CertificatePath})
	if result.TotalCount != 1 {
		t.Errorf("Expected TotalCount=1, got %d", result.TotalCount)
	}
	if result.HealthyCount != 1 {
		t.Errorf("Expected HealthyCount=1 (cert is valid for 365 days), got %d", result.HealthyCount)
	}
}
