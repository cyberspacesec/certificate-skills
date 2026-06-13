package pkg

import (
	"testing"
)

func TestScanCertSecurityLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := ScanCertSecurity("google.com:443")
	if err != nil {
		t.Fatalf("ScanCertSecurity failed: %v", err)
	}

	if len(result.Checks) != 13 {
		t.Errorf("Expected 13 checks, got %d", len(result.Checks))
	}

	if result.Summary.TotalChecked != 13 {
		t.Errorf("Expected TotalChecked=13, got %d", result.Summary.TotalChecked)
	}

	t.Logf("Summary: Passed=%d Failed=%d IsSecure=%v",
		result.Summary.Passed, result.Summary.Failed, result.Summary.IsSecure)

	// google.com should pass most checks
	if result.Summary.Passed < 8 {
		t.Errorf("Expected google.com to pass at least 8 checks, got %d", result.Summary.Passed)
	}
}
