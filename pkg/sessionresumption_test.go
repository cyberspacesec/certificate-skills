package pkg

import (
	"testing"
)

func TestCheckSessionResumptionLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckSessionResumption("google.com:443")
	if err != nil {
		t.Fatalf("CheckSessionResumption failed: %v", err)
	}
	if result.Error != "" {
		t.Logf("Session resumption check error (may be network-related): %s", result.Error)
		return
	}
	t.Logf("SessionID=%v SessionTicket=%v TLSVersion=%s",
		result.SupportsSessionID, result.SupportsSessionTicket, result.TLSVersion)
}
