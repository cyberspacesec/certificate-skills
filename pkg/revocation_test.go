package pkg

import (
	"testing"
)

func TestRevocationResult_Fields(t *testing.T) {
	result := &RevocationResult{
		Target:        "example.com",
		OCSPStatus:    OCSPStatus{Status: "Good", Checked: true},
		CRLStatus:     CRLStatus{Status: "Good", Checked: true},
		OverallStatus: "Good",
	}
	if result.OverallStatus != "Good" {
		t.Error("OverallStatus should be Good")
	}
	if !result.OCSPStatus.Checked {
		t.Error("OCSP should be checked")
	}
}

func TestOCSPStatus_Fields(t *testing.T) {
	status := OCSPStatus{
		Checked:    true,
		Status:     "Good",
		ThisUpdate: "2024-01-01T00:00:00Z",
		NextUpdate: "2024-01-08T00:00:00Z",
		OCSPURL:    "http://ocsp.example.com",
	}
	if !status.Checked {
		t.Error("Should be checked")
	}
	if status.Status != "Good" {
		t.Error("Status should be Good")
	}
}

func TestCRLStatus_Fields(t *testing.T) {
	status := CRLStatus{
		Checked:    true,
		Status:     "Good",
		CRLURL:     "http://crl.example.com/ca.crl",
		ThisUpdate: "2024-01-01T00:00:00Z",
		NextUpdate: "2024-02-01T00:00:00Z",
	}
	if !status.Checked {
		t.Error("Should be checked")
	}
}

func TestCheckRevocationLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckRevocation("google.com:443")
	if err != nil {
		t.Fatalf("CheckRevocation failed: %v", err)
	}
	t.Logf("Overall=%s OCSP=%s CRL=%s",
		result.OverallStatus, result.OCSPStatus.Status, result.CRLStatus.Status)
}
