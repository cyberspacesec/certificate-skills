package pkg

import (
	"testing"
)

func TestDetectEVLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := DetectEV("google.com:443")
	if err != nil {
		t.Fatalf("DetectEV failed: %v", err)
	}
	// google.com is not EV, so it should not be detected as EV
	if result.IsEV {
		t.Error("google.com should not be detected as EV")
	}
	if result.Reason == "" {
		t.Error("Expected a reason for non-EV detection")
	}
	t.Logf("google.com EV detection: IsEV=%v, Reason=%s", result.IsEV, result.Reason)
}

func TestDetectEVPolicyOIDs(t *testing.T) {
	// Test that known EV OIDs are in the map
	if _, ok := evPolicyOIDs["2.16.840.1.114412.2.1"]; !ok {
		t.Error("Expected DigiCert EV OID in evPolicyOIDs map")
	}
	if _, ok := evPolicyOIDs["1.3.6.1.4.1.4146.1.1"]; !ok {
		t.Error("Expected GlobalSign EV OID in evPolicyOIDs map")
	}
}

func TestDetectEVDVOIDs(t *testing.T) {
	// DV OID should not be in EV map
	if _, ok := evPolicyOIDs["2.23.140.1.2.1"]; ok {
		t.Error("DV OID should not be in evPolicyOIDs map")
	}
}
