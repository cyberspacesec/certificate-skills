package pkg

import (
	"testing"
)

func TestHasStatusRequestInValue(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"nil data", nil, false},
		{"empty data", []byte{}, false},
		{"short data", []byte{0x01, 0x02}, false},
		{"status_request pattern", []byte{0x30, 0x03, 0x02, 0x01, 0x05}, true}, // DER: SEQUENCE { INTEGER 5 }
		{"no status_request", []byte{0x30, 0x03, 0x02, 0x01, 0x06}, false},     // DER: SEQUENCE { INTEGER 6 }
	}

	for _, tc := range tests {
		result := hasStatusRequestInValue(tc.data)
		if result != tc.expected {
			t.Errorf("hasStatusRequestInValue(%s) = %v, want %v", tc.name, result, tc.expected)
		}
	}
}

func TestOIDString(t *testing.T) {
	tests := []struct {
		oid      []int
		expected string
	}{
		{[]int{1, 3, 6, 1, 5, 5, 7, 1, 24}, "1.3.6.1.5.5.7.1.24"},
		{[]int{2, 16, 840, 1, 114412, 2, 1}, "2.16.840.1.114412.2.1"},
		{[]int{}, ""},
		{[]int{1}, "1"},
	}

	for _, tc := range tests {
		result := oidString(tc.oid)
		if result != tc.expected {
			t.Errorf("oidString(%v) = %q, want %q", tc.oid, result, tc.expected)
		}
	}
}

func TestAsn1OIDEqual(t *testing.T) {
	oid := asn1OID{1, 3, 6, 1, 5, 5, 7, 1, 24}

	tests := []struct {
		other    []int
		expected bool
	}{
		{[]int{1, 3, 6, 1, 5, 5, 7, 1, 24}, true},     // same
		{[]int{1, 3, 6, 1, 5, 5, 7, 1, 25}, false},    // different last
		{[]int{1, 3, 6, 1}, false},                    // shorter
		{[]int{1, 3, 6, 1, 5, 5, 7, 1, 24, 0}, false}, // longer
	}

	for _, tc := range tests {
		result := oid.Equal(tc.other)
		if result != tc.expected {
			t.Errorf("asn1OID.Equal(%v) = %v, want %v", tc.other, result, tc.expected)
		}
	}
}

func TestOCSPMustStapleResult_Fields(t *testing.T) {
	result := &OCSPMustStapleResult{
		Target:        "example.com",
		HasMustStaple: false,
		HasStaple:     false,
		IsCompliant:   true,
		Detail:        "No OCSP Must-Staple requirement",
	}
	if result.HasMustStaple {
		t.Error("HasMustStaple should be false")
	}
	if !result.IsCompliant {
		t.Error("Without Must-Staple, should be compliant")
	}
}

func TestOCSPMustStapleResult_MustStapleViolation(t *testing.T) {
	result := &OCSPMustStapleResult{
		Target:        "example.com",
		HasMustStaple: true,
		HasStaple:     false,
		IsCompliant:   false,
		Violation:     "Certificate has OCSP Must-Staple extension but server does not provide OCSP staple",
	}
	if result.IsCompliant {
		t.Error("Must-Staple without staple should not be compliant")
	}
}

func TestCheckOCSPMustStapleLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckOCSPMustStaple("google.com:443")
	if err != nil {
		t.Fatalf("CheckOCSPMustStaple failed: %v", err)
	}
	t.Logf("MustStaple=%v HasStaple=%v Compliant=%v Detail=%s",
		result.HasMustStaple, result.HasStaple, result.IsCompliant, result.Detail)
}
