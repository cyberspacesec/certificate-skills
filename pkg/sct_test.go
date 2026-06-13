package pkg

import (
	"testing"
)

func TestParseASN1Length(t *testing.T) {
	tests := []struct {
		data     []byte
		wantLen  int
		wantCons int
	}{
		{[]byte{0x05}, 5, 1},               // Short form
		{[]byte{0x81, 0x80}, 128, 2},       // Long form, 1 byte
		{[]byte{0x82, 0x01, 0x00}, 256, 3}, // Long form, 2 bytes
	}

	for _, tc := range tests {
		gotLen, gotCons := parseASN1Length(tc.data)
		if gotLen != tc.wantLen || gotCons != tc.wantCons {
			t.Errorf("parseASN1Length(%v) = (%d, %d), want (%d, %d)",
				tc.data, gotLen, gotCons, tc.wantLen, tc.wantCons)
		}
	}
}

func TestCheckSCTLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckSCT("google.com:443")
	if err != nil {
		t.Fatalf("CheckSCT failed: %v", err)
	}
	if result.Error != "" {
		t.Logf("SCT check error (network): %s", result.Error)
		return
	}
	t.Logf("HasSCTs=%v SCTCount=%d MeetsRequirement=%v",
		result.HasSCTs, result.SCTCount, result.MeetsRequirement)
}
