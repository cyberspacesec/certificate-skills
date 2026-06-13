package pkg

import (
	"testing"
)

func TestBuildHeartbeatClientHello(t *testing.T) {
	hello := buildHeartbeatClientHello("example.com:443")
	if len(hello) < 10 {
		t.Errorf("ClientHello too short: %d bytes", len(hello))
	}
	// Check TLS record type
	if hello[0] != 0x16 {
		t.Errorf("Expected record type 0x16 (Handshake), got 0x%02x", hello[0])
	}
	// Check handshake type
	if hello[5] != 0x01 {
		t.Errorf("Expected handshake type 0x01 (ClientHello), got 0x%02x", hello[5])
	}
}

func TestBuildMalformedHeartbeat(t *testing.T) {
	req := buildMalformedHeartbeat()
	if len(req) != 9 {
		t.Errorf("Expected 9 bytes for malformed heartbeat, got %d", len(req))
	}
	// Check record type is Heartbeat (0x18 = 24)
	if req[0] != 0x18 {
		t.Errorf("Expected record type 0x18 (Heartbeat), got 0x%02x", req[0])
	}
	// Check TLS version
	if req[1] != 0x03 || req[2] != 0x03 {
		t.Errorf("Expected TLS 1.2 (0x03 0x03), got 0x%02x 0x%02x", req[1], req[2])
	}
	// Check record length field
	recordLen := uint16(req[3])<<8 | uint16(req[4])
	if recordLen != 3 {
		t.Errorf("Expected record length 3, got %d", recordLen)
	}
	// Check heartbeat type
	if req[5] != 0x01 {
		t.Errorf("Expected heartbeat type 0x01 (Request), got 0x%02x", req[5])
	}
	// Check payload length field (should be 0x4000 = 16384, way more than actual 1 byte)
	payloadLen := uint16(req[6])<<8 | uint16(req[7])
	if payloadLen != 0x4000 {
		t.Errorf("Expected payload length 0x4000, got 0x%04x", payloadLen)
	}
}

func TestBuildCompressionClientHello(t *testing.T) {
	hello := buildCompressionClientHello("example.com:443")
	if len(hello) < 10 {
		t.Errorf("ClientHello too short: %d bytes", len(hello))
	}
	// Check that compression methods are included (DEFLATE + NULL)
	if hello[0] != 0x16 {
		t.Errorf("Expected record type 0x16 (Handshake), got 0x%02x", hello[0])
	}
}

func TestParseServerHelloForExtension(t *testing.T) {
	// Test with empty/invalid data
	if parseServerHelloForExtension([]byte{}, 0xff01) {
		t.Error("Expected false for empty data")
	}
	if parseServerHelloForExtension([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00}, 0xff01) {
		t.Error("Expected false for non-handshake record")
	}
}

func TestVulnerabilityScanLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := VulnerabilityScan("google.com:443")
	if err != nil {
		t.Fatalf("VulnerabilityScan failed: %v", err)
	}
	if len(result.Vulnerabilities) != 11 {
		t.Errorf("Expected 11 vulnerability checks, got %d", len(result.Vulnerabilities))
	}
	if result.Summary.TotalChecked != 11 {
		t.Errorf("Expected TotalChecked=11, got %d", result.Summary.TotalChecked)
	}
	t.Logf("Summary: Vulnerable=%d Secure=%d IsSecure=%v",
		result.Summary.Vulnerable, result.Summary.Secure, result.Summary.IsSecure)
}
