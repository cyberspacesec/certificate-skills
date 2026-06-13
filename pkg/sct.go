package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// SCT OID for embedded SCTs in certificates
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// SCTResult represents the result of an SCT (Signed Certificate Timestamp) verification.
type SCTResult struct {
	Target           string     `json:"target"`
	HasSCTs          bool       `json:"has_scts"`
	SCTCount         int        `json:"sct_count"`
	MeetsRequirement bool       `json:"meets_requirement"`
	RequiredSCTs     int        `json:"required_scts"`
	SCTs             []SCTEntry `json:"scts"`
	Warnings         []string   `json:"warnings,omitempty"`
	CertValidity     int        `json:"cert_validity_days"`
	Error            string     `json:"error,omitempty"`
}

// SCTEntry represents a single Signed Certificate Timestamp entry.
type SCTEntry struct {
	Version      int    `json:"version"`
	LogID        string `json:"log_id"`
	LogIDHex     string `json:"log_id_hex"`
	Timestamp    int64  `json:"timestamp"`
	TimestampStr string `json:"timestamp_str,omitempty"`
	Source       string `json:"source"` // embedded, ocsp, tls_extension
}

// CheckSCT verifies Signed Certificate Timestamps (SCTs) for a domain's certificate.
// SCTs are proof that the certificate was publicly logged in a Certificate Transparency log,
// as required by CA/Browser Forum baseline requirements.
func CheckSCT(target string) (*SCTResult, error) {
	result := &SCTResult{
		Target:   target,
		SCTs:     []SCTEntry{},
		Warnings: []string{},
	}

	host, port := parseHostPort(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		result.Error = fmt.Sprintf("failed to connect: %v", err)
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.Error = "no certificates found"
		return result, nil
	}

	cert := state.PeerCertificates[0]

	// Extract embedded SCTs from certificate extensions
	embeddedSCTs := parseEmbeddedSCTs(cert)
	for _, sct := range embeddedSCTs {
		sct.Source = "embedded"
		result.SCTs = append(result.SCTs, sct)
	}

	result.SCTCount = len(result.SCTs)
	result.HasSCTs = result.SCTCount > 0

	// CA/Browser Forum CT requirements based on certificate validity
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	result.CertValidity = validityDays

	var requiredSCTs int
	switch {
	case validityDays <= 822: // ≤ 27 months
		requiredSCTs = 2
	case validityDays <= 1185: // ≤ 39 months
		requiredSCTs = 3
	default:
		requiredSCTs = 4
	}
	result.RequiredSCTs = requiredSCTs
	result.MeetsRequirement = result.SCTCount >= requiredSCTs

	if !result.HasSCTs {
		result.Warnings = append(result.Warnings,
			"No SCTs found in certificate. Certificate may not comply with CA/Browser Forum CT requirements (RFC 6962)")
	}

	if result.HasSCTs && !result.MeetsRequirement {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Certificate has %d SCT(s) but requires at least %d for %d-day validity period",
				result.SCTCount, requiredSCTs, validityDays))
	}

	return result, nil
}

// parseEmbeddedSCTs parses the SCT list from the certificate's embedded extension.
func parseEmbeddedSCTs(cert *x509.Certificate) []SCTEntry {
	var scts []SCTEntry

	// Find the SCT extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSCTList) {
			// Parse the SCT list
			parsed, err := parseSCTList(ext.Value)
			if err != nil {
				continue
			}
			scts = append(scts, parsed...)
		}
	}

	return scts
}

// parseSCTList parses an SCT list from raw ASN.1 data.
// Format: SEQUENCE { OCTET STRING { SCT } }
func parseSCTList(data []byte) ([]SCTEntry, error) {
	var scts []SCTEntry

	// The SCT list is a SEQUENCE OF OCTET STRING
	// First, try to parse as a raw SEQUENCE
	if len(data) == 0 {
		return nil, fmt.Errorf("empty SCT data")
	}

	// Skip ASN.1 SEQUENCE tag and length
	offset := 0
	if data[0] != 0x04 { // OCTET STRING tag
		// Try to skip outer wrapping
		if data[0] == 0x30 { // SEQUENCE
			offset = 1
			_, length := parseASN1Length(data[offset:])
			offset += length
		}
	} else {
		offset = 1
		_, length := parseASN1Length(data[offset:])
		offset += length
	}

	// Now parse the SCT list length (2 bytes)
	if offset+2 > len(data) {
		// Try direct parsing without outer wrapper
		return parseSCTListRaw(data)
	}

	sctListLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	end := offset + sctListLen
	if end > len(data) {
		end = len(data)
	}

	// Parse individual SCTs
	for offset < end {
		if offset+2 > end {
			break
		}

		sctLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+sctLen > end {
			break
		}

		sctData := data[offset : offset+sctLen]
		sct, err := parseSingleSCT(sctData)
		if err == nil {
			scts = append(scts, sct)
		}

		offset += sctLen
	}

	if len(scts) == 0 {
		// Fallback: try raw parsing
		return parseSCTListRaw(data)
	}

	return scts, nil
}

// parseSCTListRaw tries to parse SCTs from raw data without ASN.1 wrapping.
func parseSCTListRaw(data []byte) ([]SCTEntry, error) {
	var scts []SCTEntry

	// Try reading as a 2-byte-length-prefixed list
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short")
	}

	// Check if this starts with a total length
	totalLen := int(data[0])<<8 | int(data[1])
	offset := 2

	if totalLen > len(data)-2 {
		// Maybe the whole data is the list without the outer length
		offset = 0
		totalLen = len(data)
	}

	end := offset + totalLen
	if end > len(data) {
		end = len(data)
	}

	for offset < end {
		if offset+2 > end {
			break
		}
		sctLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		if offset+sctLen > end {
			break
		}
		sctData := data[offset : offset+sctLen]
		sct, err := parseSingleSCT(sctData)
		if err == nil {
			scts = append(scts, sct)
		}
		offset += sctLen
	}

	return scts, nil
}

// parseSingleSCT parses a single SCT entry.
// Format: version(1) + logID(32) + timestamp(8) + extensions(2+length) + signature(2+length)
func parseSingleSCT(data []byte) (SCTEntry, error) {
	if len(data) < 43 { // Minimum: 1 + 32 + 8 + 2 = 43
		return SCTEntry{}, fmt.Errorf("SCT data too short: %d bytes", len(data))
	}

	sct := SCTEntry{}

	// Version (1 byte): v1 = 0
	sct.Version = int(data[0])

	// Log ID (32 bytes)
	logID := data[1:33]
	sct.LogIDHex = hex.EncodeToString(logID)
	// Display first 16 hex chars as short ID
	sct.LogID = fmt.Sprintf("%s...%s",
		sct.LogIDHex[:8],
		sct.LogIDHex[len(sct.LogIDHex)-8:])

	// Timestamp (8 bytes, milliseconds since epoch)
	timestamp := uint64(0)
	for i := 0; i < 8; i++ {
		timestamp = timestamp<<8 | uint64(data[33+i])
	}
	sct.Timestamp = int64(timestamp)
	sct.TimestampStr = time.UnixMilli(int64(timestamp)).UTC().Format(time.RFC3339)

	return sct, nil
}

// parseASN1Length parses an ASN.1 length field.
func parseASN1Length(data []byte) (contentLength int, bytesConsumed int) {
	if len(data) == 0 {
		return 0, 0
	}

	if data[0] < 0x80 {
		return int(data[0]), 1
	}

	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || numBytes > 4 || numBytes >= len(data) {
		return 0, 0
	}

	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(data[1+i])
	}

	return length, 1 + numBytes
}
