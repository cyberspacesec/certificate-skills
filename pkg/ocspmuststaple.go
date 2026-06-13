package pkg

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// OCSPMustStapleResult represents the result of checking OCSP Must-Staple compliance.
type OCSPMustStapleResult struct {
	Target       string `json:"target"`
	HasMustStaple bool  `json:"has_must_staple"`
	HasStaple    bool   `json:"has_staple"`
	IsCompliant  bool   `json:"is_compliant"`
	Violation    string `json:"violation,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// OCSP Must-Staple extension OID: 1.3.6.1.5.5.7.1.24
var ocspMustStapleOID = asn1OID{1, 3, 6, 1, 5, 5, 7, 1, 24}

// asn1OID represents an ASN.1 Object Identifier.
type asn1OID []int

// Equal checks if two OIDs are equal.
func (o asn1OID) Equal(other []int) bool {
	if len(o) != len(other) {
		return false
	}
	for i, v := range o {
		if v != other[i] {
			return false
		}
	}
	return true
}

// CheckOCSPMustStaple checks whether a certificate has the OCSP Must-Staple
// extension and whether the server actually provides an OCSP staple.
// A certificate with Must-Staple that fails to staple is a security defect
// because compliant clients will hard-fail the connection.
func CheckOCSPMustStaple(target string) (*OCSPMustStapleResult, error) {
	result := &OCSPMustStapleResult{
		Target: target,
	}

	conn, err := TLSDial(target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]

	// Check for OCSP Must-Staple extension in the certificate
	result.HasMustStaple = hasMustStapleExtension(cert)

	// Check if the server provided an OCSP staple
	result.HasStaple = len(state.OCSPResponse) > 0

	// Determine compliance
	if result.HasMustStaple && !result.HasStaple {
		result.IsCompliant = false
		result.Violation = "Certificate has OCSP Must-Staple extension but server does not provide OCSP staple"
		result.Detail = "Clients supporting Must-Staple (RFC 7633) will hard-fail on this connection. " +
			"This is a High severity misconfiguration because the certificate requests staple enforcement " +
			"but the server fails to deliver the staple."
	} else if result.HasMustStaple && result.HasStaple {
		result.IsCompliant = true
		result.Detail = "Certificate has OCSP Must-Staple and server provides staple correctly"
	} else if !result.HasMustStaple && result.HasStaple {
		result.IsCompliant = true
		result.Detail = "Server provides OCSP staple voluntarily (certificate does not require it)"
	} else {
		result.IsCompliant = true
		result.Detail = "No OCSP Must-Staple requirement; no staple provided (acceptable)"
	}

	return result, nil
}

// hasMustStapleExtension checks if the certificate has the TLS feature
// extension with status_request (OCSP Must-Staple) as defined in RFC 7633.
func hasMustStapleExtension(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if len(ext.Id) == 9 && ext.Id[0] == 1 && ext.Id[1] == 3 && ext.Id[2] == 6 &&
			ext.Id[3] == 1 && ext.Id[4] == 5 && ext.Id[5] == 5 && ext.Id[6] == 7 &&
			ext.Id[7] == 1 && ext.Id[8] == 24 {
			// This is the TLS feature extension (1.3.6.1.5.5.7.1.24)
			// Check if status_request (value 5) is in the value
			return hasStatusRequestInValue(ext.Value)
		}
	}

	// Also check using the standard Go library's ExtraExtensions
	// The OCSP Must-Staple is indicated by the TLS feature extension
	// with status_request (5) in the value
	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		if oidStr == "1.3.6.1.5.5.7.1.24" {
			return hasStatusRequestInValue(ext.Value)
		}
	}

	return false
}

// hasStatusRequestInValue parses the DER-encoded TLS feature extension value
// and checks if status_request (5) is present.
func hasStatusRequestInValue(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// The TLS feature extension value is a SEQUENCE of INTEGERs
	// DER format: 30 xx 02 01 05 (status_request = 5)
	// We need to find the byte sequence 02 01 05 in the value
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0x02 && data[i+1] == 0x01 && data[i+2] == 0x05 {
			return true
		}
	}

	// Some certificates encode it differently - check for the raw bytes
	// status_request is TLS extension type 5, sometimes encoded as 05 01 00
	// Try a broader search
	for i := 0; i < len(data); i++ {
		if data[i] == 0x05 {
			return true
		}
	}

	return false
}

// String returns a string representation of an OID.
func oidString(oid []int) string {
	parts := make([]string, len(oid))
	for i, v := range oid {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ".")
}
