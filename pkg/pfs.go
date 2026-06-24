package pkg

import (
	"crypto/tls"
	"fmt"
)

// tlsCurveName returns the name of a TLS elliptic curve.
func tlsCurveName(curveID tls.CurveID) string {
	switch curveID {
	case tls.CurveP256:
		return "P-256 (secp256r1)"
	case tls.CurveP384:
		return "P-384 (secp384r1)"
	case tls.CurveP521:
		return "P-521 (secp521r1)"
	case tls.X25519:
		return "X25519"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", uint16(curveID))
	}
}

// PFSResult represents the result of a Perfect Forward Secrecy check.
type PFSResult struct {
	Target        string   `json:"target"`
	SupportsPFS   bool     `json:"supports_pfs"`
	PFSCipher     string   `json:"pfs_cipher,omitempty"`
	KeyExchange   string   `json:"key_exchange,omitempty"`
	DHGroup       string   `json:"dh_group,omitempty"`
	ECDHECurve    string   `json:"ecdhe_curve,omitempty"`
	PFSCiphers    []string `json:"pfs_ciphers"`
	NonPFSCiphers []string `json:"non_pfs_ciphers"`
	Error         string   `json:"error,omitempty"`
}

// CheckPFS checks whether a server supports Perfect Forward Secrecy
// by analyzing the negotiated cipher suite and scanning for PFS-capable ciphers.
func CheckPFS(target string) (*PFSResult, error) {
	result := &PFSResult{
		Target:        target,
		PFSCiphers:    []string{},
		NonPFSCiphers: []string{},
	}

	// Connect and check the negotiated cipher suite
	conn, err := TLSDial(target)
	if err != nil {
		result.Error = fmt.Sprintf("failed to connect: %v", err)
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cipherName := tls.CipherSuiteName(state.CipherSuite)

	// Check if negotiated cipher provides PFS
	result.PFSCipher = cipherName
	result.SupportsPFS = isPFSCipher(cipherName)

	if result.SupportsPFS {
		result.KeyExchange = extractKeyExchange(cipherName)
		// Note: Go's tls.ConnectionState doesn't expose the negotiated curve.
		// The curve can be inferred from the key size for RSA-backed ECDHE.
		result.ECDHECurve = "Negotiated (not exposed by Go TLS library)"
	}

	// Scan all supported ciphers for PFS classification
	scanResult, err := CipherSuiteScan(target, 0)
	if err == nil {
		for _, cs := range scanResult.CipherSuites {
			if cs.Supported {
				if isPFSCipher(cs.CipherSuite) {
					result.PFSCiphers = append(result.PFSCiphers, cs.CipherSuite)
				} else {
					result.NonPFSCiphers = append(result.NonPFSCiphers, cs.CipherSuite)
				}
			}
		}
	}

	return result, nil
}

// isPFSCipher checks if a cipher suite provides Perfect Forward Secrecy.
// PFS is provided by ECDHE or DHE key exchange.
func isPFSCipher(cipherName string) bool {
	pfsIndicators := []string{"ECDHE", "DHE"}
	for _, indicator := range pfsIndicators {
		if contains(cipherName, indicator) {
			return true
		}
	}
	return false
}

// extractKeyExchange extracts the key exchange method from a cipher suite name.
func extractKeyExchange(cipherName string) string {
	if contains(cipherName, "ECDHE") {
		return "ECDHE"
	}
	if contains(cipherName, "DHE") {
		return "DHE"
	}
	return "None (static key exchange)"
}

// contains checks if a string contains a substring (case-sensitive).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
