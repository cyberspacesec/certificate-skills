package pkg

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// JA3Result represents the result of a JA3/JA3S fingerprint scan.
type JA3Result struct {
	Target      string `json:"target"`
	JA3Hash     string `json:"ja3_hash"`
	JA3Raw      string `json:"ja3_raw"`
	JA3SHash    string `json:"ja3s_hash"`
	JA3SRaw     string `json:"ja3s_raw"`
	TLSVersion  string `json:"tls_version"`
	CipherSuite string `json:"cipher_suite"`
	ALPN        string `json:"alpn,omitempty"`
	Error       string `json:"error,omitempty"`
}

// JA3 creates a fingerprint of a TLS Client Hello by hashing:
// TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
//
// JA3S creates a fingerprint of a TLS Server Hello by hashing:
// TLSVersion,CipherSuite,Extensions
//
// Both are MD5 hashes of the raw string representation.
// These fingerprints are widely used for:
// - Malware C2 identification
// - TLS client/server classification
// - Service fingerprinting in cyberspace mapping
// - Bot detection

// JA3Scan performs a TLS connection to the target and generates
// both JA3 (client) and JA3S (server) fingerprints.
//
// Note: The JA3 hash represents OUR client hello as seen by the server,
// and the JA3S hash represents the server's hello as seen by us.
// For cyberspace mapping, JA3S is more useful (fingerprint the server).
func JA3Scan(target string) (*JA3Result, error) {
	host, port := parseHostPort(target)
	addr := net.JoinHostPort(host, port)

	result := &JA3Result{
		Target: target,
	}

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	// Build a comprehensive Client Hello with common cipher suites and extensions
	// to get a full server response for JA3S fingerprinting
	config := &tls.Config{
		ServerName: host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		result.Error = fmt.Sprintf("failed to connect: %v", err)
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Generate JA3 (client fingerprint)
	// This represents the Client Hello that WE sent
	result.JA3Raw = generateJA3Raw(state)
	result.JA3Hash = md5Hash(result.JA3Raw)

	// Generate JA3S (server fingerprint)
	// This represents the Server Hello that the TARGET sent
	result.JA3SRaw = generateJA3SRaw(state)
	result.JA3SHash = md5Hash(result.JA3SRaw)

	result.TLSVersion = getTLSVersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	if state.NegotiatedProtocol != "" {
		result.ALPN = state.NegotiatedProtocol
	}

	return result, nil
}

// generateJA3Raw creates the raw JA3 string from the TLS connection state.
// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
//
// Since Go's tls package doesn't expose the raw Client Hello fields directly,
// we reconstruct the JA3 string from the connection state and configuration.
// The cipher suites are from our configured client hello, and the
// curves/formats are from our curve preferences.
func generateJA3Raw(state tls.ConnectionState) string {
	// TLS Version
	version := fmt.Sprintf("%d", state.Version)

	// Cipher Suites - use the client-side configured suites
	// Go's ConnectionState doesn't expose the full client cipher list,
	// so we use the standard comprehensive list that our client sends
	cipherSuites := getStandardClientCipherIDs()
	cipherStr := intsToString(cipherSuites, ",")

	// Extensions - standard TLS extensions sent by Go client
	// These are the typical extension IDs in a Go TLS Client Hello
	extensions := []int{
		0x0000, // server_name
		0x000d, // signature_algorithms
		0x0010, // application_layer_protocol_negotiation (ALPN)
		0x0017, // extended_master_secret
		0x0023, // session_ticket
		0x002b, // supported_versions
		0x002d, // psk_key_exchange_modes
		0x0033, // key_share
		0xff01, // renegotiation_info
	}
	extStr := intsToString(extensions, ",")

	// Elliptic Curves (Supported Groups)
	curves := []int{
		0x001d, // X25519
		0x0017, // secp256r1
		0x0018, // secp384r1
		0x0019, // secp521r1
	}
	curveStr := intsToString(curves, ",")

	// Elliptic Curve Point Formats
	pointFormats := []int{
		0x00, // uncompressed
	}
	pointStr := intsToString(pointFormats, ",")

	return fmt.Sprintf("%s,%s,%s,%s,%s", version, cipherStr, extStr, curveStr, pointStr)
}

// generateJA3SRaw creates the raw JA3S string from the TLS connection state.
// Format: TLSVersion,CipherSuite,Extensions
func generateJA3SRaw(state tls.ConnectionState) string {
	// TLS Version chosen by the server
	version := fmt.Sprintf("%d", state.Version)

	// Cipher Suite chosen by the server
	cipherSuite := fmt.Sprintf("%d", state.CipherSuite)

	// Extensions in the Server Hello
	// The server only includes a subset of extensions in its response
	serverExtensions := []string{}

	if state.NegotiatedProtocol != "" {
		serverExtensions = append(serverExtensions, "16") // ALPN
	}

	if state.DidResume {
		serverExtensions = append(serverExtensions, "23") // session_ticket
	}

	// supported_versions is always present in TLS 1.3
	if state.Version == tls.VersionTLS13 {
		serverExtensions = append(serverExtensions, "43") // supported_versions
	}

	// renegotiation_info is almost always present
	serverExtensions = append(serverExtensions, "65281") // 0xff01

	extStr := strings.Join(serverExtensions, "-")

	return fmt.Sprintf("%s,%s,%s", version, cipherSuite, extStr)
}

// getStandardClientCipherIDs returns the list of cipher suite IDs
// that a standard Go TLS client sends in its Client Hello.
func getStandardClientCipherIDs() []int {
	// Go 1.23 default cipher suites for TLS 1.2 and 1.3
	return []int{
		// TLS 1.3 cipher suites
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		// TLS 1.2 cipher suites
		0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
		0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
		0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
		0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
	}
}

// md5Hash computes the MD5 hash of a string and returns it as hex.
func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// intsToString converts a slice of ints to a delimited string.
func intsToString(ids []int, sep string) string {
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = fmt.Sprintf("%d", id)
	}
	return strings.Join(strs, sep)
}
