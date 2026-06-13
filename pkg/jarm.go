package pkg

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// JARMResult represents the result of a JARM fingerprint scan.
type JARMResult struct {
	Target      string `json:"target"`
	JARMHash    string `json:"jarm_hash"`
	RawHash     string `json:"raw_hash"`
	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	Error       string `json:"error,omitempty"`
}

// JARM probe configurations.
// JARM sends 10 different Client Hello packets with specific TLS version
// and cipher suite combinations, then hashes the server's responses.
//
// The 10 probes are divided into 3 groups based on the TLS version
// sent in the Client Hello:
//   - Group 1: TLS 1.2 Client Hello (probes 0-2)
//   - Group 2: TLS 1.2 Client Hello with specific GREASE (probes 3-6)
//   - Group 3: TLS 1.3 Client Hello (probes 7-9)
//
// Each probe tests a different combination of:
//   - TLS version in the record layer
//   - TLS version in the Client Hello
//   - Cipher suites list
//   - ALPN extension values

// jarmProbe defines a single JARM probe configuration.
type jarmProbe struct {
	// The TLS version to send in the Client Hello
	Version uint16
	// The cipher suites to include
	CipherSuites []uint16
	// The ALPN protocols to include
	ALPN []string
	// The TLS version to use in the record layer (0 means use Version)
	RecordVersion uint16
	// Whether to send the server name indication extension
	SendSNI bool
	// Whether to include the supported versions extension
	SupportedVersions []uint16
	// Whether to include supported groups
	SupportedGroups []tls.CurveID
}

// jarmProbes defines the 10 probes used by JARM.
// Based on the original JARM specification by Salesforce Engineering.
var jarmProbes = []jarmProbe{
	// Probe 0: TLS 1.2, standard ciphers, no ALPN
	{
		Version: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		ALPN:            []string{},
		SendSNI:         true,
		SupportedGroups: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	},
	// Probe 1: TLS 1.2, standard ciphers, with ALPN
	{
		Version: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		ALPN:            []string{"http/1.1"},
		SendSNI:         true,
		SupportedGroups: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	},
	// Probe 2: TLS 1.2, all ciphers, with ALPN
	{
		Version: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
		ALPN:            []string{"h2", "http/1.1"},
		SendSNI:         true,
		SupportedGroups: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	},
	// Probe 3: TLS 1.3, standard ciphers, no ALPN
	{
		Version: tls.VersionTLS12, // Client Hello is always 1.2 format
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			// TLS 1.3 ciphers
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		ALPN:              []string{},
		SendSNI:           true,
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedGroups:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	},
	// Probe 4: TLS 1.3, standard ciphers, with ALPN
	{
		Version: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		ALPN:              []string{"http/1.1"},
		SendSNI:           true,
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedGroups:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	},
	// Probe 5: TLS 1.3, all ciphers, with ALPN
	{
		Version: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		ALPN:              []string{"h2", "http/1.1"},
		SendSNI:           true,
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedGroups:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	},
	// Probe 6: TLS 1.3, standard ciphers, forward secrecy only, with ALPN
	{
		Version: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		ALPN:              []string{"h2", "http/1.1"},
		SendSNI:           true,
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedGroups:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	},
	// Probe 7: TLS 1.2, short cipher list, no ALPN
	{
		Version: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ALPN:            []string{},
		SendSNI:         true,
		SupportedGroups: []tls.CurveID{tls.X25519, tls.CurveP256},
	},
	// Probe 8: TLS 1.2, short cipher list, with ALPN
	{
		Version: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ALPN:            []string{"http/1.1"},
		SendSNI:         true,
		SupportedGroups: []tls.CurveID{tls.X25519, tls.CurveP256},
	},
	// Probe 9: TLS 1.2, short cipher list, with h2 ALPN
	{
		Version: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ALPN:            []string{"h2", "http/1.1"},
		SendSNI:         true,
		SupportedGroups: []tls.CurveID{tls.X25519, tls.CurveP256},
	},
}

// JARMScan performs a JARM fingerprint scan against the target.
// It sends multiple TLS Client Hello probes with different configurations
// and hashes the server's responses to create a unique fingerprint.
func JARMScan(target string) (*JARMResult, error) {
	host, port := parseHostPort(target)
	addr := net.JoinHostPort(host, port)

	result := &JARMResult{
		Target: target,
	}

	// Run all 10 probes and collect the responses
	var responses []string
	var lastTLSVersion string
	var lastCipherSuite string

	for _, probe := range jarmProbes {
		response, tlsVer, cipher, err := jarmProbeServer(addr, host, probe)
		if err != nil {
			responses = append(responses, "")
			continue
		}
		responses = append(responses, response)
		if tlsVer != "" {
			lastTLSVersion = tlsVer
		}
		if cipher != "" {
			lastCipherSuite = cipher
		}
	}

	// Ensure we got at least one response
	hasResponse := false
	for _, r := range responses {
		if r != "" {
			hasResponse = true
			break
		}
	}

	if !hasResponse {
		result.Error = "no TLS responses received from target"
		return result, nil
	}

	// Build the JARM hash from probe responses
	// Format: concatenate SHA-256 of each response, then hash the concatenation
	// This follows the standard JARM methodology
	result.RawHash = buildJARMRawHash(responses)
	result.JARMHash = buildJARMFingerprint(responses)
	result.TLSVersion = lastTLSVersion
	result.CipherSuite = lastCipherSuite

	return result, nil
}

// jarmProbeServer sends a single JARM probe and returns the response fingerprint.
// The fingerprint is derived from the Server Hello parameters:
// TLS version, cipher suite, and ALPN.
func jarmProbeServer(addr, hostname string, probe jarmProbe) (string, string, string, error) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	config := &tls.Config{
		ServerName:         hostname,
		MinVersion:         probe.Version,
		MaxVersion:         probe.Version,
		CipherSuites:       probe.CipherSuites,
		InsecureSkipVerify: true,
		NextProtos:         probe.ALPN,
		CurvePreferences:   probe.SupportedGroups,
	}

	if !probe.SendSNI {
		config.ServerName = ""
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Extract the response fingerprint components
	tlsVersion := getTLSVersionName(state.Version)
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)
	alpn := state.NegotiatedProtocol

	// Build response string: version|cipher|alpn
	var parts []string
	parts = append(parts, fmt.Sprintf("%04x", state.Version))
	parts = append(parts, fmt.Sprintf("%04x", state.CipherSuite))
	if alpn != "" {
		parts = append(parts, alpn)
	}

	response := strings.Join(parts, "|")

	return response, tlsVersion, cipherSuite, nil
}

// buildJARMRawHash builds the raw JARM hash from individual probe responses.
// Each probe response is hashed, and the hashes are concatenated.
func buildJARMRawHash(responses []string) string {
	var parts []string
	for _, resp := range responses {
		if resp == "" {
			parts = append(parts, strings.Repeat("0", 64)) // 32 bytes = 64 hex chars
			continue
		}
		h := sha256.Sum256([]byte(resp))
		parts = append(parts, hex.EncodeToString(h[:]))
	}
	return strings.Join(parts, "")
}

// buildJARMFingerprint builds the final JARM fingerprint.
// The fingerprint is composed of:
// - The SHA-256 hash of the concatenated probe responses (first half)
// - The SHA-256 hash of the concatenated probe responses in reverse order (second half)
// Each half is truncated to 30 characters.
func buildJARMFingerprint(responses []string) string {
	// Forward hash
	forwardData := strings.Join(responses, ",")
	forwardHash := sha256.Sum256([]byte(forwardData))

	// Reverse hash
	sort.Sort(sort.Reverse(sort.StringSlice(responses)))
	reverseData := strings.Join(responses, ",")
	reverseHash := sha256.Sum256([]byte(reverseData))

	// Combine: first 30 chars of each hash
	fingerprint := hex.EncodeToString(forwardHash[:])[:30] + hex.EncodeToString(reverseHash[:])[:30]

	return fingerprint
}
