package pkg

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"time"
)

// CipherSuiteResult represents a single cipher suite scan result.
type CipherSuiteResult struct {
	CipherSuite string `json:"cipher_suite"`
	ID          uint16 `json:"id"`
	Supported   bool   `json:"supported"`
	Secure      bool   `json:"secure"`
	Error       string `json:"error,omitempty"`
}

// CipherScanResult represents the complete cipher suite scan result.
type CipherScanResult struct {
	Target       string              `json:"target"`
	TLSVersion   string              `json:"tls_version"`
	CipherSuites []CipherSuiteResult `json:"cipher_suites"`
	Summary      CipherScanSummary   `json:"summary"`
}

// CipherScanSummary provides a summary of supported cipher suites.
type CipherScanSummary struct {
	TotalTested    int      `json:"total_tested"`
	SupportedCount int      `json:"supported_count"`
	SecureCount    int      `json:"secure_count"`
	WeakCount      int      `json:"weak_count"`
	SecureSuites   []string `json:"secure_suites"`
	WeakSuites     []string `json:"weak_suites"`
	IsSecure       bool     `json:"is_secure"`
}

// Weak cipher suite IDs (IANA assignments) — Go doesn't export all as constants.
var weakCipherIDs = map[uint16]bool{
	// RC4 ciphers
	0x0005:   true, // TLS_RSA_WITH_RC4_128_SHA
	0x0004:   true, // TLS_RSA_WITH_RC4_128_MD5
	0x00C011: true, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
	0x00C007: true, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	// 3DES
	0x000A:   true, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x00C012: true, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	0x00C008: true, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
	// NULL ciphers
	0x0002:   true, // TLS_RSA_WITH_NULL_SHA
	0x003B:   true, // TLS_RSA_WITH_NULL_SHA256
	0x00C010: true, // TLS_ECDHE_RSA_WITH_NULL_SHA
	0x00C006: true, // TLS_ECDHE_ECDSA_WITH_NULL_SHA
	// EXPORT ciphers
	0x0003: true, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
	0x0006: true, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
	0x0008: true, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
	// DES
	0x0009: true, // TLS_RSA_WITH_DES_CBC_SHA
}

// isWeakCipherSuite checks if a cipher suite ID is considered weak.
func isWeakCipherSuite(id uint16) bool {
	if weakCipherIDs[id] {
		return true
	}
	name := tls.CipherSuiteName(id)
	if len(name) == 0 {
		return false
	}
	weakKeywords := []string{"EXPORT", "NULL", "RC4", "DES40"}
	for _, kw := range weakKeywords {
		for i := 0; i+len(kw) <= len(name); i++ {
			if name[i:i+len(kw)] == kw {
				return true
			}
		}
	}
	return false
}

// getCipherSuitesForVersion returns cipher suites to test for a TLS version.
func getCipherSuitesForVersion(version uint16) []uint16 {
	if version == tls.VersionTLS13 {
		return []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		}
	}
	// Common TLS 1.2 and below cipher suites (both secure and weak for comparison)
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		// Weak ciphers (using IANA IDs)
		0x0005,   // TLS_RSA_WITH_RC4_128_SHA
		0x00C011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
		0x0002,   // TLS_RSA_WITH_NULL_SHA
		0x00C010, // TLS_ECDHE_RSA_WITH_NULL_SHA
	}
}

// CipherSuiteScan scans a target for supported cipher suites.
func CipherSuiteScan(target string, tlsVersion uint16) (*CipherScanResult, error) {
	if tlsVersion == 0 {
		tlsVersion = tls.VersionTLS12
	}

	host, port := parseHostPort(target)
	addr := net.JoinHostPort(host, port)

	ciphers := getCipherSuitesForVersion(tlsVersion)
	versionName := getTLSVersionName(tlsVersion)

	result := &CipherScanResult{
		Target:     target,
		TLSVersion: versionName,
	}

	for _, cipherID := range ciphers {
		cipherResult := CipherSuiteResult{
			CipherSuite: tls.CipherSuiteName(cipherID),
			ID:          cipherID,
			Secure:      !isWeakCipherSuite(cipherID),
		}

		supported, err := probeCipherSuite(addr, tlsVersion, cipherID)
		if err != nil {
			cipherResult.Supported = false
			cipherResult.Error = "not supported"
		} else {
			cipherResult.Supported = supported
		}

		result.CipherSuites = append(result.CipherSuites, cipherResult)
	}

	// Build summary
	summary := CipherScanSummary{
		TotalTested: len(result.CipherSuites),
	}

	var secureSuites, weakSuites []string
	for _, cs := range result.CipherSuites {
		if cs.Supported {
			summary.SupportedCount++
			if cs.Secure {
				summary.SecureCount++
				secureSuites = append(secureSuites, cs.CipherSuite)
			} else {
				summary.WeakCount++
				weakSuites = append(weakSuites, cs.CipherSuite)
			}
		}
	}

	sort.Strings(secureSuites)
	sort.Strings(weakSuites)
	summary.SecureSuites = secureSuites
	summary.WeakSuites = weakSuites
	summary.IsSecure = summary.WeakCount == 0 && summary.SupportedCount > 0

	result.Summary = summary

	return result, nil
}

// probeCipherSuite attempts a TLS connection with a specific cipher suite.
func probeCipherSuite(addr string, tlsVersion uint16, cipherID uint16) (bool, error) {
	config := &tls.Config{
		MinVersion:         tlsVersion,
		MaxVersion:         tlsVersion,
		CipherSuites:       []uint16{cipherID},
		InsecureSkipVerify: true,
	}

	// Extract host and port from addr for TLSDialRaw
	host, port, _ := net.SplitHostPort(addr)
	target := host
	if port != "443" {
		target = fmt.Sprintf("%s:%s", host, port)
	}

	conn, err := TLSDialRaw(target, config, 5*time.Second)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}
