package pkg

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// TLSProtocolResult represents the result of scanning a single TLS protocol version.
type TLSProtocolResult struct {
	Version     string `json:"version"`
	VersionCode uint16 `json:"version_code"`
	Supported   bool   `json:"supported"`
	Error       string `json:"error,omitempty"`
}

// TLSProtocolScanResult represents the complete TLS protocol scan result.
type TLSProtocolScanResult struct {
	Target    string              `json:"target"`
	Protocols []TLSProtocolResult `json:"protocols"`
	Summary   TLSProtocolSummary  `json:"summary"`
}

// TLSProtocolSummary provides a summary of supported protocols.
type TLSProtocolSummary struct {
	SupportedVersions   []string `json:"supported_versions"`
	UnsupportedVersions []string `json:"unsupported_versions"`
	MinimumVersion      string   `json:"minimum_version"`
	MaximumVersion      string   `json:"maximum_version"`
	IsSecure            bool     `json:"is_secure"`
}

// tlsProtocolVersions defines all TLS protocol versions to scan.
var tlsProtocolVersions = []struct {
	Version uint16
	Name    string
	Secure  bool
}{
	{tls.VersionSSL30, "SSL 3.0", false},
	{tls.VersionTLS10, "TLS 1.0", false},
	{tls.VersionTLS11, "TLS 1.1", false},
	{tls.VersionTLS12, "TLS 1.2", true},
	{tls.VersionTLS13, "TLS 1.3", true},
}

// TLSProtocolScan scans a target for supported TLS protocol versions.
// It attempts to connect using each TLS version individually to determine
// which versions the server actually supports.
func TLSProtocolScan(target string) (*TLSProtocolScanResult, error) {
	host, port := parseHostPort(target)
	addr := net.JoinHostPort(host, port)

	result := &TLSProtocolScanResult{
		Target: target,
	}

	for _, pv := range tlsProtocolVersions {
		probe := TLSProtocolResult{
			Version:     pv.Name,
			VersionCode: pv.Version,
		}

		supported, err := probeTLSVersion(addr, pv.Version)
		if err != nil {
			probe.Supported = false
			probe.Error = err.Error()
		} else {
			probe.Supported = supported
		}

		result.Protocols = append(result.Protocols, probe)
	}

	// Build summary
	var supported, unsupported []string
	var minSecure, maxSecure string
	var minInsecure string

	for _, p := range result.Protocols {
		if p.Supported {
			supported = append(supported, p.Version)
			// Find minimum/maximum secure version
			for _, pv := range tlsProtocolVersions {
				if pv.Name == p.Version {
					if pv.Secure {
						if minSecure == "" {
							minSecure = p.Version
						}
						maxSecure = p.Version
					} else {
						if minInsecure == "" {
							minInsecure = p.Version
						}
					}
					break
				}
			}
		} else {
			unsupported = append(unsupported, p.Version)
		}
	}

	// Secure if no insecure protocols are supported
	isSecure := true
	for _, p := range result.Protocols {
		if p.Supported {
			for _, pv := range tlsProtocolVersions {
				if pv.Name == p.Version && !pv.Secure {
					isSecure = false
					break
				}
			}
		}
	}

	result.Summary = TLSProtocolSummary{
		SupportedVersions:   supported,
		UnsupportedVersions: unsupported,
		MinimumVersion:      firstNonEmpty(minInsecure, minSecure),
		MaximumVersion:      maxSecure,
		IsSecure:            isSecure,
	}

	return result, nil
}

// probeTLSVersion attempts a TLS connection with a specific protocol version.
func probeTLSVersion(addr string, version uint16) (bool, error) {
	config := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
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

// firstNonEmpty returns the first non-empty string from the given strings.
func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
