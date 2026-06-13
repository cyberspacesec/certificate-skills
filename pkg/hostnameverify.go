package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// HostnameVerifyResult represents the result of a hostname verification check.
type HostnameVerifyResult struct {
	Target       string         `json:"target"`
	Hostname     string         `json:"hostname"`
	IsValid      bool           `json:"is_valid"`
	MatchType    string         `json:"match_type"`     // exact, wildcard, none
	MatchedSAN   string         `json:"matched_san,omitempty"`
	AllSANs      []string       `json:"all_sans"`
	CommonName   string         `json:"common_name"`
	MismatchInfo string         `json:"mismatch_info,omitempty"`
	Warnings     []string       `json:"warnings,omitempty"`
	Error        string         `json:"error,omitempty"`
}

// VerifyHostname checks whether the certificate presented by a server
// is valid for the target hostname. This is critical for cyberspace mapping
// to identify misconfigured or potentially malicious certificates.
func VerifyHostname(target string) (*HostnameVerifyResult, error) {
	result := &HostnameVerifyResult{
		AllSANs:  []string{},
		Warnings: []string{},
	}

	host, port := parseHostPort(target)
	result.Hostname = host
	result.Target = target

	addr := fmt.Sprintf("%s:%s", host, port)

	// First, connect with InsecureSkipVerify to get the certificate
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

	// Extract certificate details
	result.CommonName = cert.Subject.CommonName
	for _, dnsName := range cert.DNSNames {
		result.AllSANs = append(result.AllSANs, dnsName)
	}

	// Perform hostname verification using Go's built-in verification
	err = cert.VerifyHostname(host)
	result.IsValid = err == nil

	if result.IsValid {
		// Determine match type
		result.MatchType = determineMatchType(cert, host)
		result.MatchedSAN = findMatchingSAN(cert, host)
	} else {
		result.MatchType = "none"
		result.MismatchInfo = err.Error()

		// Provide detailed mismatch information
		if cert.Subject.CommonName != "" {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Common Name '%s' does not match hostname '%s'", cert.Subject.CommonName, host))
		}

		if len(cert.DNSNames) == 0 {
			result.Warnings = append(result.Warnings,
				"Certificate has no Subject Alternative Names (SANs) - hostname cannot be verified")
		} else {
			// Check if any SAN is close to the hostname
			closestMatch := findClosestMatch(cert.DNSNames, host)
			if closestMatch != "" {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("No exact match, closest SAN is '%s'", closestMatch))
			}
		}
	}

	// Additional checks
	if len(cert.DNSNames) == 0 && cert.Subject.CommonName != "" {
		// Certificate only has CN, no SANs - not RFC 6125 compliant
		result.Warnings = append(result.Warnings,
			"Certificate uses Common Name instead of SANs for hostname binding (not RFC 6125 compliant)")
	}

	// Check if CN doesn't match any SAN (potential misconfiguration)
	if cert.Subject.CommonName != "" && len(cert.DNSNames) > 0 {
		cnInSANs := false
		for _, san := range cert.DNSNames {
			if san == cert.Subject.CommonName {
				cnInSANs = true
				break
			}
		}
		if !cnInSANs {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Common Name '%s' is not included in SANs - some clients may reject this", cert.Subject.CommonName))
		}
	}

	return result, nil
}

// determineMatchType determines how a hostname matched a certificate.
func determineMatchType(cert *x509.Certificate, hostname string) string {
	// Check exact match first
	for _, san := range cert.DNSNames {
		if san == hostname {
			return "exact"
		}
	}

	// Check CN exact match
	if cert.Subject.CommonName == hostname {
		return "exact"
	}

	// Check wildcard match
	for _, san := range cert.DNSNames {
		if matchWildcard(san, hostname) {
			return "wildcard"
		}
	}

	// Check CN wildcard match
	if matchWildcard(cert.Subject.CommonName, hostname) {
		return "wildcard"
	}

	return "none"
}

// findMatchingSAN finds the SAN that matches the hostname.
func findMatchingSAN(cert *x509.Certificate, hostname string) string {
	// Exact match in SANs
	for _, san := range cert.DNSNames {
		if san == hostname {
			return san
		}
	}

	// Wildcard match in SANs
	for _, san := range cert.DNSNames {
		if matchWildcard(san, hostname) {
			return san
		}
	}

	// CN match
	if cert.Subject.CommonName == hostname || matchWildcard(cert.Subject.CommonName, hostname) {
		return cert.Subject.CommonName
	}

	return ""
}

// matchWildcard checks if a wildcard pattern matches a hostname.
func matchWildcard(pattern, hostname string) bool {
	if len(pattern) == 0 || len(hostname) == 0 {
		return false
	}

	if pattern[0] != '*' {
		return pattern == hostname
	}

	// Wildcard: *.example.com matches sub.example.com but NOT example.com
	// and NOT deep.sub.example.com (per RFC 6125, wildcard matches exactly one label)
	if len(pattern) < 2 {
		return false
	}

	suffix := pattern[1:] // ".example.com"

	// The hostname must end with the suffix
	if !strings.HasSuffix(hostname, suffix) {
		return false
	}

	// The hostname must have exactly one label before the suffix
	// e.g., www.example.com matches *.example.com (one label: www)
	// but deep.sub.example.com does NOT (two labels: deep.sub)
	prefix := strings.TrimSuffix(hostname, suffix) // "www" or "deep.sub"
	if strings.Contains(prefix, ".") {
		// More than one label before the suffix - not a valid wildcard match
		return false
	}
	if prefix == "" {
		// No label before the suffix (hostname == "example.com")
		return false
	}

	return true
}

// findClosestMatch finds the SAN that is closest to the given hostname.
func findClosestMatch(sans []string, hostname string) string {
	var bestMatch string
	bestScore := -1

	for _, san := range sans {
		score := domainSimilarity(san, hostname)
		if score > bestScore {
			bestScore = score
			bestMatch = san
		}
	}

	return bestMatch
}

// domainSimilarity calculates a simple similarity score between two domain names.
func domainSimilarity(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	score := 0
	minLen := len(partsA)
	if len(partsB) < minLen {
		minLen = len(partsB)
	}

	// Count matching domain parts from the right (TLD first)
	for i := 1; i <= minLen; i++ {
		idxA := len(partsA) - i
		idxB := len(partsB) - i
		if idxA >= 0 && idxB >= 0 && partsA[idxA] == partsB[idxB] {
			score++
		} else {
			break
		}
	}

	return score
}
