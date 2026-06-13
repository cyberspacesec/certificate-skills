package pkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CTSearchResult represents the result of a Certificate Transparency log search.
type CTSearchResult struct {
	Target       string   `json:"target"`
	TotalCount   int      `json:"total_count"`
	Certificates []CTCert `json:"certificates"`
	Error        string   `json:"error,omitempty"`
}

// CTCert represents a certificate found in CT logs.
type CTCert struct {
	Issuer            string `json:"issuer"`
	CommonName        string `json:"common_name"`
	NameValue         string `json:"name_value"` // All SANs (newline-separated from crt.sh)
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	SerialNumber      string `json:"serial_number,omitempty"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	IssuerCAID        int    `json:"issuer_ca_id,omitempty"`
	IssuerName        string `json:"issuer_name,omitempty"`
}

// crtshEntry represents a single entry from the crt.sh API response.
type crtshEntry struct {
	IssuerCAID        int    `json:"issuer_ca_id"`
	IssuerName        string `json:"issuer_name"`
	CommonName        string `json:"common_name"`
	NameValue         string `json:"name_value"`
	SerialNumber      string `json:"serial_number,omitempty"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	FingerprintSHA256 string `json:"sha256,omitempty"`
}

// CTSearch searches Certificate Transparency logs for certificates
// associated with the given domain using the crt.sh API.
//
// This is a crucial capability for cyberspace mapping:
// - Discover all subdomains and certificates for a domain
// - Find certificate issuance patterns and timelines
// - Identify unauthorized or suspicious certificates
// - Map organizational certificate infrastructure
func CTSearch(domain string) (*CTSearchResult, error) {
	result := &CTSearchResult{
		Target: domain,
	}

	// Query crt.sh API
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result, nil
	}

	req.Header.Set("User-Agent", "cert-hacker/1.0 (certificate security toolkit)")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("failed to query CT logs: %v", err)
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Sprintf("CT log API returned status %d: %s", resp.StatusCode, string(body))
		return result, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read response: %v", err)
		return result, nil
	}

	// Parse the JSON response
	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		// crt.sh sometimes returns empty or malformed responses
		if strings.TrimSpace(string(body)) == "" {
			result.TotalCount = 0
			return result, nil
		}
		result.Error = fmt.Sprintf("failed to parse CT log response: %v", err)
		return result, nil
	}

	result.TotalCount = len(entries)

	// Convert to our format and deduplicate
	seen := make(map[string]bool)
	for _, entry := range entries {
		// Deduplicate by fingerprint or common_name+issuer+not_before
		key := entry.FingerprintSHA256
		if key == "" {
			h := sha256.Sum256([]byte(entry.CommonName + entry.IssuerName + entry.NotBefore))
			key = hex.EncodeToString(h[:])
		}

		if seen[key] {
			continue
		}
		seen[key] = true

		cert := CTCert{
			CommonName:        entry.CommonName,
			NameValue:         entry.NameValue,
			NotBefore:         entry.NotBefore,
			NotAfter:          entry.NotAfter,
			SerialNumber:      entry.SerialNumber,
			FingerprintSHA256: entry.FingerprintSHA256,
			IssuerCAID:        entry.IssuerCAID,
			IssuerName:        entry.IssuerName,
		}

		// Parse the issuer name to a cleaner format
		if entry.IssuerName != "" {
			cert.Issuer = cleanIssuerName(entry.IssuerName)
		}

		result.Certificates = append(result.Certificates, cert)
	}

	return result, nil
}

// cleanIssuerName cleans up the issuer name from crt.sh format.
// crt.sh returns issuer names like: "O=Example Inc, CN=Example CA"
// We convert to a more readable format.
func cleanIssuerName(name string) string {
	// Split by comma and clean up
	parts := strings.Split(name, ",")
	var cleaned []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	return strings.Join(cleaned, ", ")
}

// CTSearchByFingerprint searches Certificate Transparency logs
// for a specific certificate by its SHA-256 fingerprint.
func CTSearchByFingerprint(fingerprint string) (*CTSearchResult, error) {
	result := &CTSearchResult{
		Target: fmt.Sprintf("fingerprint:%s", fingerprint),
	}

	// Remove colons and spaces from fingerprint
	fp := strings.NewReplacer(":", "", " ", "").Replace(fingerprint)

	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", fp)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result, nil
	}

	req.Header.Set("User-Agent", "cert-hacker/1.0 (certificate security toolkit)")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("failed to query CT logs: %v", err)
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Sprintf("CT log API returned status %d: %s", resp.StatusCode, string(body))
		return result, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read response: %v", err)
		return result, nil
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		if strings.TrimSpace(string(body)) == "" {
			result.TotalCount = 0
			return result, nil
		}
		result.Error = fmt.Sprintf("failed to parse CT log response: %v", err)
		return result, nil
	}

	result.TotalCount = len(entries)

	for _, entry := range entries {
		cert := CTCert{
			CommonName:        entry.CommonName,
			NameValue:         entry.NameValue,
			NotBefore:         entry.NotBefore,
			NotAfter:          entry.NotAfter,
			SerialNumber:      entry.SerialNumber,
			FingerprintSHA256: entry.FingerprintSHA256,
			IssuerCAID:        entry.IssuerCAID,
			IssuerName:        entry.IssuerName,
		}

		if entry.IssuerName != "" {
			cert.Issuer = cleanIssuerName(entry.IssuerName)
		}

		result.Certificates = append(result.Certificates, cert)
	}

	return result, nil
}
