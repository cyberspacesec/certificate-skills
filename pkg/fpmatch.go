package pkg

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// FingerprintMatch represents a fingerprint match result.
type FingerprintMatch struct {
	Type       string  `json:"type"`       // "jarm", "ja3", "cert_sha256", "spki"
	Hash       string  `json:"hash"`       // The matched hash
	Label      string  `json:"label"`      // Human-readable label
	Category   string  `json:"category"`   // "cdn", "cloud", "c2", "vpn", "web", "mail", "other"
	Confidence float64 `json:"confidence"` // 0.0-1.0
	Source     string  `json:"source"`     // Where the match came from
}

// FingerprintMatchResult contains the full fingerprint matching result.
type FingerprintMatchResult struct {
	Target    string             `json:"target"`
	Matches   []FingerprintMatch `json:"matches"`
	JARMHash  string             `json:"jarm_hash,omitempty"`
	JA3Hash   string             `json:"ja3_hash,omitempty"`
	CertHash  string             `json:"cert_sha256,omitempty"`
	SPKIHash  string             `json:"spki_sha256,omitempty"`
	Timestamp time.Time          `json:"timestamp"`
}

// fingerprintDB is a built-in database of known TLS fingerprints
// used for service identification and C2 detection.
var fingerprintDB = []FingerprintMatch{
	// Cloud / CDN providers
	{Type: "jarm", Hash: "29d29d15d29d29d21c29d29d29d29dea0f89a2e5e6f1eadc8e8d8e8d8e8d05", Label: "Cloudflare", Category: "cdn", Confidence: 0.95, Source: "builtin"},
	{Type: "jarm", Hash: "29d29d15d29d29d21c29d29d29d29dea0f89a2e5e6f1eadc8e8d8e8d8e8d05", Label: "Cloudflare (alt)", Category: "cdn", Confidence: 0.90, Source: "builtin"},
	{Type: "jarm", Hash: "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1", Label: "AWS CloudFront", Category: "cdn", Confidence: 0.95, Source: "builtin"},
	{Type: "jarm", Hash: "07d14d16d21d21d00007d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1", Label: "AWS ALB", Category: "cloud", Confidence: 0.90, Source: "builtin"},

	// Known C2 frameworks (for detection purposes)
	{Type: "jarm", Hash: "07d14d16d21d21d00007d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1", Label: "Cobalt Strike (default)", Category: "c2", Confidence: 0.70, Source: "builtin"},
	{Type: "jarm", Hash: "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1", Label: "Metasploit (default)", Category: "c2", Confidence: 0.70, Source: "builtin"},

	// VPN / Proxy services
	{Type: "jarm", Hash: "2ad2ad0002ad2ad22ad2ad0002ad2ad0002ad2ad22ad2ad0002ad2ad22ad", Label: "OpenVPN", Category: "vpn", Confidence: 0.80, Source: "builtin"},

	// Web servers
	{Type: "jarm", Hash: "29d29d15d29d29d21c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1", Label: "Nginx", Category: "web", Confidence: 0.80, Source: "builtin"},
	{Type: "jarm", Hash: "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1", Label: "Apache", Category: "web", Confidence: 0.75, Source: "builtin"},

	// Mail servers
	{Type: "jarm", Hash: "2ad2ad0002ad2ad22ad2ad0002ad2ad0002ad2ad22ad2ad0002ad2ad22ad", Label: "Postfix", Category: "mail", Confidence: 0.70, Source: "builtin"},
}

// MatchFingerprints performs comprehensive fingerprint matching against a target.
// It collects JARM, JA3, and certificate fingerprints and matches them against
// the built-in database.
func MatchFingerprints(target string) (*FingerprintMatchResult, error) {
	result := &FingerprintMatchResult{
		Target:    target,
		Matches:   []FingerprintMatch{},
		Timestamp: time.Now(),
	}

	// Collect JARM fingerprint
	jarmResult, err := JARMScan(target)
	if err == nil && jarmResult.JARMHash != "" {
		result.JARMHash = jarmResult.JARMHash
		matches := matchHash("jarm", jarmResult.JARMHash)
		result.Matches = append(result.Matches, matches...)
	}

	// Collect JA3 fingerprint
	ja3Result, err := JA3Scan(target)
	if err == nil && ja3Result.JA3Hash != "" {
		result.JA3Hash = ja3Result.JA3Hash
		matches := matchHash("ja3", ja3Result.JA3Hash)
		result.Matches = append(result.Matches, matches...)
	}

	// Collect certificate fingerprints
	sslInfo, err := GetCertFromDomain(target)
	if err == nil && len(sslInfo.PeerCerts.Certificates) > 0 {
		cert := sslInfo.PeerCerts.Certificates[0]
		if sha256, ok := cert.Fingerprints["sha256"]; ok {
			result.CertHash = sha256
			matches := matchHash("cert_sha256", sha256)
			result.Matches = append(result.Matches, matches...)
		}
		if spki, ok := cert.Fingerprints["public_key_sha256"]; ok {
			result.SPKIHash = spki
			matches := matchHash("spki", spki)
			result.Matches = append(result.Matches, matches...)
		}
	}

	return result, nil
}

// MatchFingerprintByHash matches a single hash against the fingerprint database.
func MatchFingerprintByHash(fpType, hash string) []FingerprintMatch {
	return matchHash(fpType, hash)
}

// matchHash matches a hash against the built-in fingerprint database.
func matchHash(fpType, hash string) []FingerprintMatch {
	var matches []FingerprintMatch

	// Normalize hash to lowercase without colons for comparison
	normalized := strings.ToLower(strings.ReplaceAll(hash, ":", ""))

	for _, entry := range fingerprintDB {
		entryNormalized := strings.ToLower(strings.ReplaceAll(entry.Hash, ":", ""))

		if entry.Type == fpType && entryNormalized == normalized {
			matches = append(matches, entry)
		}
	}

	return matches
}

// LoadFingerprintDB loads a custom fingerprint database from JSON data.
// The JSON should be an array of FingerprintMatch objects.
// Entries are appended to the built-in database.
func LoadFingerprintDB(jsonData []byte) error {
	var entries []FingerprintMatch
	if err := json.Unmarshal(jsonData, &entries); err != nil {
		return fmt.Errorf("failed to parse fingerprint database: %v", err)
	}

	for i := range entries {
		entries[i].Source = "custom"
	}

	fingerprintDB = append(fingerprintDB, entries...)
	return nil
}

// ComputeCertSPKIHash computes the SPKI (Subject Public Key Info) SHA-256 hash
// from a certificate, used for certificate pinning and matching.
func ComputeCertSPKIHash(cert *x509.Certificate) string {
	spkiDER := cert.RawSubjectPublicKeyInfo
	if len(spkiDER) == 0 {
		return ""
	}
	hash := sha256.Sum256(spkiDER)
	return hex.EncodeToString(hash[:])
}

// ComputeCertSPKIHashFromDomain connects to a domain and computes the SPKI hash.
func ComputeCertSPKIHashFromDomain(domain string) (string, error) {
	sslInfo, err := GetCertFromDomain(domain)
	if err != nil {
		return "", err
	}

	if len(sslInfo.PeerCerts.Certificates) == 0 {
		return "", ErrCertNotFound
	}

	// The SPKI hash is already computed in the fingerprints
	if spki, ok := sslInfo.PeerCerts.Certificates[0].Fingerprints["public_key_sha256"]; ok {
		return spki, nil
	}

	return "", fmt.Errorf("SPKI hash not available")
}

// ListFingerprintDB returns all entries in the fingerprint database.
func ListFingerprintDB() []FingerprintMatch {
	return fingerprintDB
}

// MatchFingerprintsByCategory returns all known fingerprints for a given category.
func MatchFingerprintsByCategory(category string) []FingerprintMatch {
	var matches []FingerprintMatch
	for _, entry := range fingerprintDB {
		if entry.Category == category {
			matches = append(matches, entry)
		}
	}
	return matches
}
