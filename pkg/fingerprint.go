package pkg

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// GenerateFingerprints generates certificate fingerprints.
func GenerateFingerprints(cert *x509.Certificate) map[string]string {
	fingerprints := make(map[string]string)

	// MD5 fingerprint
	md5Hash := md5.Sum(cert.Raw)
	fingerprints["md5"] = formatFingerprint(md5Hash[:])

	// SHA-1 fingerprint
	sha1Hash := sha1.Sum(cert.Raw)
	fingerprints["sha1"] = formatFingerprint(sha1Hash[:])

	// SHA-256 fingerprint
	sha256Hash := sha256.Sum256(cert.Raw)
	fingerprints["sha256"] = formatFingerprint(sha256Hash[:])

	// Public key fingerprint (for SSL Pinning)
	if cert.PublicKey != nil {
		pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err == nil {
			pubKeySha256 := sha256.Sum256(pubKeyDER)
			fingerprints["public_key_sha256"] = formatFingerprint(pubKeySha256[:])
		}
	}

	return fingerprints
}

// formatFingerprint formats the fingerprint in standard format (colon-separated).
func formatFingerprint(hash []byte) string {
	hexStr := hex.EncodeToString(hash)
	var formatted string

	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			formatted += ":"
		}
		formatted += hexStr[i : i+2]
	}

	return fmt.Sprintf("%s", formatted)
}

// GenerateFingerprintFromBytes generates fingerprints from certificate byte data.
func GenerateFingerprintFromBytes(certData []byte) map[string]string {
	fingerprints := make(map[string]string)

	// MD5 fingerprint
	md5Hash := md5.Sum(certData)
	fingerprints["md5"] = formatFingerprint(md5Hash[:])

	// SHA-1 fingerprint
	sha1Hash := sha1.Sum(certData)
	fingerprints["sha1"] = formatFingerprint(sha1Hash[:])

	// SHA-256 fingerprint
	sha256Hash := sha256.Sum256(certData)
	fingerprints["sha256"] = formatFingerprint(sha256Hash[:])

	return fingerprints
}

// CompareCertFingerprints compares fingerprints of two certificates.
func CompareCertFingerprints(cert1, cert2 *x509.Certificate) bool {
	fp1 := GenerateFingerprints(cert1)
	fp2 := GenerateFingerprints(cert2)

	// Compare SHA-256 fingerprints
	return fp1["sha256"] == fp2["sha256"]
}

// ValidateFingerprint validates whether a fingerprint format is correct.
func ValidateFingerprint(fingerprint string, hashType string) bool {
	// Remove all colons and spaces
	cleaned := ""
	for _, char := range fingerprint {
		if char != ':' && char != ' ' {
			cleaned += string(char)
		}
	}

	// Check length and characters
	expectedLengths := map[string]int{
		"md5":    32, // 16 bytes * 2 hex chars
		"sha1":   40, // 20 bytes * 2 hex chars
		"sha256": 64, // 32 bytes * 2 hex chars
	}

	expectedLength, exists := expectedLengths[hashType]
	if !exists || len(cleaned) != expectedLength {
		return false
	}

	// Check if valid hexadecimal characters
	for _, char := range cleaned {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}

	return true
}
