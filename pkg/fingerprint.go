package pkg

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// GenerateFingerprints 生成证书指纹
func GenerateFingerprints(cert *x509.Certificate) map[string]string {
	fingerprints := make(map[string]string)

	// MD5 指纹
	md5Hash := md5.Sum(cert.Raw)
	fingerprints["md5"] = formatFingerprint(md5Hash[:])

	// SHA-1 指纹
	sha1Hash := sha1.Sum(cert.Raw)
	fingerprints["sha1"] = formatFingerprint(sha1Hash[:])

	// SHA-256 指纹
	sha256Hash := sha256.Sum256(cert.Raw)
	fingerprints["sha256"] = formatFingerprint(sha256Hash[:])

	// 公钥指纹 (用于 SSL Pinning)
	if cert.PublicKey != nil {
		pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err == nil {
			pubKeySha256 := sha256.Sum256(pubKeyDER)
			fingerprints["public_key_sha256"] = formatFingerprint(pubKeySha256[:])
		}
	}

	return fingerprints
}

// formatFingerprint 格式化指纹为标准格式 (用冒号分隔)
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

// GenerateFingerprintFromBytes 从证书字节数据生成指纹
func GenerateFingerprintFromBytes(certData []byte) map[string]string {
	fingerprints := make(map[string]string)

	// MD5 指纹
	md5Hash := md5.Sum(certData)
	fingerprints["md5"] = formatFingerprint(md5Hash[:])

	// SHA-1 指纹
	sha1Hash := sha1.Sum(certData)
	fingerprints["sha1"] = formatFingerprint(sha1Hash[:])

	// SHA-256 指纹
	sha256Hash := sha256.Sum256(certData)
	fingerprints["sha256"] = formatFingerprint(sha256Hash[:])

	return fingerprints
}

// CompareCertFingerprints 比较两个证书的指纹
func CompareCertFingerprints(cert1, cert2 *x509.Certificate) bool {
	fp1 := GenerateFingerprints(cert1)
	fp2 := GenerateFingerprints(cert2)

	// 比较 SHA-256 指纹
	return fp1["sha256"] == fp2["sha256"]
}

// ValidateFingerprint 验证指纹格式是否正确
func ValidateFingerprint(fingerprint string, hashType string) bool {
	// 移除所有冒号和空格
	cleaned := ""
	for _, char := range fingerprint {
		if char != ':' && char != ' ' {
			cleaned += string(char)
		}
	}

	// 检查长度和字符
	expectedLengths := map[string]int{
		"md5":    32, // 16 bytes * 2 hex chars
		"sha1":   40, // 20 bytes * 2 hex chars
		"sha256": 64, // 32 bytes * 2 hex chars
	}

	expectedLength, exists := expectedLengths[hashType]
	if !exists || len(cleaned) != expectedLength {
		return false
	}

	// 检查是否为有效的十六进制字符
	for _, char := range cleaned {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}

	return true
}
