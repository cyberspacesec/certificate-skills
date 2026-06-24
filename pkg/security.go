package pkg

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SecurityAnalysis is the security analysis result.
type SecurityAnalysis struct {
	Target           string           `json:"target"`
	OverallScore     int              `json:"overall_score"`     // Overall security score (0-100)
	SecurityLevel    string           `json:"security_level"`    // Security level: Critical, High, Medium, Low, Good
	Issues           []SecurityIssue  `json:"issues"`            // Discovered security issues
	Recommendations  []string         `json:"recommendations"`   // Security recommendations
	CertificateCheck CertificateCheck `json:"certificate_check"` // Certificate check result
	TLSCheck         TLSCheck         `json:"tls_check"`         // TLS check result
	ExpirationCheck  ExpirationCheck  `json:"expiration_check"`  // Expiration check
}

// SecurityIssue represents a security issue.
type SecurityIssue struct {
	Severity    string `json:"severity"`    // Critical, High, Medium, Low
	Type        string `json:"type"`        // Issue type
	Description string `json:"description"` // Issue description
	Impact      string `json:"impact"`      // Impact description
}

// CertificateCheck is the certificate check result.
type CertificateCheck struct {
	IsValid         bool     `json:"is_valid"`
	IsSelfSigned    bool     `json:"is_self_signed"`
	IsExpired       bool     `json:"is_expired"`
	IsExpiringSoon  bool     `json:"is_expiring_soon"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	KeySize         int      `json:"key_size"`
	SignatureAlg    string   `json:"signature_algorithm"`
	WeakSignature   bool     `json:"weak_signature"`
	HasSAN          bool     `json:"has_san"`
	SANCount        int      `json:"san_count"`
	WildcardCert    bool     `json:"wildcard_cert"`
	WeakKeySize     bool     `json:"weak_key_size"`
	ShortValidity   bool     `json:"short_validity"`
	ChainValid      bool     `json:"chain_valid"`
	Warnings        []string `json:"warnings"`
}

// TLSCheck is the TLS connection check result.
type TLSCheck struct {
	Version             string      `json:"version"`
	CipherSuite         string      `json:"cipher_suite"`
	IsSecureVersion     bool        `json:"is_secure_version"`
	IsSecureCipherSuite bool        `json:"is_secure_cipher_suite"`
	SupportsHTTP2       bool        `json:"supports_http2"`
	HasOCSPStaple       bool        `json:"has_ocsp_staple"`
	HSTS                *HSTSResult `json:"hsts,omitempty"`
	Warnings            []string    `json:"warnings"`
}

// ExpirationCheck is the expiration check.
type ExpirationCheck struct {
	DaysUntilExpiry int    `json:"days_until_expiry"`
	ExpirationDate  string `json:"expiration_date"`
	Status          string `json:"status"` // Expired, Critical, Warning, Good
	Message         string `json:"message"`
}

// BatchSecurityAnalysis is the batch security analysis.
type BatchSecurityAnalysis struct {
	Results    []SecurityAnalysis `json:"results"`
	TotalCount int                `json:"total_count"`
	Summary    BatchSummary       `json:"summary"`
}

// BatchSummary is the batch analysis summary.
type BatchSummary struct {
	GoodCount     int `json:"good_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
	CriticalCount int `json:"critical_count"`
	AverageScore  int `json:"average_score"`
}

// AnalyzeSecurityWithContext performs security analysis with context support.
func AnalyzeSecurityWithContext(ctx context.Context, target string) (*SecurityAnalysis, error) {
	analysis := &SecurityAnalysis{
		Target:          target,
		Issues:          []SecurityIssue{},
		Recommendations: []string{},
	}

	// Get SSL info
	sslInfo, err := GetCertFromDomainWithContext(ctx, target)
	if err != nil {
		return nil, err // already wrapped by GetCertFromDomainWithContext
	}

	if len(sslInfo.PeerCerts.Certificates) == 0 {
		return nil, ErrCertNotFound
	}

	cert := sslInfo.PeerCerts.Certificates[0]

	// Perform checks
	analysis.CertificateCheck = analyzeCertificate(&cert, sslInfo)
	analysis.TLSCheck = analyzeTLS(sslInfo)
	analysis.ExpirationCheck = analyzeExpiration(&cert)

	// Check HSTS (non-blocking, optional enhancement)
	hstsResult := CheckHSTS(target)
	analysis.TLSCheck.HSTS = hstsResult

	// Collect security issues
	analysis.collectSecurityIssues()

	// Calculate overall score
	analysis.calculateOverallScore()

	// Generate security recommendations
	analysis.generateRecommendations()

	return analysis, nil
}

// AnalyzeSecurity performs security analysis.
func AnalyzeSecurity(target string) (*SecurityAnalysis, error) {
	return AnalyzeSecurityWithContext(context.Background(), target)
}

// analyzeCertificate analyzes certificate security.
func analyzeCertificate(cert *CertInfo, sslInfo *SSLInfo) CertificateCheck {
	check := CertificateCheck{
		IsValid:      true,
		SignatureAlg: cert.SignatureAlgorithm,
		KeySize:      cert.KeySize,
		HasSAN:       len(cert.DNSNames) > 0,
		SANCount:     len(cert.DNSNames),
		Warnings:     []string{},
		ChainValid:   sslInfo.PeerCerts.IsValid,
	}

	// Check if expired
	now := time.Now()
	check.IsExpired = now.After(cert.NotAfter)
	check.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)
	check.IsExpiringSoon = check.DaysUntilExpiry <= 30 && check.DaysUntilExpiry > 0

	// Check signature algorithm security
	weakSignatures := []string{"MD5", "SHA1"}
	for _, weak := range weakSignatures {
		if strings.Contains(strings.ToUpper(cert.SignatureAlgorithm), weak) {
			check.WeakSignature = true
			check.Warnings = append(check.Warnings, fmt.Sprintf("Weak signature algorithm: %s", cert.SignatureAlgorithm))
			break
		}
	}

	// Check if wildcard certificate
	for _, dnsName := range cert.DNSNames {
		if strings.HasPrefix(dnsName, "*.") {
			check.WildcardCert = true
			break
		}
	}

	// Check if self-signed
	if cert.Subject == cert.Issuer {
		check.IsSelfSigned = true
		check.Warnings = append(check.Warnings, "Self-signed certificate detected")
	}

	// Check weak key size (RSA < 2048 bits)
	if cert.KeySize > 0 && cert.KeySize < 2048 {
		check.WeakKeySize = true
		check.Warnings = append(check.Warnings, fmt.Sprintf("Weak key size: %d bits (minimum 2048 recommended)", cert.KeySize))
	}

	// Check certificate chain validation result
	if !sslInfo.PeerCerts.IsValid {
		check.ChainValid = false
		check.Warnings = append(check.Warnings, "Certificate chain validation failed")
	}

	// Check if certificate validity period is too long (> 398 days for public certs, per CA/Browser Forum)
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if validityDays > 398 && !check.IsSelfSigned {
		check.ShortValidity = false // It's actually long validity, but we flag it
		check.Warnings = append(check.Warnings, fmt.Sprintf("Certificate validity period is %d days (CA/Browser Forum recommends ≤ 398 days)", validityDays))
	}

	return check
}

// analyzeTLS analyzes TLS connection security.
func analyzeTLS(sslInfo *SSLInfo) TLSCheck {
	check := TLSCheck{
		Version:       sslInfo.TLSVersion,
		CipherSuite:   sslInfo.CipherSuite,
		SupportsHTTP2: sslInfo.SupportsHTTP2,
		HasOCSPStaple: sslInfo.HasOCSPStaple,
		HSTS:          nil, // Will be populated separately
		Warnings:      []string{},
	}

	// Check TLS version security
	secureVersions := []string{"TLS 1.2", "TLS 1.3"}
	check.IsSecureVersion = false
	for _, version := range secureVersions {
		if sslInfo.TLSVersion == version {
			check.IsSecureVersion = true
			break
		}
	}

	if !check.IsSecureVersion {
		check.Warnings = append(check.Warnings, fmt.Sprintf("Insecure TLS version: %s", sslInfo.TLSVersion))
	}

	// Check cipher suite security (simplified check)
	cipherSuite := strings.ToUpper(sslInfo.CipherSuite)
	check.IsSecureCipherSuite = true

	// Check weak cipher suites
	weakCiphers := []string{"RC4", "DES", "3DES", "NULL", "EXPORT"}
	for _, weak := range weakCiphers {
		if strings.Contains(cipherSuite, weak) {
			check.IsSecureCipherSuite = false
			check.Warnings = append(check.Warnings, fmt.Sprintf("Weak cipher suite: %s", sslInfo.CipherSuite))
			break
		}
	}

	return check
}

// analyzeExpiration analyzes certificate expiration status.
func analyzeExpiration(cert *CertInfo) ExpirationCheck {
	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	check := ExpirationCheck{
		DaysUntilExpiry: daysUntilExpiry,
		ExpirationDate:  cert.NotAfter.Format("2006-01-02 15:04:05 UTC"),
	}

	if daysUntilExpiry < 0 {
		check.Status = "Expired"
		check.Message = fmt.Sprintf("Certificate expired %d days ago", -daysUntilExpiry)
	} else if daysUntilExpiry <= 7 {
		check.Status = "Critical"
		check.Message = fmt.Sprintf("Certificate expires in %d days - URGENT renewal required", daysUntilExpiry)
	} else if daysUntilExpiry <= 30 {
		check.Status = "Warning"
		check.Message = fmt.Sprintf("Certificate expires in %d days - renewal recommended", daysUntilExpiry)
	} else {
		check.Status = "Good"
		check.Message = fmt.Sprintf("Certificate expires in %d days", daysUntilExpiry)
	}

	return check
}

// collectSecurityIssues collects security issues.
func (analysis *SecurityAnalysis) collectSecurityIssues() {
	// Certificate-related issues
	if analysis.CertificateCheck.IsExpired {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "Critical",
			Type:        "Certificate Expired",
			Description: "The certificate has expired",
			Impact:      "Users will see security warnings and may not be able to connect",
		})
	}

	if analysis.CertificateCheck.IsExpiringSoon {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Certificate Expiring Soon",
			Description: fmt.Sprintf("Certificate expires in %d days", analysis.CertificateCheck.DaysUntilExpiry),
			Impact:      "Certificate will expire soon, causing service disruption",
		})
	}

	if analysis.CertificateCheck.WeakSignature {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Weak Signature Algorithm",
			Description: fmt.Sprintf("Using weak signature algorithm: %s", analysis.CertificateCheck.SignatureAlg),
			Impact:      "Certificate may be vulnerable to cryptographic attacks",
		})
	}

	if analysis.CertificateCheck.IsSelfSigned {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "Medium",
			Type:        "Self-Signed Certificate",
			Description: "Certificate is self-signed",
			Impact:      "Users will see security warnings and trust may be compromised",
		})
	}

	if analysis.CertificateCheck.WeakKeySize {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Weak Key Size",
			Description: fmt.Sprintf("Certificate uses a %d-bit key (minimum 2048 bits recommended)", analysis.CertificateCheck.KeySize),
			Impact:      "Key may be vulnerable to brute-force attacks and factorization",
		})
	}

	if !analysis.CertificateCheck.ChainValid {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Certificate Chain Invalid",
			Description: "Certificate chain validation failed - unable to verify chain to a trusted root",
			Impact:      "Clients may reject the certificate or show security warnings",
		})
	}

	// TLS-related issues
	if !analysis.TLSCheck.IsSecureVersion {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Insecure TLS Version",
			Description: fmt.Sprintf("Using insecure TLS version: %s", analysis.TLSCheck.Version),
			Impact:      "Connection may be vulnerable to protocol downgrade attacks",
		})
	}

	if !analysis.TLSCheck.IsSecureCipherSuite {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Weak Cipher Suite",
			Description: fmt.Sprintf("Using weak cipher suite: %s", analysis.TLSCheck.CipherSuite),
			Impact:      "Encrypted data may be vulnerable to cryptographic attacks",
		})
	}

	if !analysis.TLSCheck.HasOCSPStaple {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "Low",
			Type:        "Missing OCSP Stapling",
			Description: "Server does not provide OCSP stapling",
			Impact:      "Clients must query OCSP responders separately, adding latency to connection setup",
		})
	}

	if analysis.TLSCheck.HSTS != nil && !analysis.TLSCheck.HSTS.Enabled {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "Medium",
			Type:        "Missing HSTS Header",
			Description: "Strict-Transport-Security header is not set",
			Impact:      "Browser may attempt HTTP connections before upgrading to HTTPS, vulnerable to SSL stripping",
		})
	}
}

// calculateOverallScore calculates the overall security score.
func (analysis *SecurityAnalysis) calculateOverallScore() {
	score := 100

	for _, issue := range analysis.Issues {
		switch issue.Severity {
		case "Critical":
			score -= 30
		case "High":
			score -= 20
		case "Medium":
			score -= 10
		case "Low":
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	}

	analysis.OverallScore = score

	// Determine security level
	if score >= 90 {
		analysis.SecurityLevel = "Good"
	} else if score >= 70 {
		analysis.SecurityLevel = "Medium"
	} else if score >= 50 {
		analysis.SecurityLevel = "Low"
	} else {
		analysis.SecurityLevel = "Critical"
	}
}

// generateRecommendations generates security recommendations.
func (analysis *SecurityAnalysis) generateRecommendations() {
	recommendations := []string{}

	if analysis.CertificateCheck.IsExpired || analysis.CertificateCheck.IsExpiringSoon {
		recommendations = append(recommendations, "Renew the certificate immediately to avoid service disruption")
	}

	if analysis.CertificateCheck.WeakSignature {
		recommendations = append(recommendations, "Upgrade to a certificate with SHA-256 or higher signature algorithm")
	}

	if analysis.CertificateCheck.IsSelfSigned {
		recommendations = append(recommendations, "Replace self-signed certificate with one from a trusted CA")
	}

	if analysis.CertificateCheck.WeakKeySize {
		recommendations = append(recommendations, "Regenerate certificate with at least 2048-bit RSA key or use ECDSA")
	}

	if !analysis.CertificateCheck.ChainValid {
		recommendations = append(recommendations, "Ensure the full certificate chain is properly configured with intermediate certificates")
	}

	if !analysis.TLSCheck.IsSecureVersion {
		recommendations = append(recommendations, "Upgrade to TLS 1.2 or TLS 1.3")
		recommendations = append(recommendations, "Disable support for older TLS versions (TLS 1.0, TLS 1.1)")
	}

	if !analysis.TLSCheck.IsSecureCipherSuite {
		recommendations = append(recommendations, "Configure secure cipher suites (AES-GCM, ChaCha20-Poly1305)")
		recommendations = append(recommendations, "Disable weak cipher suites (RC4, 3DES, NULL ciphers)")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Certificate and TLS configuration appear to be secure")
		recommendations = append(recommendations, "Continue monitoring certificate expiration dates")
		recommendations = append(recommendations, "Regularly review and update TLS configuration")
	}

	analysis.Recommendations = recommendations
}

// BatchAnalyzeSecurityWithContext performs concurrent batch analysis with context support.
// It analyzes up to 10 targets in parallel for significantly faster results.
func BatchAnalyzeSecurityWithContext(ctx context.Context, targets []string) *BatchSecurityAnalysis {
	result := &BatchSecurityAnalysis{
		Results:    make([]SecurityAnalysis, len(targets)),
		TotalCount: len(targets),
	}

	// Limit concurrency to avoid overwhelming the network
	maxConcurrency := 10
	if len(targets) < maxConcurrency {
		maxConcurrency = len(targets)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, t string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check context cancellation
			select {
			case <-ctx.Done():
				result.Results[idx] = SecurityAnalysis{
					Target:        t,
					OverallScore:  0,
					SecurityLevel: "Error",
					Issues: []SecurityIssue{{
						Severity:    "Critical",
						Type:        "Cancelled",
						Description: fmt.Sprintf("Analysis cancelled: %v", ctx.Err()),
						Impact:      "Unable to assess security posture",
					}},
				}
				return
			default:
			}

			analysis, err := AnalyzeSecurityWithContext(ctx, t)
			if err != nil {
				result.Results[idx] = SecurityAnalysis{
					Target:        t,
					OverallScore:  0,
					SecurityLevel: "Error",
					Issues: []SecurityIssue{{
						Severity:    "Critical",
						Type:        "Connection Failed",
						Description: fmt.Sprintf("Failed to analyze: %v", err),
						Impact:      "Unable to assess security posture",
					}},
				}
				return
			}

			result.Results[idx] = *analysis
		}(i, target)
	}

	wg.Wait()

	// Calculate summary from results
	totalScore := 0
	for _, a := range result.Results {
		totalScore += a.OverallScore
		switch a.SecurityLevel {
		case "Good":
			result.Summary.GoodCount++
		case "Medium":
			result.Summary.MediumCount++
		case "Low":
			result.Summary.LowCount++
		case "Critical", "Error":
			result.Summary.CriticalCount++
		}
	}

	if len(targets) > 0 {
		result.Summary.AverageScore = totalScore / len(targets)
	}

	return result
}

// BatchAnalyzeSecurity performs batch security analysis on multiple targets.
func BatchAnalyzeSecurity(targets []string) *BatchSecurityAnalysis {
	return BatchAnalyzeSecurityWithContext(context.Background(), targets)
}
