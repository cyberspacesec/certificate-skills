package pkg

import (
	"crypto/tls"
	"crypto/x509"
)

// OfflineAnalysisResult contains the results of offline certificate analysis
// when working with an already-parsed *x509.Certificate rather than a live connection.
type OfflineAnalysisResult struct {
	Target           string
	Cert             *x509.Certificate
	ConnectionState  *tls.ConnectionState
	IntermediatePool *x509.CertPool
}

// NewOfflineAnalysis creates an OfflineAnalysisResult from a parsed certificate.
// Optional: provide intermediate certificates for chain verification.
func NewOfflineAnalysis(cert *x509.Certificate, intermediates ...*x509.Certificate) *OfflineAnalysisResult {
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	return &OfflineAnalysisResult{
		Target:           cert.Subject.CommonName,
		Cert:             cert,
		IntermediatePool: pool,
	}
}

// AnalyzeSecurityFromCert performs security analysis on an already-parsed
// *x509.Certificate without requiring a network connection.
// This is the offline variant of AnalyzeSecurity().
func AnalyzeSecurityFromCert(cert *x509.Certificate, host string) (*SecurityAnalysis, error) {
	return AnalyzeSecurityFromCertWithState(cert, host, nil)
}

// AnalyzeSecurityFromCertWithState performs security analysis using an
// already-parsed certificate and optional TLS connection state.
func AnalyzeSecurityFromCertWithState(cert *x509.Certificate, host string, state *tls.ConnectionState) (*SecurityAnalysis, error) {
	// For offline analysis, we build a partial result from the cert
	// The full AnalyzeSecurity requires a live connection for TLS details
	// This provides the certificate-level analysis only
	result := &SecurityAnalysis{
		Target: host,
	}

	// Run cert security checks offline
	certResult, err := ScanCertSecurityFromChain(cert, host, state)
	if err != nil {
		return nil, err
	}

	// Map cert check results to security issues
	for _, check := range certResult.Checks {
		if !check.Passed {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:    check.Severity,
				Type:        check.Code,
				Description: check.Name,
				Impact:      check.Detail,
			})
		}
	}

	// Calculate score: start from 100, deduct per issue
	score := 100
	for _, issue := range result.Issues {
		switch issue.Severity {
		case "Critical":
			score -= 25
		case "High":
			score -= 15
		case "Medium":
			score -= 5
		case "Low":
			score -= 2
		}
	}
	if score < 0 {
		score = 0
	}
	result.OverallScore = score

	// Determine security level
	switch {
	case score >= 80:
		result.SecurityLevel = "Good"
	case score >= 60:
		result.SecurityLevel = "Medium"
	case score >= 40:
		result.SecurityLevel = "High"
	default:
		result.SecurityLevel = "Critical"
	}

	return result, nil
}

// CheckDistrustedCAFromCert checks for distrusted CAs in a certificate chain
// without requiring a network connection.
func CheckDistrustedCAFromCert(chain []*x509.Certificate) *DistrustedCAResult {
	result := &DistrustedCAResult{
		ChainPosition: make(map[string]string),
	}

	for i, cert := range chain {
		fp := fingerprintCert(cert)
		result.ChainPosition[fp] = cert.Subject.String()

		matched := matchDistrustedCA(cert)
		if matched != nil {
			matched.ChainPosition = i
			matched.Fingerprint = fp
			result.DistrustedCAs = append(result.DistrustedCAs, *matched)
		}
	}

	result.IsDistrusted = len(result.DistrustedCAs) > 0
	return result
}

// CheckKeyUsageFromCert validates key usage compliance on an already-parsed
// certificate without requiring a network connection.
func CheckKeyUsageFromCert(cert *x509.Certificate) *KeyUsageComplianceResult {
	result := &KeyUsageComplianceResult{
		IsCompliant: true,
		IsCA:        cert.IsCA,
		KeyUsage:    keyUsageToStrings(cert),
		ExtKeyUsage: extKeyUsageToStrings(cert),
	}

	// Rule 1: CA must have keyCertSign
	if cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		result.IsCompliant = false
		result.Issues = append(result.Issues, KeyUsageIssue{
			Severity:    "High",
			Description: "CA certificate missing keyCertSign key usage",
			Rule:        "RFC 5280: CA certificates MUST have keyCertSign",
		})
	}

	// Rule 2: Non-CA should NOT have keyCertSign
	if !cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		result.IsCompliant = false
		result.Issues = append(result.Issues, KeyUsageIssue{
			Severity:    "High",
			Description: "Non-CA certificate has keyCertSign key usage",
			Rule:        "RFC 5280: Only CA certificates should have keyCertSign",
		})
	}

	// Rule 3: TLS leaf must have digitalSignature or keyEncipherment
	if !cert.IsCA {
		hasDS := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
		hasKE := cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0
		if !hasDS && !hasKE {
			result.IsCompliant = false
			result.Issues = append(result.Issues, KeyUsageIssue{
				Severity:    "High",
				Description: "TLS certificate missing digitalSignature and keyEncipherment",
				Rule:        "CA/B BR: TLS certificates MUST have digitalSignature or keyEncipherment",
			})
		}
	}

	// Rule 4: No key usage at all
	if cert.KeyUsage == 0 && len(cert.ExtKeyUsage) == 0 {
		result.IsCompliant = false
		result.Issues = append(result.Issues, KeyUsageIssue{
			Severity:    "High",
			Description: "Certificate has no key usage or extended key usage",
			Rule:        "RFC 5280: Certificates SHOULD have Key Usage extension",
		})
	}

	return result
}

// CheckPolicyFromCert analyzes certificate policy OIDs without network access.
func CheckPolicyFromCert(cert *x509.Certificate) *PolicyAnalysisResult {
	result := &PolicyAnalysisResult{
		IsCompliant: true,
	}

	for _, oid := range cert.PolicyIdentifiers {
		oidStr := oid.String()
		if known, ok := knownPolicyOIDs[oidStr]; ok {
			result.PolicyOIDs = append(result.PolicyOIDs, known)
		} else {
			result.PolicyOIDs = append(result.PolicyOIDs, PolicyOID{
				OID:         oidStr,
				Description: "Unknown policy OID",
				Type:        "Unknown",
			})
		}
	}

	result.HasPolicies = len(result.PolicyOIDs) > 0
	result.ValidationType = determineValidationType(result.PolicyOIDs)

	return result
}

// CheckNameConstraintsFromCert checks name constraints on a certificate chain
// without requiring a network connection.
func CheckNameConstraintsFromCert(chain []*x509.Certificate) *NameConstraintsResult {
	result := &NameConstraintsResult{
		IsCompliant: true,
	}

	if len(chain) < 2 {
		result.Detail = "No CA certificates in chain to check constraints"
		return result
	}

	leafNames := collectLeafNames(chain[0])

	for i := 1; i < len(chain); i++ {
		ca := chain[i]
		if !ca.IsCA {
			continue
		}

		constraint := extractCAConstraint(ca, i)
		if constraint == nil {
			continue
		}

		constraint.IsConstraining = len(constraint.PermittedDNS) > 0 ||
			len(constraint.ExcludedDNS) > 0 ||
			len(constraint.PermittedIPs) > 0 ||
			len(constraint.ExcludedIPs) > 0 ||
			len(constraint.PermittedEmails) > 0 ||
			len(constraint.ExcludedEmails) > 0

		if !constraint.IsConstraining {
			continue
		}

		result.HasConstraints = true
		result.ConstraintedCAs = append(result.ConstraintedCAs, *constraint)

		for _, name := range leafNames {
			if violatesExcluded(name, constraint) {
				result.IsCompliant = false
				result.Violations = append(result.Violations, ConstraintViolation{
					CASubject:     ca.Subject.String(),
					ViolatedName:  name,
					ViolationType: "excluded",
					Constraint:    formatConstraint(constraint),
				})
			}
			if violatesNotPermitted(name, constraint) {
				result.IsCompliant = false
				result.Violations = append(result.Violations, ConstraintViolation{
					CASubject:     ca.Subject.String(),
					ViolatedName:  name,
					ViolationType: "not_permitted",
					Constraint:    formatConstraint(constraint),
				})
			}
		}
	}

	return result
}

// ScanCertSecurityFromChain performs certificate security checks on an
// already-parsed certificate chain without requiring a network connection.
func ScanCertSecurityFromChain(cert *x509.Certificate, host string, state *tls.ConnectionState) (*CertSecurityResult, error) {
	result := &CertSecurityResult{
		Target: host,
	}

	type certCheck struct {
		name     string
		code     string
		severity string
		desc     string
		check    func(cert *x509.Certificate, host string, state *tls.ConnectionState) (bool, string)
	}

	checks := []certCheck{
		{name: "Weak Signature Algorithm", code: "CERT-001", severity: "High", desc: "Certificate uses a weak signature algorithm", check: checkWeakSignature},
		{name: "Short RSA Key", code: "CERT-002", severity: "High", desc: "Certificate uses an RSA key shorter than 2048 bits", check: checkShortRSAKey},
		{name: "Weak ECDSA Curve", code: "CERT-003", severity: "Medium", desc: "Certificate uses a weak elliptic curve", check: checkWeakCurve},
		{name: "Missing SAN", code: "CERT-004", severity: "High", desc: "Certificate has no Subject Alternative Names", check: checkMissingSAN},
		{name: "Hostname Mismatch", code: "CERT-005", severity: "Critical", desc: "Certificate does not match hostname", check: checkHostnameMismatch},
		{name: "Excessive Validity Period", code: "CERT-006", severity: "Medium", desc: "Certificate validity exceeds 398 days", check: checkExcessiveValidity},
		{name: "Self-Signed Certificate", code: "CERT-007", severity: "Medium", desc: "Certificate is self-signed", check: checkSelfSigned},
		{name: "Certificate Expired", code: "CERT-008", severity: "Critical", desc: "Certificate has expired", check: checkCertExpired},
		{name: "Certificate Expiring Soon", code: "CERT-009", severity: "High", desc: "Certificate expires within 30 days", check: checkCertExpiringSoon},
		{name: "CN Not in SANs", code: "CERT-010", severity: "Low", desc: "Common Name is not in Subject Alternative Names", check: checkCNNotInSANs},
		{name: "Wildcard Certificate", code: "CERT-011", severity: "Low", desc: "Certificate uses wildcard patterns", check: checkWildcardCert},
		{name: "Internal Name Certificate", code: "CERT-012", severity: "High", desc: "Certificate uses an internal name", check: checkInternalName},
	}

	// Add checks that need ConnectionState
	if state != nil {
		checks = append(checks, []certCheck{
			{name: "Untrusted Chain", code: "CERT-013", severity: "High", desc: "Certificate chain does not validate", check: checkUntrustedChain},
			{name: "Distrusted CA", code: "CERT-014", severity: "Critical", desc: "Chain contains distrusted CA", check: checkDistrustedCA},
			{name: "OCSP Must-Staple Violation", code: "CERT-015", severity: "High", desc: "Must-Staple without staple", check: checkOCSPMustStaple},
			{name: "Key Usage Non-Compliance", code: "CERT-016", severity: "High", desc: "Key usage violates RFC 5280", check: checkKeyUsageCompliance},
			{name: "Low Serial Entropy", code: "CERT-017", severity: "Medium", desc: "Low serial number entropy", check: checkSerialEntropy},
			{name: "Name Constraint Violation", code: "CERT-018", severity: "High", desc: "Name constraint violation", check: checkNameConstraints},
		}...)
	}

	for _, c := range checks {
		passed, detail := c.check(cert, host, state)
		result.Checks = append(result.Checks, CertSecurityCheck{
			Name:        c.name,
			Code:        c.code,
			Severity:    c.severity,
			Passed:      passed,
			Description: c.desc,
			Detail:      detail,
		})
	}

	result.Summary = buildCertSecuritySummary(result.Checks)
	return result, nil
}

// fingerprintCert generates a hex SHA-256 fingerprint for a certificate.
func fingerprintCert(cert *x509.Certificate) string {
	fps := GenerateFingerprints(cert)
	if fp, ok := fps["sha256"]; ok {
		return fp
	}
	return ""
}
