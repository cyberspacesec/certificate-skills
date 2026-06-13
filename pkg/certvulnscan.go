package pkg

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// CertSecurityResult represents the result of a certificate-specific security scan.
// Unlike the TLS vulnerability scanner (which checks protocol-level issues),
// this checks the certificate itself for security weaknesses.
type CertSecurityResult struct {
	Target  string              `json:"target"`
	Checks  []CertSecurityCheck `json:"checks"`
	Summary CertSecuritySummary `json:"summary"`
}

// CertSecurityCheck represents a single certificate security check result.
type CertSecurityCheck struct {
	Name        string `json:"name"`
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Passed      bool   `json:"passed"`
	Description string `json:"description"`
	Detail      string `json:"detail,omitempty"`
}

// CertSecuritySummary provides a summary of certificate security checks.
type CertSecuritySummary struct {
	TotalChecked int      `json:"total_checked"`
	Passed       int      `json:"passed"`
	Failed       int      `json:"failed"`
	FailedChecks []string `json:"failed_checks"`
	IsSecure     bool     `json:"is_secure"`
}

// ScanCertSecurity performs certificate-specific security checks.
// These checks focus on the certificate's properties rather than the TLS protocol.
func ScanCertSecurity(target string) (*CertSecurityResult, error) {
	host, port := parseHostPort(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	result := &CertSecurityResult{
		Target: target,
	}

	conn, err := TLSDial(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	leafCert := state.PeerCertificates[0]

	// Define all certificate-specific security checks
	type certCheck struct {
		name     string
		code     string
		severity string
		desc     string
		check    func(cert *x509.Certificate, host string, state *tls.ConnectionState) (bool, string)
	}

	checks := []certCheck{
		{
			name: "Weak Signature Algorithm", code: "CERT-001", severity: "High",
			desc:  "Certificate uses a weak signature algorithm (MD5, SHA-1) vulnerable to collision attacks",
			check: checkWeakSignature,
		},
		{
			name: "Short RSA Key", code: "CERT-002", severity: "High",
			desc:  "Certificate uses an RSA key shorter than 2048 bits",
			check: checkShortRSAKey,
		},
		{
			name: "Weak ECDSA Curve", code: "CERT-003", severity: "Medium",
			desc:  "Certificate uses a weak elliptic curve (P-224 or weaker)",
			check: checkWeakCurve,
		},
		{
			name: "Missing SAN", code: "CERT-004", severity: "High",
			desc:  "Certificate has no Subject Alternative Names (not RFC 6125 compliant)",
			check: checkMissingSAN,
		},
		{
			name: "Hostname Mismatch", code: "CERT-005", severity: "Critical",
			desc:  "Certificate's SAN/CN does not match the requested hostname",
			check: checkHostnameMismatch,
		},
		{
			name: "Excessive Validity Period", code: "CERT-006", severity: "Medium",
			desc:  "Certificate validity exceeds 398 days (CA/Browser Forum limit)",
			check: checkExcessiveValidity,
		},
		{
			name: "Self-Signed Certificate", code: "CERT-007", severity: "Medium",
			desc:  "Certificate is self-signed and not trusted by standard root stores",
			check: checkSelfSigned,
		},
		{
			name: "Certificate Expired", code: "CERT-008", severity: "Critical",
			desc:  "Certificate has expired and is no longer valid",
			check: checkCertExpired,
		},
		{
			name: "Certificate Expiring Soon", code: "CERT-009", severity: "High",
			desc:  "Certificate expires within 30 days",
			check: checkCertExpiringSoon,
		},
		{
			name: "CN Not in SANs", code: "CERT-010", severity: "Low",
			desc:  "Common Name is not included in Subject Alternative Names",
			check: checkCNNotInSANs,
		},
		{
			name: "Wildcard Certificate", code: "CERT-011", severity: "Low",
			desc:  "Certificate uses wildcard patterns which increase the impact of key compromise",
			check: checkWildcardCert,
		},
		{
			name: "Internal Name Certificate", code: "CERT-012", severity: "High",
			desc:  "Certificate uses an internal name (.local, .internal) that cannot be publicly validated",
			check: checkInternalName,
		},
		{
			name: "Untrusted Chain", code: "CERT-013", severity: "High",
			desc:  "Certificate chain does not validate to a trusted root",
			check: checkUntrustedChain,
		},
		{
			name: "Distrusted CA", code: "CERT-014", severity: "Critical",
			desc:  "Certificate chain contains a known distrusted/compromised Certificate Authority",
			check: checkDistrustedCA,
		},
		{
			name: "OCSP Must-Staple Violation", code: "CERT-015", severity: "High",
			desc:  "Certificate requires OCSP stapling (Must-Staple) but server does not provide staple",
			check: checkOCSPMustStaple,
		},
		{
			name: "Key Usage Non-Compliance", code: "CERT-016", severity: "High",
			desc:  "Certificate key usage extensions violate RFC 5280 or CA/Browser Forum requirements",
			check: checkKeyUsageCompliance,
		},
		{
			name: "Low Serial Entropy", code: "CERT-017", severity: "Medium",
			desc:  "Certificate serial number has insufficient entropy (CA/B BR requires >= 64 bits)",
			check: checkSerialEntropy,
		},
		{
			name: "Name Constraint Violation", code: "CERT-018", severity: "High",
			desc:  "Certificate names violate CA name constraints (trust boundary violation)",
			check: checkNameConstraints,
		},
	}

	// Run all checks
	for _, c := range checks {
		passed, detail := c.check(leafCert, host, &state)
		check := CertSecurityCheck{
			Name:        c.name,
			Code:        c.code,
			Severity:    c.severity,
			Passed:      passed,
			Description: c.desc,
			Detail:      detail,
		}
		result.Checks = append(result.Checks, check)
	}

	// Build summary
	result.Summary = buildCertSecuritySummary(result.Checks)

	return result, nil
}

func buildCertSecuritySummary(checks []CertSecurityCheck) CertSecuritySummary {
	summary := CertSecuritySummary{
		TotalChecked: len(checks),
		IsSecure:     true,
	}

	for _, c := range checks {
		if c.Passed {
			summary.Passed++
		} else {
			summary.Failed++
			summary.FailedChecks = append(summary.FailedChecks, c.Name)
			summary.IsSecure = false
		}
	}

	return summary
}

// --- Individual Certificate Security Checks ---

func checkWeakSignature(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	sigAlg := cert.SignatureAlgorithm.String()
	weakAlgs := []string{"MD5", "SHA1", "MD2"}
	for _, weak := range weakAlgs {
		if strings.Contains(strings.ToUpper(sigAlg), weak) {
			return false, fmt.Sprintf("Uses weak signature: %s", sigAlg)
		}
	}
	return true, fmt.Sprintf("Signature algorithm: %s", sigAlg)
}

func checkShortRSAKey(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		if key.N.BitLen() < 2048 {
			return false, fmt.Sprintf("RSA key is only %d bits (minimum 2048)", key.N.BitLen())
		}
		return true, fmt.Sprintf("RSA key size: %d bits", key.N.BitLen())
	}
	return true, "Not an RSA key"
}

func checkWeakCurve(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		bitSize := key.Curve.Params().BitSize
		if bitSize < 256 {
			return false, fmt.Sprintf("ECDSA curve is only %d bits (minimum P-256)", bitSize)
		}
		return true, fmt.Sprintf("ECDSA curve: %d bits", bitSize)
	}
	return true, "Not an ECDSA key"
}

func checkMissingSAN(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		return false, "No Subject Alternative Names"
	}
	return true, fmt.Sprintf("%d SAN entries", len(cert.DNSNames)+len(cert.IPAddresses))
}

func checkHostnameMismatch(cert *x509.Certificate, host string, _ *tls.ConnectionState) (bool, string) {
	err := cert.VerifyHostname(host)
	if err != nil {
		return false, fmt.Sprintf("'%s' does not match: %v", host, err)
	}
	return true, fmt.Sprintf("'%s' matches certificate", host)
}

func checkExcessiveValidity(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if validityDays > 398 {
		return false, fmt.Sprintf("Validity: %d days (limit: 398)", validityDays)
	}
	return true, fmt.Sprintf("Validity: %d days", validityDays)
}

func checkSelfSigned(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	if cert.Subject.String() == cert.Issuer.String() {
		return false, "Self-signed certificate"
	}
	return true, "Issued by a CA"
}

func checkCertExpired(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	if time.Now().After(cert.NotAfter) {
		return false, fmt.Sprintf("Expired on %s", cert.NotAfter.Format("2006-01-02"))
	}
	return true, "Not expired"
}

func checkCertExpiringSoon(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	days := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
	if days <= 30 && days > 0 {
		return false, fmt.Sprintf("Expires in %d days", days)
	}
	return true, fmt.Sprintf("Expires in %d days", days)
}

func checkCNNotInSANs(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	if cert.Subject.CommonName == "" || len(cert.DNSNames) == 0 {
		return true, "N/A"
	}
	for _, san := range cert.DNSNames {
		if san == cert.Subject.CommonName {
			return true, "CN is in SANs"
		}
	}
	return false, fmt.Sprintf("CN '%s' not in SANs", cert.Subject.CommonName)
}

func checkWildcardCert(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	count := 0
	for _, san := range cert.DNSNames {
		if strings.HasPrefix(san, "*.") {
			count++
		}
	}
	if count > 0 {
		return false, fmt.Sprintf("%d wildcard SAN(s)", count)
	}
	return true, "No wildcards"
}

func checkInternalName(cert *x509.Certificate, _ string, _ *tls.ConnectionState) (bool, string) {
	internalTLDs := []string{".local", ".internal", ".intranet", ".private", ".corp", ".home", ".lan", ".test", ".example", ".invalid"}
	allNames := append(cert.DNSNames, cert.Subject.CommonName)
	for _, name := range allNames {
		lower := strings.ToLower(name)
		for _, tld := range internalTLDs {
			if strings.HasSuffix(lower, tld) {
				return false, fmt.Sprintf("Internal name: %s", name)
			}
		}
	}
	return true, "No internal names"
}

func checkUntrustedChain(cert *x509.Certificate, _ string, state *tls.ConnectionState) (bool, string) {
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return true, "Cannot verify (system cert pool unavailable)"
	}

	opts := x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: intermediates,
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return false, fmt.Sprintf("Chain untrusted: %v", err)
	}
	return true, "Chain trusted"
}

// checkDistrustedCA checks if any certificate in the chain was issued by a distrusted CA.
func checkDistrustedCA(cert *x509.Certificate, host string, state *tls.ConnectionState) (bool, string) {
	for i, c := range state.PeerCertificates {
		matched := matchDistrustedCA(c)
		if matched != nil {
			return false, fmt.Sprintf("Chain position %d: %s (distrusted since %s) - %s",
				i, matched.Name, matched.DistrustDate, matched.Reason)
		}
	}
	return true, "No distrusted CAs found in chain"
}

// checkOCSPMustStaple checks for OCSP Must-Staple compliance.
func checkOCSPMustStaple(cert *x509.Certificate, host string, state *tls.ConnectionState) (bool, string) {
	hasMustStaple := hasMustStapleExtension(cert)
	hasStaple := len(state.OCSPResponse) > 0

	if hasMustStaple && !hasStaple {
		return false, "Certificate has OCSP Must-Staple extension but server does not provide OCSP staple (RFC 7633 violation - clients will hard-fail)"
	}
	if hasMustStaple && hasStaple {
		return true, "OCSP Must-Staple enabled and staple provided"
	}
	// No Must-Staple requirement = pass regardless of staple
	return true, "No OCSP Must-Staple requirement"
}

// checkKeyUsageCompliance validates key usage compliance.
func checkKeyUsageCompliance(cert *x509.Certificate, host string, state *tls.ConnectionState) (bool, string) {
	var issues []string

	// CA cert without keyCertSign
	if cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		issues = append(issues, "CA certificate missing keyCertSign")
	}

	// Non-CA with keyCertSign
	if !cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		issues = append(issues, "Non-CA certificate has keyCertSign (can sign certificates)")
	}

	// TLS leaf without digitalSignature or keyEncipherment
	if !cert.IsCA {
		hasDS := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
		hasKE := cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0
		if !hasDS && !hasKE {
			issues = append(issues, "TLS certificate missing digitalSignature and keyEncipherment")
		}
	}

	// No key usage at all
	if cert.KeyUsage == 0 && len(cert.ExtKeyUsage) == 0 {
		issues = append(issues, "Certificate has no key usage or extended key usage extensions")
	}

	if len(issues) > 0 {
		return false, strings.Join(issues, "; ")
	}
	return true, "Key usage extensions are compliant"
}

// checkSerialEntropy analyzes serial number entropy.
func checkSerialEntropy(cert *x509.Certificate, host string, state *tls.ConnectionState) (bool, string) {
	if cert.SerialNumber == nil {
		return false, "Certificate has no serial number"
	}

	bitLen := cert.SerialNumber.BitLen()
	if bitLen < 64 {
		return false, fmt.Sprintf("Serial number is only %d bits (CA/B BR requires >= 64 bits)", bitLen)
	}

	// Estimate entropy
	bytes := cert.SerialNumber.Bytes()
	entropy := estimateShannonEntropy(bytes)
	if entropy < 3.0 {
		return false, fmt.Sprintf("Low entropy (%.2f bits/byte) suggests insufficient randomness in serial generation", entropy)
	}

	if isSequentialSerial(cert.SerialNumber) {
		return false, "Serial number appears sequential/predictable, violating CA/B BR entropy requirements"
	}

	return true, fmt.Sprintf("Serial number has %d bits with %.2f bits/byte entropy", bitLen, entropy)
}

// checkNameConstraints checks for name constraint violations.
func checkNameConstraints(cert *x509.Certificate, host string, state *tls.ConnectionState) (bool, string) {
	if len(state.PeerCertificates) < 2 {
		return true, "No CA certificates in chain to check constraints"
	}

	leafNames := collectLeafNames(cert)
	var violations []string

	for i := 1; i < len(state.PeerCertificates); i++ {
		ca := state.PeerCertificates[i]
		if !ca.IsCA {
			continue
		}

		constraint := extractCAConstraint(ca, i)
		if constraint == nil || !constraint.IsConstraining {
			continue
		}

		for _, name := range leafNames {
			if violatesExcluded(name, constraint) {
				violations = append(violations, fmt.Sprintf("%s excluded by %s", name, ca.Subject.CommonName))
			}
			if violatesNotPermitted(name, constraint) {
				violations = append(violations, fmt.Sprintf("%s not permitted by %s", name, ca.Subject.CommonName))
			}
		}
	}

	if len(violations) > 0 {
		return false, strings.Join(violations, "; ")
	}
	return true, "Leaf certificate names comply with all CA name constraints"
}
