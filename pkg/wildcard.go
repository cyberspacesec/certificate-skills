package pkg

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// WildcardResult represents the result of a wildcard certificate analysis.
type WildcardResult struct {
	Target         string         `json:"target"`
	IsWildcard     bool           `json:"is_wildcard"`
	WildcardNames  []string       `json:"wildcard_names"`
	ExactNames     []string       `json:"exact_names"`
	WildcardLevel  int            `json:"wildcard_level"`  // 0=none, 1=*.domain, 2=*.*.domain etc.
	RiskLevel      string         `json:"risk_level"`      // None, Low, Medium, High
	RiskReason     string         `json:"risk_reason,omitempty"`
	CoveredDomains []string       `json:"covered_domains"` // Domains that the wildcard covers
	AllSANs        []SANEntry     `json:"all_sans"`
	CommonName     string         `json:"common_name"`
	Issuer         string         `json:"issuer"`
	Error          string         `json:"error,omitempty"`
}

// SANEntry represents a single Subject Alternative Name entry with its classification.
type SANEntry struct {
	Type     string `json:"type"`     // DNS, IP, Email, URI
	Value    string `json:"value"`
	IsWildcard bool  `json:"is_wildcard"`
	WildcardLevel int `json:"wildcard_level,omitempty"` // 1=*.domain, 2=*.*.domain
	BaseDomain string `json:"base_domain,omitempty"` // The base domain for wildcard entries
}

// CheckWildcard performs a comprehensive wildcard certificate analysis.
// It detects wildcard patterns in SAN/CN, classifies wildcard levels,
// and assesses the security risk of using wildcard certificates.
func CheckWildcard(target string) (*WildcardResult, error) {
	result := &WildcardResult{
		Target:         target,
		WildcardNames:  []string{},
		ExactNames:     []string{},
		CoveredDomains: []string{},
		AllSANs:        []SANEntry{},
	}

	var cert *CertInfo
	var sslInfo *SSLInfo

	if IsFileTarget(target) {
		certInfo, err := GetCertFromFile(target)
		if err != nil {
			result.Error = fmt.Sprintf("failed to read certificate: %v", err)
			return result, nil
		}
		cert = certInfo
	} else {
		var err error
		sslInfo, err = GetCertFromDomain(target)
		if err != nil {
			result.Error = fmt.Sprintf("failed to connect: %v", err)
			return result, nil
		}
		if len(sslInfo.PeerCerts.Certificates) == 0 {
			result.Error = "no certificates found"
			return result, nil
		}
		c := sslInfo.PeerCerts.Certificates[0]
		cert = &c
	}

	result.CommonName = cert.Subject
	result.Issuer = cert.Issuer

	// Analyze Common Name
	if strings.HasPrefix(cert.Subject, "CN=") {
		// Extract CN value
		cnValue := extractCN(cert.Subject)
		if cnValue != "" {
			entry := classifySANEntry("DNS", cnValue)
			result.AllSANs = append(result.AllSANs, entry)
			if entry.IsWildcard {
				result.IsWildcard = true
				result.WildcardNames = append(result.WildcardNames, cnValue)
			} else {
				result.ExactNames = append(result.ExactNames, cnValue)
			}
		}
	}

	// Analyze DNS SANs
	for _, dnsName := range cert.DNSNames {
		entry := classifySANEntry("DNS", dnsName)
		result.AllSANs = append(result.AllSANs, entry)
		if entry.IsWildcard {
			result.IsWildcard = true
			result.WildcardNames = append(result.WildcardNames, dnsName)
			if entry.WildcardLevel > result.WildcardLevel {
				result.WildcardLevel = entry.WildcardLevel
			}
			// Track covered base domains
			if entry.BaseDomain != "" {
				result.CoveredDomains = append(result.CoveredDomains, entry.BaseDomain)
			}
		} else {
			result.ExactNames = append(result.ExactNames, dnsName)
		}
	}

	// Analyze IP SANs
	for _, ip := range cert.IPAddresses {
		result.AllSANs = append(result.AllSANs, SANEntry{
			Type:  "IP",
			Value: ip,
		})
	}

	// Assess wildcard risk
	result.RiskLevel, result.RiskReason = assessWildcardRisk(result)

	return result, nil
}

// classifySANEntry classifies a SAN entry by type and wildcard level.
func classifySANEntry(sanType, value string) SANEntry {
	entry := SANEntry{
		Type:  sanType,
		Value: value,
	}

	if sanType == "DNS" && strings.HasPrefix(value, "*.") {
		entry.IsWildcard = true
		// Count wildcard levels: *.example.com = 1, *.*.example.com = 2
		parts := strings.Split(value, ".")
		wildcardCount := 0
		for _, part := range parts {
			if part == "*" {
				wildcardCount++
			}
		}
		entry.WildcardLevel = wildcardCount
		// Extract base domain (everything after the wildcard prefix)
		entry.BaseDomain = strings.TrimPrefix(value, "*.")
		if wildcardCount > 1 {
			// For *.*.example.com, base domain is example.com
			parts := strings.Split(value, ".")
			if len(parts) >= 2 {
				entry.BaseDomain = strings.Join(parts[wildcardCount:], ".")
			}
		}
	}

	return entry
}

// assessWildcardRisk evaluates the security risk of wildcard certificate usage.
func assessWildcardRisk(result *WildcardResult) (level string, reason string) {
	if !result.IsWildcard {
		return "None", "No wildcard patterns detected"
	}

	// High risk: multi-level wildcards like *.*.example.com
	if result.WildcardLevel >= 2 {
		return "High", fmt.Sprintf("Multi-level wildcard certificate detected (%d levels). This certificate covers an extremely broad namespace and presents significant security risk.", result.WildcardLevel)
	}

	// Medium risk: wildcard covering many base domains
	if len(result.CoveredDomains) > 3 {
		return "High", fmt.Sprintf("Wildcard certificate covers %d different base domains. A compromised private key would affect all subdomains across all domains.", len(result.CoveredDomains))
	}

	// Medium risk: wildcard with many exact names too (mixed usage)
	if len(result.ExactNames) > 10 {
		return "Medium", "Wildcard certificate combined with many exact SANs. Consider using separate certificates for different services."
	}

	// Low risk: single wildcard for one domain
	if len(result.CoveredDomains) == 1 {
		return "Low", "Single-domain wildcard certificate. Acceptable for internal use but consider if individual certificates would be more appropriate for production."
	}

	// Medium risk: wildcard covering multiple domains
	return "Medium", fmt.Sprintf("Wildcard certificate covers %d base domains. A compromised private key would expose all subdomains.", len(result.CoveredDomains))
}

// extractCN extracts the Common Name value from a subject string like "CN=example.com,O=Org"
func extractCN(subject string) string {
	parts := strings.Split(subject, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return ""
}

// GetCertSANs retrieves all Subject Alternative Names from a domain's certificate.
// Returns DNS names, IP addresses, and email addresses separately.
func GetCertSANs(target string) (dnsNames []string, ipAddrs []string, emails []string, err error) {
	conn, err2 := TLSDial(target)
	if err2 != nil {
		return nil, nil, nil, fmt.Errorf("failed to connect: %v", err2)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, nil, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]
	dnsNames = cert.DNSNames
	emails = cert.EmailAddresses

	for _, ip := range cert.IPAddresses {
		ipAddrs = append(ipAddrs, ip.String())
	}

	return dnsNames, ipAddrs, emails, nil
}

// GetTrustedDomains extracts all domain names trusted by a certificate,
// including wildcard expansions. Useful for cyberspace mapping to understand
// what domain namespace a certificate covers.
func GetTrustedDomains(target string) (*TrustedDomainsResult, error) {
	result := &TrustedDomainsResult{
		Target: target,
	}

	host, port := parseHostPort(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]

	// Extract CN
	result.CommonName = cert.Subject.CommonName
	if cert.Subject.CommonName != "" {
		result.AllDomains = append(result.AllDomains, cert.Subject.CommonName)
	}

	// Extract DNS SANs
	for _, dnsName := range cert.DNSNames {
		result.AllDomains = append(result.AllDomains, dnsName)
		if strings.HasPrefix(dnsName, "*.") {
			result.WildcardDomains = append(result.WildcardDomains, dnsName)
			// Extract base domain from wildcard
			baseDomain := strings.TrimPrefix(dnsName, "*.")
			result.BaseDomains = append(result.BaseDomains, baseDomain)
		} else {
			result.ExactDomains = append(result.ExactDomains, dnsName)
			// Also track the base domain
			parts := strings.Split(dnsName, ".")
			if len(parts) >= 2 {
				baseDomain := strings.Join(parts[len(parts)-2:], ".")
				result.BaseDomains = append(result.BaseDomains, baseDomain)
			}
		}
	}

	// Extract IPs
	for _, ip := range cert.IPAddresses {
		result.IPAddresses = append(result.IPAddresses, ip.String())
	}

	// Extract organization for related domain discovery
	result.Organization = strings.Join(cert.Subject.Organization, ", ")
	result.OrganizationalUnit = strings.Join(cert.Subject.OrganizationalUnit, ", ")

	// Deduplicate
	result.BaseDomains = uniqueStrings(result.BaseDomains)

	return result, nil
}

// TrustedDomainsResult represents the result of extracting trusted domains from a certificate.
type TrustedDomainsResult struct {
	Target             string   `json:"target"`
	CommonName         string   `json:"common_name"`
	AllDomains         []string `json:"all_domains"`
	ExactDomains       []string `json:"exact_domains"`
	WildcardDomains    []string `json:"wildcard_domains"`
	BaseDomains        []string `json:"base_domains"`      // Unique base domains
	IPAddresses        []string `json:"ip_addresses"`
	Organization       string   `json:"organization,omitempty"`
	OrganizationalUnit string   `json:"organizational_unit,omitempty"`
}

// uniqueStrings removes duplicate strings from a slice.
func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
