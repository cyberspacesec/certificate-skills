package pkg

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CTEnumerationResult represents an enhanced CT log search result
// focused on subdomain enumeration for cyberspace mapping.
type CTEnumerationResult struct {
	Target           string              `json:"target"`
	TotalCerts       int                 `json:"total_certs"`
	UniqueSubdomains []string            `json:"unique_subdomains"`
	WildcardDomains  []string            `json:"wildcard_domains"`
	SubdomainCount   int                 `json:"subdomain_count"`
	ByIssuer         map[string][]string `json:"by_issuer"`
	ByCA             map[string]int      `json:"by_ca"`
	ActiveCerts      int                 `json:"active_certs"`
	ExpiredCerts     int                 `json:"expired_certs"`
	Organizations    []string            `json:"organizations"`
	Error            string              `json:"error,omitempty"`
}

// CTEnumerateSubdomains performs an enhanced CT log search focused on
// subdomain enumeration for cyberspace mapping.
func CTEnumerateSubdomains(domain string) (*CTEnumerationResult, error) {
	result := &CTEnumerationResult{
		Target:        domain,
		ByIssuer:      make(map[string][]string),
		ByCA:          make(map[string]int),
		Organizations: []string{},
	}

	searchResult, err := CTSearch(domain)
	if err != nil {
		return nil, fmt.Errorf("CT search failed: %v", err)
	}

	if searchResult.Error != "" {
		result.Error = searchResult.Error
		return result, nil
	}

	result.TotalCerts = searchResult.TotalCount

	subdomainSet := make(map[string]bool)
	wildcardSet := make(map[string]bool)
	orgSet := make(map[string]bool)

	for _, cert := range searchResult.Certificates {
		names := strings.Split(cert.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if strings.HasPrefix(name, "*.") {
				wildcardSet[name] = true
				baseDomain := strings.TrimPrefix(name, "*.")
				subdomainSet[baseDomain] = true
			} else {
				subdomainSet[name] = true
			}
		}

		issuerName := cert.Issuer
		if issuerName == "" {
			issuerName = cert.IssuerName
		}
		if issuerName != "" {
			result.ByCA[issuerName]++

			org := extractCTOrganization(issuerName)
			if org != "" {
				orgSet[org] = true
			}

			for _, name := range names {
				name = strings.TrimSpace(name)
				if name != "" && !strings.HasPrefix(name, "*.") {
					found := false
					for _, existing := range result.ByIssuer[issuerName] {
						if existing == name {
							found = true
							break
						}
					}
					if !found {
						result.ByIssuer[issuerName] = append(result.ByIssuer[issuerName], name)
					}
				}
			}
		}

		// Check active vs expired
		if cert.NotAfter != "" {
			for _, format := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
				if t, err := time.Parse(format, cert.NotAfter); err == nil {
					if t.Before(time.Now()) {
						result.ExpiredCerts++
					} else {
						result.ActiveCerts++
					}
					break
				}
			}
		}
	}

	for sd := range subdomainSet {
		result.UniqueSubdomains = append(result.UniqueSubdomains, sd)
	}
	for wd := range wildcardSet {
		result.WildcardDomains = append(result.WildcardDomains, wd)
	}
	for org := range orgSet {
		result.Organizations = append(result.Organizations, org)
	}

	sort.Strings(result.UniqueSubdomains)
	sort.Strings(result.WildcardDomains)
	sort.Strings(result.Organizations)
	result.SubdomainCount = len(result.UniqueSubdomains)

	return result, nil
}

// extractCTOrganization extracts organization name from issuer string.
func extractCTOrganization(issuer string) string {
	parts := strings.Split(issuer, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "O=") {
			return strings.TrimPrefix(part, "O=")
		}
	}
	return ""
}
