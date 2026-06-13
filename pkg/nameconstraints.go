package pkg

import (
	"crypto/x509"
	"fmt"
	"net"
	"strings"
)

// NameConstraintsResult represents the result of name constraints checking.
type NameConstraintsResult struct {
	Target              string              `json:"target"`
	HasConstraints      bool                `json:"has_constraints"`
	ConstraintedCAs     []CAConstraint      `json:"constrained_cas,omitempty"`
	Violations          []ConstraintViolation `json:"violations,omitempty"`
	IsCompliant         bool                `json:"is_compliant"`
	Detail              string              `json:"detail,omitempty"`
}

// CAConstraint represents name constraints found on a CA certificate.
type CAConstraint struct {
	Subject           string   `json:"subject"`
	ChainPosition     int      `json:"chain_position"`
	PermittedDNS      []string `json:"permitted_dns,omitempty"`
	ExcludedDNS       []string `json:"excluded_dns,omitempty"`
	PermittedIPs      []string `json:"permitted_ips,omitempty"`
	ExcludedIPs       []string `json:"excluded_ips,omitempty"`
	PermittedEmails   []string `json:"permitted_emails,omitempty"`
	ExcludedEmails    []string `json:"excluded_emails,omitempty"`
	IsConstraining    bool     `json:"is_constraining"`
}

// ConstraintViolation represents a name constraint violation.
type ConstraintViolation struct {
	CASubject   string `json:"ca_subject"`
	ViolatedName string `json:"violated_name"`
	ViolationType string `json:"violation_type"` // "excluded" or "not_permitted"
	Constraint  string `json:"constraint"`
}

// CheckNameConstraints examines the certificate chain for Name Constraints
// on CA certificates and verifies that leaf certificate names comply.
func CheckNameConstraints(target string) (*NameConstraintsResult, error) {
	result := &NameConstraintsResult{
		IsCompliant: true,
	}

	conn, err := TLSDial(target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	chain := state.PeerCertificates
	leaf := chain[0]

	// Collect all names from the leaf certificate
	leafNames := collectLeafNames(leaf)

	// Check each CA in the chain for name constraints
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

		if constraint.IsConstraining {
			result.HasConstraints = true
			result.ConstraintedCAs = append(result.ConstraintedCAs, *constraint)

			// Verify leaf names against constraints
			for _, name := range leafNames {
				if violatesExcluded(name, constraint) {
					result.IsCompliant = false
					result.Violations = append(result.Violations, ConstraintViolation{
						CASubject:    ca.Subject.String(),
						ViolatedName: name,
						ViolationType: "excluded",
						Constraint:   formatConstraint(constraint),
					})
				}
				if violatesNotPermitted(name, constraint) {
					result.IsCompliant = false
					result.Violations = append(result.Violations, ConstraintViolation{
						CASubject:    ca.Subject.String(),
						ViolatedName: name,
						ViolationType: "not_permitted",
						Constraint:   formatConstraint(constraint),
					})
				}
			}
		}
	}

	if result.HasConstraints && result.IsCompliant {
		result.Detail = "Leaf certificate names comply with all CA name constraints"
	} else if result.HasConstraints {
		violations := make([]string, len(result.Violations))
		for i, v := range result.Violations {
			violations[i] = fmt.Sprintf("%s: %s (%s)", v.CASubject, v.ViolatedName, v.ViolationType)
		}
		result.Detail = fmt.Sprintf("Name constraint violations: %s", strings.Join(violations, "; "))
	} else {
		result.Detail = "No CA certificates in chain have Name Constraints"
	}

	return result, nil
}

// collectLeafNames collects all names from a leaf certificate.
func collectLeafNames(cert *x509.Certificate) []string {
	var names []string
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	names = append(names, cert.EmailAddresses...)
	return names
}

// extractCAConstraint extracts name constraints from a CA certificate.
func extractCAConstraint(ca *x509.Certificate, position int) *CAConstraint {
	constraint := &CAConstraint{
		Subject:       ca.Subject.String(),
		ChainPosition: position,
	}

	hasConstraints := false

	// Permitted DNS names
	for _, name := range ca.PermittedDNSDomains {
		constraint.PermittedDNS = append(constraint.PermittedDNS, name)
		hasConstraints = true
	}

	// Excluded DNS names
	for _, name := range ca.ExcludedDNSDomains {
		constraint.ExcludedDNS = append(constraint.ExcludedDNS, name)
		hasConstraints = true
	}

	// Permitted IP ranges
	for _, ipNet := range ca.PermittedIPRanges {
		constraint.PermittedIPs = append(constraint.PermittedIPs, ipNet.String())
		hasConstraints = true
	}

	// Excluded IP ranges
	for _, ipNet := range ca.ExcludedIPRanges {
		constraint.ExcludedIPs = append(constraint.ExcludedIPs, ipNet.String())
		hasConstraints = true
	}

	// Permitted Email addresses
	for _, email := range ca.PermittedEmailAddresses {
		constraint.PermittedEmails = append(constraint.PermittedEmails, email)
		hasConstraints = true
	}

	// Excluded Email addresses
	for _, email := range ca.ExcludedEmailAddresses {
		constraint.ExcludedEmails = append(constraint.ExcludedEmails, email)
		hasConstraints = true
	}

	if !hasConstraints {
		return nil
	}

	return constraint
}

// violatesExcluded checks if a name is in the excluded list.
func violatesExcluded(name string, constraint *CAConstraint) bool {
	for _, excluded := range constraint.ExcludedDNS {
		if nameMatchesPattern(name, excluded) {
			return true
		}
	}

	// Check excluded IP ranges
	for _, ipRange := range constraint.ExcludedIPs {
		if ipMatchesRange(name, ipRange) {
			return true
		}
	}

	return false
}

// violatesNotPermitted checks if a name is not in the permitted list
// (when permitted list is non-empty, names must match at least one entry).
func violatesNotPermitted(name string, constraint *CAConstraint) bool {
	// If there are no permitted names, everything is permitted
	if len(constraint.PermittedDNS) == 0 && len(constraint.PermittedIPs) == 0 {
		return false
	}

	// Check if name matches any permitted DNS pattern
	if len(constraint.PermittedDNS) > 0 {
		for _, permitted := range constraint.PermittedDNS {
			if nameMatchesPattern(name, permitted) {
				return false
			}
		}
		// Name didn't match any permitted DNS pattern
		// Only fail if the name looks like a DNS name (not an IP)
		if !isIPAddress(name) {
			return true
		}
	}

	// Check if name matches any permitted IP range
	if len(constraint.PermittedIPs) > 0 && isIPAddress(name) {
		for _, ipRange := range constraint.PermittedIPs {
			if ipMatchesRange(name, ipRange) {
				return false
			}
		}
		return true
	}

	return false
}

// nameMatchesPattern checks if a name matches a DNS constraint pattern.
func nameMatchesPattern(name, pattern string) bool {
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(name, pattern) || name == pattern[1:]
	}
	return name == pattern || strings.HasSuffix(name, "."+pattern)
}

// isIPAddress checks if a string looks like an IP address.
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// ipMatchesRange checks if an IP address is within a CIDR range.
func ipMatchesRange(name, cidrStr string) bool {
	ip := net.ParseIP(name)
	if ip == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

// formatConstraint formats a constraint for display.
func formatConstraint(c *CAConstraint) string {
	var parts []string
	if len(c.PermittedDNS) > 0 {
		parts = append(parts, "permitted DNS: "+strings.Join(c.PermittedDNS, ", "))
	}
	if len(c.ExcludedDNS) > 0 {
		parts = append(parts, "excluded DNS: "+strings.Join(c.ExcludedDNS, ", "))
	}
	if len(c.PermittedIPs) > 0 {
		parts = append(parts, "permitted IPs: "+strings.Join(c.PermittedIPs, ", "))
	}
	if len(c.ExcludedIPs) > 0 {
		parts = append(parts, "excluded IPs: "+strings.Join(c.ExcludedIPs, ", "))
	}
	return strings.Join(parts, "; ")
}
