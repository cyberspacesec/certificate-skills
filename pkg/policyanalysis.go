package pkg

import (
	"fmt"
	"strings"
)

// PolicyAnalysisResult represents the result of certificate policy analysis.
type PolicyAnalysisResult struct {
	Target         string        `json:"target"`
	ValidationType string        `json:"validation_type"` // DV, OV, EV, or Unknown
	PolicyOIDs     []PolicyOID   `json:"policy_oids"`
	HasPolicies    bool          `json:"has_policies"`
	Issues         []string      `json:"issues,omitempty"`
	IsCompliant    bool          `json:"is_compliant"`
	Detail         string        `json:"detail,omitempty"`
}

// PolicyOID represents a certificate policy OID with its known meaning.
type PolicyOID struct {
	OID         string `json:"oid"`
	Description string `json:"description"`
	Type        string `json:"type"` // DV, OV, EV, or Unknown
}

// Known policy OIDs for major CAs
var knownPolicyOIDs = map[string]PolicyOID{
	// DigiCert
	"2.16.840.1.114412.1.1":  {OID: "2.16.840.1.114412.1.1", Description: "DigiCert DV", Type: "DV"},
	"2.16.840.1.114412.1.2":  {OID: "2.16.840.1.114412.1.2", Description: "DigiCert OV", Type: "OV"},
	"2.16.840.1.114412.1.3":  {OID: "2.16.840.1.114412.1.3", Description: "DigiCert EV", Type: "EV"},
	// Let's Encrypt
	"2.23.140.1.2.1":         {OID: "2.23.140.1.2.1", Description: "Domain Validated", Type: "DV"},
	// Global CA/B Forum OIDs
	"2.23.140.1.2.2":         {OID: "2.23.140.1.2.2", Description: "Organization Validated", Type: "OV"},
	"2.23.140.1.1":           {OID: "2.23.140.1.1", Description: "Extended Validation", Type: "EV"},
	// Sectigo (formerly Comodo)
	"1.3.6.1.4.1.6449.1.2.1.5.1": {OID: "1.3.6.1.4.1.6449.1.2.1.5.1", Description: "Sectigo DV", Type: "DV"},
	"1.3.6.1.4.1.6449.1.2.2.6.1": {OID: "1.3.6.1.4.1.6449.1.2.2.6.1", Description: "Sectigo OV", Type: "OV"},
	"1.3.6.1.4.1.6449.1.2.1.7.1": {OID: "1.3.6.1.4.1.6449.1.2.1.7.1", Description: "Sectigo EV", Type: "EV"},
	// GoDaddy
	"2.16.840.1.114413.1.7.23.1": {OID: "2.16.840.1.114413.1.7.23.1", Description: "GoDaddy DV", Type: "DV"},
	"2.16.840.1.114413.1.7.23.2": {OID: "2.16.840.1.114413.1.7.23.2", Description: "GoDaddy OV", Type: "OV"},
	"2.16.840.1.114413.1.7.23.3": {OID: "2.16.840.1.114413.1.7.23.3", Description: "GoDaddy EV", Type: "EV"},
	// GlobalSign
	"1.3.6.1.4.1.4146.1.1":  {OID: "1.3.6.1.4.1.4146.1.1", Description: "GlobalSign DV", Type: "DV"},
	"1.3.6.1.4.1.4146.1.2":  {OID: "1.3.6.1.4.1.4146.1.2", Description: "GlobalSign OV", Type: "OV"},
	"1.3.6.1.4.1.4146.1.3":  {OID: "1.3.6.1.4.1.4146.1.3", Description: "GlobalSign EV", Type: "EV"},
	// Entrust
	"2.16.840.1.114028.10.1.2": {OID: "2.16.840.1.114028.10.1.2", Description: "Entrust DV", Type: "DV"},
	"2.16.840.1.114028.10.1.4": {OID: "2.16.840.1.114028.10.1.4", Description: "Entrust OV", Type: "OV"},
	"2.16.840.1.114028.10.1.5": {OID: "2.16.840.1.114028.10.1.5", Description: "Entrust EV", Type: "EV"},
}

// CheckPolicyAnalysis performs certificate policy analysis beyond simple EV detection.
func CheckPolicyAnalysis(target string) (*PolicyAnalysisResult, error) {
	result := &PolicyAnalysisResult{
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

	cert := state.PeerCertificates[0]
	result.Target = target

	// Extract policy OIDs
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

	// Determine validation type
	result.ValidationType = determineValidationType(result.PolicyOIDs)

	// Check for missing Certificate Policies extension on public CA-issued certs
	if !result.HasPolicies && !cert.IsCA {
		issuerOrg := ""
		if len(cert.Issuer.Organization) > 0 {
			issuerOrg = cert.Issuer.Organization[0]
		}
		// Check if this looks like it was issued by a public CA
		publicCAIndicators := []string{"DigiCert", "Let's Encrypt", "Sectigo", "GoDaddy", "GlobalSign",
			"Entrust", "Comodo", "Certum", "QuoVadis", "SWISSSIGN", "Buypass", "Certigna"}
		for _, indicator := range publicCAIndicators {
			if strings.Contains(issuerOrg, indicator) {
				result.IsCompliant = false
				result.Issues = append(result.Issues,
					"Certificate issued by public CA is missing Certificate Policies extension (CA/B BR violation)")
				break
			}
		}
	}

	// Check for unknown policy OIDs
	unknownCount := 0
	for _, policy := range result.PolicyOIDs {
		if policy.Type == "Unknown" {
			unknownCount++
		}
	}
	if unknownCount > 0 {
		result.Issues = append(result.Issues,
			fmt.Sprintf("%d unknown policy OID(s) - could indicate custom/private CA", unknownCount))
	}

	if result.IsCompliant {
		result.Detail = fmt.Sprintf("Validation type: %s, %d policy OID(s)", result.ValidationType, len(result.PolicyOIDs))
	}

	return result, nil
}

// determineValidationType determines the validation type from policy OIDs.
func determineValidationType(policies []PolicyOID) string {
	hasEV := false
	hasOV := false
	hasDV := false

	for _, policy := range policies {
		switch policy.Type {
		case "EV":
			hasEV = true
		case "OV":
			hasOV = true
		case "DV":
			hasDV = true
		}
	}

	if hasEV {
		return "EV"
	}
	if hasOV {
		return "OV"
	}
	if hasDV {
		return "DV"
	}
	return "Unknown"
}
