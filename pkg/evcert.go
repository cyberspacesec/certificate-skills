package pkg

import (
	"fmt"
)

// EVResult represents the result of an Extended Validation (EV) certificate detection.
type EVResult struct {
	Target           string   `json:"target"`
	IsEV             bool     `json:"is_ev"`
	EVIssuer         string   `json:"ev_issuer,omitempty"`
	Organization     string   `json:"organization,omitempty"`
	BusinessCategory string   `json:"business_category,omitempty"`
	Jurisdiction     string   `json:"jurisdiction,omitempty"`
	SerialNumber     string   `json:"serial_number,omitempty"`
	Reason           string   `json:"reason,omitempty"`
	EVOIDs           []string `json:"ev_oids,omitempty"`
}

// Known EV OID policy identifiers from CA/Browser Forum EV guidelines
var evPolicyOIDs = map[string]string{
	// DigiCert
	"2.16.840.1.114412.2.1": "DigiCert EV",
	"2.16.840.1.114412.1.2": "DigiCert EV",
	"2.16.840.1.114412.4.1": "DigiCert EV",
	"2.16.840.1.114412.4.2": "DigiCert EV",
	"2.16.840.1.114412.4.3": "DigiCert EV",
	// GlobalSign
	"1.3.6.1.4.1.4146.1.1": "GlobalSign EV",
	// GoDaddy
	"2.16.840.1.114413.1.7.23.3": "GoDaddy EV",
	// Entrust
	"2.16.840.1.114028.10.1.2": "Entrust EV",
	"2.16.840.1.114028.10.1.1": "Entrust EV",
	// Certum
	"1.2.616.1.113527.2.5.1.1": "Certum EV",
	// Camerfirma
	"1.3.6.1.4.1.17326.4.1.2": "Camerfirma EV",
	// Trustwave
	"2.16.840.1.114404.1.1": "Trustwave EV",
	// Symantec/VeriSign
	"2.16.840.1.113733.1.7.23.6": "Symantec/VeriSign EV",
	"2.16.840.1.113733.1.7.1.6":  "Symantec/VeriSign EV",
	// Let's Encrypt (NOT EV, but listed for reference)
	// Let's Encrypt uses "2.23.140.1.2.1" for DV - intentionally NOT included
}

// Domain-validated and organization-validated OID patterns
var dvOIDs = []string{
	"2.23.140.1.2.1", // CA/Browser Forum DV
}

var ovOIDs = []string{
	"2.23.140.1.2.2", // CA/Browser Forum OV
}

// DetectEV checks whether a domain's certificate is an Extended Validation (EV) certificate.
// EV certificates require rigorous identity verification and are the highest trust level.
func DetectEV(target string) (*EVResult, error) {
	result := &EVResult{
		Target: target,
		EVOIDs: []string{},
	}

	host, port := parseHostPort(target)

	conn, err := TLSDial(fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		result.Reason = fmt.Sprintf("failed to connect: %v", err)
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.Reason = "no certificates found"
		return result, nil
	}

	cert := state.PeerCertificates[0]

	// Check certificate policies for EV OID
	for _, policy := range cert.PolicyIdentifiers {
		oidStr := policy.String()
		result.EVOIDs = append(result.EVOIDs, oidStr)

		if evName, isEV := evPolicyOIDs[oidStr]; isEV {
			result.IsEV = true
			result.EVIssuer = evName
		}

		// Check CA/Browser Forum reserved EV OID
		if oidStr == "2.23.140.1.1" {
			result.IsEV = true
			result.EVIssuer = "CA/Browser Forum EV"
		}
	}

	// Extract organization info if EV
	if result.IsEV {
		result.Organization = cert.Subject.Organization[0]
		if len(cert.Subject.SerialNumber) > 0 {
			result.SerialNumber = cert.Subject.SerialNumber
		}

		// Look for business category and jurisdiction in subject
		for _, ext := range cert.Extensions {
			// EV certificates include jurisdiction of incorporation (OID 1.3.6.1.4.1.311.60.2.1.3)
			if ext.Id.String() == "1.3.6.1.4.1.311.60.2.1.3" ||
				ext.Id.String() == "1.3.6.1.4.1.311.60.2.2.1" {
				result.Jurisdiction = string(ext.Value)
			}
			// Business Category OID (1.3.6.1.4.1.311.60.2.1.2)
			if ext.Id.String() == "1.3.6.1.4.1.311.60.2.1.2" {
				result.BusinessCategory = string(ext.Value)
			}
		}
	}

	if !result.IsEV {
		// Determine why it's not EV
		for _, oid := range result.EVOIDs {
			for _, dvOid := range dvOIDs {
				if oid == dvOid {
					result.Reason = "Certificate is Domain-Validated (DV), not EV"
					return result, nil
				}
			}
			for _, ovOid := range ovOIDs {
				if oid == ovOid {
					result.Reason = "Certificate is Organization-Validated (OV), not EV"
					return result, nil
				}
			}
		}
		if len(cert.PolicyIdentifiers) == 0 {
			result.Reason = "No certificate policies found (likely DV or self-signed)"
		} else {
			result.Reason = "No recognized EV OID in certificate policies"
		}
	}

	return result, nil
}
