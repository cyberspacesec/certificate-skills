package pkg

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// KeyUsageComplianceResult represents the result of key usage compliance validation.
type KeyUsageComplianceResult struct {
	Target       string              `json:"target"`
	IsCompliant  bool                `json:"is_compliant"`
	Issues       []KeyUsageIssue     `json:"issues,omitempty"`
	KeyUsage     []string            `json:"key_usage"`
	ExtKeyUsage  []string            `json:"ext_key_usage"`
	IsCA         bool                `json:"is_ca"`
	Detail       string              `json:"detail,omitempty"`
}

// KeyUsageIssue represents a key usage compliance violation.
type KeyUsageIssue struct {
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Rule        string `json:"rule"`
}

// CheckKeyUsageCompliance validates that a certificate's key usage
// extensions are compliant with RFC 5280 and CA/Browser Forum requirements.
func CheckKeyUsageCompliance(target string) (*KeyUsageComplianceResult, error) {
	result := &KeyUsageComplianceResult{
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
	result.IsCA = cert.IsCA
	result.KeyUsage = keyUsageToStrings(cert)
	result.ExtKeyUsage = extKeyUsageToStrings(cert)

	// Rule 1: CA certificates must have keyCertSign
	if cert.IsCA {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			result.IsCompliant = false
			result.Issues = append(result.Issues, KeyUsageIssue{
				Severity:    "High",
				Description: "CA certificate missing keyCertSign key usage",
				Rule:        "RFC 5280: CA certificates MUST have keyCertSign in Key Usage",
			})
		}
		if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
			result.IsCompliant = false
			result.Issues = append(result.Issues, KeyUsageIssue{
				Severity:    "Medium",
				Description: "CA certificate missing cRLSign key usage",
				Rule:        "RFC 5280: CA certificates SHOULD have cRLSign in Key Usage",
			})
		}
	}

	// Rule 2: Non-CA (leaf) certificates should NOT have keyCertSign
	if !cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		result.IsCompliant = false
		result.Issues = append(result.Issues, KeyUsageIssue{
			Severity:    "High",
			Description: "Non-CA certificate has keyCertSign key usage (can sign certificates)",
			Rule:        "RFC 5280: Only CA certificates should have keyCertSign",
		})
	}

	// Rule 3: TLS server certificates must have digitalSignature or keyEncipherment
	if !cert.IsCA {
		hasDigitalSig := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
		hasKeyEnciph := cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0
		if !hasDigitalSig && !hasKeyEnciph {
			result.IsCompliant = false
			result.Issues = append(result.Issues, KeyUsageIssue{
				Severity:    "High",
				Description: "TLS certificate missing digitalSignature and keyEncipherment key usage",
				Rule:        "CA/Browser Forum BR: TLS certificates MUST have digitalSignature or keyEncipherment",
			})
		}
	}

	// Rule 4: TLS server certificates should have ServerAuth extended key usage
	if !cert.IsCA {
		hasServerAuth := false
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageServerAuth {
				hasServerAuth = true
				break
			}
		}
		if !hasServerAuth && len(cert.ExtKeyUsage) > 0 {
			result.IsCompliant = false
			result.Issues = append(result.Issues, KeyUsageIssue{
				Severity:    "Medium",
				Description: "TLS certificate missing serverAuth extended key usage",
				Rule:        "CA/Browser Forum BR: TLS server certificates MUST have serverAuth EKU",
			})
		}
	}

	// Rule 5: Key usage and key algorithm consistency
	// RSA keys with keyEncipherment are for key exchange (TLS 1.2 and below)
	// ECDSA keys should have digitalSignature (not keyEncipherment)
	if cert.PublicKeyAlgorithm == x509.ECDSA || cert.PublicKeyAlgorithm == x509.Ed25519 {
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			result.Issues = append(result.Issues, KeyUsageIssue{
				Severity:    "Low",
				Description: fmt.Sprintf("%s certificate has keyEncipherment (not needed for this key type)", cert.PublicKeyAlgorithm),
				Rule:        "Key usage should match key algorithm capabilities",
			})
		}
	}

	// Rule 6: Check for no key usage at all (critical for trust)
	if cert.KeyUsage == 0 && len(cert.ExtKeyUsage) == 0 {
		result.IsCompliant = false
		result.Issues = append(result.Issues, KeyUsageIssue{
			Severity:    "High",
			Description: "Certificate has no key usage or extended key usage extensions",
			Rule:        "RFC 5280: Certificates SHOULD have Key Usage extension; CA/B BR requires it",
		})
	}

	if result.IsCompliant {
		result.Detail = "Key usage extensions are compliant"
	} else {
		issues := make([]string, len(result.Issues))
		for i, issue := range result.Issues {
			issues[i] = issue.Description
		}
		result.Detail = fmt.Sprintf("Compliance issues: %s", strings.Join(issues, "; "))
	}

	return result, nil
}

// keyUsageToStrings converts KeyUsage bitmask to human-readable strings.
func keyUsageToStrings(cert *x509.Certificate) []string {
	var usages []string
	ku := cert.KeyUsage
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "contentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "keyCertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "cRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "decipherOnly")
	}
	return usages
}

// extKeyUsageToStrings converts ExtKeyUsage to human-readable strings.
func extKeyUsageToStrings(cert *x509.Certificate) []string {
	var usages []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "emailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "ipsecEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "ipsecTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "ipsecUser")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "ocspSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usages = append(usages, "msServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usages = append(usages, "nsServerGatedCrypto")
		default:
			usages = append(usages, fmt.Sprintf("unknown(%d)", eku))
		}
	}
	return usages
}
