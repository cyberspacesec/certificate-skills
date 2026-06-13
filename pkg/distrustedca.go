package pkg

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// DistrustedCAResult represents the result of checking a certificate chain
// against known distrusted/compromised Certificate Authorities.
type DistrustedCAResult struct {
	Target        string            `json:"target"`
	IsDistrusted  bool              `json:"is_distrusted"`
	DistrustedCAs []DistrustedCA    `json:"distrusted_cas,omitempty"`
	ChainPosition map[string]string `json:"chain_position,omitempty"` // fingerprint -> subject
	Warning       string            `json:"warning,omitempty"`
}

// DistrustedCA represents a distrusted certificate authority found in the chain.
type DistrustedCA struct {
	Name          string `json:"name"`
	Subject       string `json:"subject"`
	Reason        string `json:"reason"`
	DistrustDate  string `json:"distrust_date"`
	ChainPosition int    `json:"chain_position"` // 0=leaf, 1=intermediate, etc.
	Fingerprint   string `json:"fingerprint"`
	Severity      string `json:"severity"`
}

// distrustedCAEntry defines a known distrusted CA.
type distrustedCAEntry struct {
	Name         string
	SubjectCN    string // Common Name patterns to match
	SubjectOrg   string // Organization patterns to match
	SPKISHA256   string // SHA-256 of Subject Public Key Info (more reliable than subject)
	Reason       string
	DistrustDate string
	Severity     string
}

// Known distrusted CAs based on browser/vendor distrust events.
// Sources: Mozilla CA Removal, Chrome Root Store, Apple Root Program
var distrustedCAs = []distrustedCAEntry{
	// DigiNotar - Compromised in 2011, issued fraudulent certificates for Google, etc.
	{
		Name:         "DigiNotar",
		SubjectCN:    "DigiNotar",
		SubjectOrg:   "DigiNotar",
		Reason:       "CA compromise: Fraudulent certificates issued for google.com and other domains (2011 Iranian attack)",
		DistrustDate: "2011-08-30",
		Severity:     "Critical",
	},
	// WoSign - Mis-issuance, backdating, unauthorized sub-CAs
	{
		Name:         "WoSign",
		SubjectCN:    "WoSign",
		SubjectOrg:   "WoSign",
		Reason:       "Mis-issuance, backdating of certificates, unauthorized sub-CA issuance",
		DistrustDate: "2017-10-19",
		Severity:     "Critical",
	},
	// StartCom (StartSSL) - Same ownership as WoSign, same issues
	{
		Name:         "StartCom",
		SubjectCN:    "StartCom",
		SubjectOrg:   "StartCom",
		Reason:       "Same ownership as WoSign CA; subject to same distrust due to mis-issuance",
		DistrustDate: "2017-10-19",
		Severity:     "Critical",
	},
	// Symantec (legacy) - Mis-issuance, failure to audit properly
	{
		Name:         "Symantec (Legacy)",
		SubjectCN:    "Symantec",
		SubjectOrg:   "Symantec Corporation",
		Reason:       "Mis-issuance and audit failures; legacy Symantec PKI distrusted by Chrome/Firefox",
		DistrustDate: "2018-10-23",
		Severity:     "High",
	},
	{
		Name:         "Thawte (Symantec-era)",
		SubjectCN:    "Thawte",
		SubjectOrg:   "Thawte Consulting",
		Reason:       "Operated under Symantec PKI infrastructure; subject to Symantec distrust",
		DistrustDate: "2018-10-23",
		Severity:     "High",
	},
	{
		Name:         "VeriSign (Symantec-era)",
		SubjectCN:    "VeriSign",
		SubjectOrg:   "VeriSign",
		Reason:       "Operated under Symantec PKI infrastructure; subject to Symantec distrust",
		DistrustDate: "2018-10-23",
		Severity:     "High",
	},
	{
		Name:         "GeoTrust (Symantec-era)",
		SubjectCN:    "GeoTrust",
		SubjectOrg:   "GeoTrust",
		Reason:       "Operated under Symantec PKI infrastructure; subject to Symantec distrust",
		DistrustDate: "2018-10-23",
		Severity:     "High",
	},
	{
		Name:         "RapidSSL (Symantec-era)",
		SubjectCN:    "RapidSSL",
		SubjectOrg:   "RapidSSL",
		Reason:       "Operated under Symantec PKI infrastructure; subject to Symantec distrust",
		DistrustDate: "2018-10-23",
		Severity:     "High",
	},
	// CNNIC - Mis-issuance, unauthorized certificate issuance
	{
		Name:         "CNNIC",
		SubjectCN:    "CNNIC",
		SubjectOrg:   "China Internet Network Information Center",
		Reason:       "Mis-issuance: Unauthorized certificates issued by intermediate CA",
		DistrustDate: "2015-04-02",
		Severity:     "Critical",
	},
	// Certinomis - Mis-issuance
	{
		Name:         "Certinomis",
		SubjectCN:    "Certinomis",
		SubjectOrg:   "Certinomis",
		Reason:       "Mis-issuance: Issued certificates in violation of BR requirements",
		DistrustDate: "2020-03-17",
		Severity:     "Medium",
	},
	// TrustCor - Ownership concerns, misrepresentation
	{
		Name:         "TrustCor",
		SubjectCN:    "TrustCor",
		SubjectOrg:   "TrustCor",
		Reason:       "Ownership concerns and misrepresentation; removed from root programs",
		DistrustDate: "2022-11-01",
		Severity:     "High",
	},
	// DarkMatter - UAE-based CA with surveillance concerns
	{
		Name:         "DarkMatter",
		SubjectCN:    "DarkMatter",
		SubjectOrg:   "DarkMatter",
		Reason:       "Surveillance concerns; intermediate CA trust issues",
		DistrustDate: "2019-03-01",
		Severity:     "High",
	},
	// Camerfirma (Enterprise) - Audit failures
	{
		Name:         "Camerfirma",
		SubjectCN:    "Camerfirma",
		SubjectOrg:   "Camerfirma",
		Reason:       "Audit failures and compliance issues",
		DistrustDate: "2021-09-01",
		Severity:     "Medium",
	},
}

// CheckDistrustedCA examines the certificate chain for any certificates
// issued by known distrusted/compromised Certificate Authorities.
func CheckDistrustedCA(target string) (*DistrustedCAResult, error) {
	result := &DistrustedCAResult{
		Target:        target,
		ChainPosition: make(map[string]string),
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

	// Check each certificate in the chain
	for i, cert := range state.PeerCertificates {
		fp := sha256.Sum256(cert.Raw)
		fingerprint := hex.EncodeToString(fp[:])
		result.ChainPosition[fingerprint] = cert.Subject.String()

		matched := matchDistrustedCA(cert)
		if matched != nil {
			matched.ChainPosition = i
			matched.Fingerprint = fingerprint
			result.DistrustedCAs = append(result.DistrustedCAs, *matched)
		}
	}

	result.IsDistrusted = len(result.DistrustedCAs) > 0

	if result.IsDistrusted {
		names := make([]string, len(result.DistrustedCAs))
		for i, ca := range result.DistrustedCAs {
			names[i] = ca.Name
		}
		result.Warning = fmt.Sprintf("Certificate chain contains distrusted CA(s): %s",
			strings.Join(names, ", "))
	}

	return result, nil
}

// matchDistrustedCA checks if a certificate matches any known distrusted CA.
func matchDistrustedCA(cert *x509.Certificate) *DistrustedCA {
	subject := cert.Subject.String()
	cn := cert.Subject.CommonName
	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = cert.Subject.Organization[0]
	}

	issuer := cert.Issuer.String()
	issuerCN := cert.Issuer.CommonName
	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}

	for _, entry := range distrustedCAs {
		// Match against both the cert itself and its issuer
		// (intermediates chain to distrusted roots)
		matched := false

		// Check if the certificate's subject matches
		if strings.Contains(cn, entry.SubjectCN) || strings.Contains(org, entry.SubjectOrg) {
			matched = true
		}

		// Check if the certificate's issuer matches (cert was issued by distrusted CA)
		if strings.Contains(issuerCN, entry.SubjectCN) || strings.Contains(issuerOrg, entry.SubjectOrg) {
			matched = true
		}

		// Also match on full subject/issuer strings
		if strings.Contains(subject, entry.SubjectCN) || strings.Contains(issuer, entry.SubjectCN) {
			matched = true
		}

		if matched {
			return &DistrustedCA{
				Name:         entry.Name,
				Subject:      cert.Subject.String(),
				Reason:       entry.Reason,
				DistrustDate: entry.DistrustDate,
				Severity:     entry.Severity,
			}
		}
	}

	return nil
}
