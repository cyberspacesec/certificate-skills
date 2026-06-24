package pkg

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"net"
	"sort"
)

// TLSExtensionInfo is a compact inventory record for one X.509 extension.
type TLSExtensionInfo struct {
	OID       string `json:"oid"`
	Name      string `json:"name,omitempty"`
	Critical  bool   `json:"critical"`
	Known     bool   `json:"known"`
	RawLength int    `json:"raw_length"`
}

// BasicConstraintsInfo summarizes CA path-length constraints.
type BasicConstraintsInfo struct {
	IsCA              bool `json:"is_ca"`
	MaxPathLen        int  `json:"max_path_len,omitempty"`
	MaxPathLenPresent bool `json:"max_path_len_present"`
}

// NameConstraintInfo summarizes parsed name constraints.
type NameConstraintInfo struct {
	PermittedDNSDomains     []string `json:"permitted_dns_domains,omitempty"`
	ExcludedDNSDomains      []string `json:"excluded_dns_domains,omitempty"`
	PermittedEmailAddresses []string `json:"permitted_email_addresses,omitempty"`
	ExcludedEmailAddresses  []string `json:"excluded_email_addresses,omitempty"`
	PermittedURIDomains     []string `json:"permitted_uri_domains,omitempty"`
	ExcludedURIDomains      []string `json:"excluded_uri_domains,omitempty"`
	PermittedIPRanges       []string `json:"permitted_ip_ranges,omitempty"`
	ExcludedIPRanges        []string `json:"excluded_ip_ranges,omitempty"`
}

// CertificateExtensionInfo exposes parsed extension details used by mapping pipelines.
type CertificateExtensionInfo struct {
	Extensions        []TLSExtensionInfo        `json:"extensions"`
	UnknownCritical   []TLSExtensionInfo        `json:"unknown_critical,omitempty"`
	SubjectKeyID      string                    `json:"subject_key_id,omitempty"`
	AuthorityKeyID    string                    `json:"authority_key_id,omitempty"`
	KeyUsage          []string                  `json:"key_usage,omitempty"`
	ExtKeyUsage       []string                  `json:"ext_key_usage,omitempty"`
	UnknownExtKeyOID  []string                  `json:"unknown_ext_key_oid,omitempty"`
	BasicConstraints  BasicConstraintsInfo      `json:"basic_constraints"`
	DNSNames          []string                  `json:"dns_names,omitempty"`
	IPAddresses       []string                  `json:"ip_addresses,omitempty"`
	EmailAddresses    []string                  `json:"email_addresses,omitempty"`
	URIs              []string                  `json:"uris,omitempty"`
	OCSPServers       []string                  `json:"ocsp_servers,omitempty"`
	IssuingCertURLs   []string                  `json:"issuing_cert_urls,omitempty"`
	CRLDistribution   []string                  `json:"crl_distribution_points,omitempty"`
	PolicyOIDs        []string                  `json:"policy_oids,omitempty"`
	Policies          []PolicyOID               `json:"policies,omitempty"`
	NameConstraints   NameConstraintInfo        `json:"name_constraints,omitempty"`
	HasSCT            bool                      `json:"has_sct"`
	SCTCount          int                       `json:"sct_count"`
	SCTs              []SCTEntry                `json:"scts,omitempty"`
	HasOCSPMustStaple bool                      `json:"has_ocsp_must_staple"`
	RawByOID          map[string]pkix.Extension `json:"-"`
}

// AnalyzeCertificateExtensions returns a no-network extension inventory for a certificate.
func AnalyzeCertificateExtensions(cert *x509.Certificate) CertificateExtensionInfo {
	if cert == nil {
		return CertificateExtensionInfo{}
	}

	info := CertificateExtensionInfo{
		Extensions:       make([]TLSExtensionInfo, 0, len(cert.Extensions)),
		RawByOID:         make(map[string]pkix.Extension, len(cert.Extensions)),
		SubjectKeyID:     hex.EncodeToString(cert.SubjectKeyId),
		AuthorityKeyID:   hex.EncodeToString(cert.AuthorityKeyId),
		KeyUsage:         parseKeyUsage(cert.KeyUsage),
		ExtKeyUsage:      parseExtKeyUsage(cert.ExtKeyUsage),
		DNSNames:         normalizeDomains(cert.DNSNames),
		IPAddresses:      normalizeIPs(cert.IPAddresses),
		EmailAddresses:   sortedStrings(cert.EmailAddresses),
		OCSPServers:      sortedStrings(cert.OCSPServer),
		IssuingCertURLs:  sortedStrings(cert.IssuingCertificateURL),
		CRLDistribution:  sortedStrings(cert.CRLDistributionPoints),
		BasicConstraints: BasicConstraintsInfo{IsCA: cert.IsCA, MaxPathLen: cert.MaxPathLen, MaxPathLenPresent: cert.MaxPathLenZero || cert.MaxPathLen > 0},
		PolicyOIDs:       objectIdentifierStrings(cert.PolicyIdentifiers),
		NameConstraints:  certificateNameConstraints(cert),
	}

	for _, uri := range cert.URIs {
		if uri != nil {
			info.URIs = append(info.URIs, uri.String())
		}
	}
	sort.Strings(info.URIs)

	for _, oid := range cert.UnknownExtKeyUsage {
		info.UnknownExtKeyOID = append(info.UnknownExtKeyOID, oid.String())
	}
	sort.Strings(info.UnknownExtKeyOID)

	for _, oid := range cert.PolicyIdentifiers {
		oidStr := oid.String()
		if known, ok := knownPolicyOIDs[oidStr]; ok {
			info.Policies = append(info.Policies, known)
		} else {
			info.Policies = append(info.Policies, PolicyOID{OID: oidStr, Type: "Unknown", Description: "Unknown policy OID"})
		}
	}

	scts := parseEmbeddedSCTs(cert)
	info.SCTs = scts
	info.SCTCount = len(scts)
	info.HasSCT = len(scts) > 0
	info.HasOCSPMustStaple = hasMustStapleExtension(cert)

	for _, ext := range cert.Extensions {
		oid := ext.Id.String()
		record := TLSExtensionInfo{
			OID:       oid,
			Name:      extensionName(ext.Id),
			Critical:  ext.Critical,
			Known:     extensionName(ext.Id) != "",
			RawLength: len(ext.Value),
		}
		info.Extensions = append(info.Extensions, record)
		info.RawByOID[oid] = ext
		if ext.Critical && !record.Known {
			info.UnknownCritical = append(info.UnknownCritical, record)
		}
	}

	sort.Slice(info.Extensions, func(i, j int) bool {
		return info.Extensions[i].OID < info.Extensions[j].OID
	})
	sort.Slice(info.UnknownCritical, func(i, j int) bool {
		return info.UnknownCritical[i].OID < info.UnknownCritical[j].OID
	})

	return info
}

func extensionName(oid asn1.ObjectIdentifier) string {
	names := map[string]string{
		"2.5.29.14":               "Subject Key Identifier",
		"2.5.29.15":               "Key Usage",
		"2.5.29.17":               "Subject Alternative Name",
		"2.5.29.19":               "Basic Constraints",
		"2.5.29.30":               "Name Constraints",
		"2.5.29.31":               "CRL Distribution Points",
		"2.5.29.32":               "Certificate Policies",
		"2.5.29.35":               "Authority Key Identifier",
		"2.5.29.37":               "Extended Key Usage",
		"1.3.6.1.5.5.7.1.1":       "Authority Information Access",
		"1.3.6.1.5.5.7.1.24":      "TLS Feature",
		"1.3.6.1.4.1.11129.2.4.2": "Signed Certificate Timestamp List",
	}
	return names[oid.String()]
}

func objectIdentifierStrings(oids []asn1.ObjectIdentifier) []string {
	values := make([]string, 0, len(oids))
	for _, oid := range oids {
		values = append(values, oid.String())
	}
	sort.Strings(values)
	return values
}

func certificateNameConstraints(cert *x509.Certificate) NameConstraintInfo {
	return NameConstraintInfo{
		PermittedDNSDomains:     sortedStrings(cert.PermittedDNSDomains),
		ExcludedDNSDomains:      sortedStrings(cert.ExcludedDNSDomains),
		PermittedEmailAddresses: sortedStrings(cert.PermittedEmailAddresses),
		ExcludedEmailAddresses:  sortedStrings(cert.ExcludedEmailAddresses),
		PermittedURIDomains:     sortedStrings(cert.PermittedURIDomains),
		ExcludedURIDomains:      sortedStrings(cert.ExcludedURIDomains),
		PermittedIPRanges:       ipNetsToStrings(cert.PermittedIPRanges),
		ExcludedIPRanges:        ipNetsToStrings(cert.ExcludedIPRanges),
	}
}

func ipNetsToStrings(values []*net.IPNet) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != nil {
			out = append(out, value.String())
		}
	}
	sort.Strings(out)
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
