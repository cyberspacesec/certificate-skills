package pkg

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"
)

// CloneCertRequest is the certificate clone request.
type CloneCertRequest struct {
	SourceCertPath  string   `json:"source_cert_path"` // Source certificate file path (or domain)
	KeySize         int      `json:"key_size"`         // New key size
	KeyType         string   `json:"key_type"`         // New key type: rsa, ecdsa, ed25519
	ValidityDays    int      `json:"validity_days"`    // New validity period in days (0 = keep original)
	ModifySubject   bool     `json:"modify_subject"`   // Whether to modify subject information
	NewCommonName   string   `json:"new_common_name"`  // New common name (only when modify_subject=true)
	NewOrganization string   `json:"new_organization"` // New organization name (only when modify_subject=true)
	AddDNSNames     []string `json:"add_dns_names"`    // Additional DNS names to add
	AddIPAddresses  []net.IP `json:"add_ip_addresses"` // Additional IP addresses to add
	OutputCertPath  string   `json:"output_cert_path"` // Certificate output path
	OutputKeyPath   string   `json:"output_key_path"`  // Private key output path

	// CA signing options (optional, if provided use CA signing instead of self-signed)
	CACertPath string `json:"ca_cert_path,omitempty"` // CA certificate file path
	CAKeyPath  string `json:"ca_key_path,omitempty"`  // CA private key file path
}

// CloneCertResult is the certificate clone result.
type CloneCertResult struct {
	CertificatePath string            `json:"certificate_path"`
	PrivateKeyPath  string            `json:"private_key_path"`
	OriginalSubject string            `json:"original_subject"`
	ClonedSubject   string            `json:"cloned_subject"`
	KeyAlgorithm    string            `json:"key_algorithm"`
	KeySize         int               `json:"key_size"`
	SerialNumber    string            `json:"serial_number"`
	NotBefore       time.Time         `json:"not_before"`
	NotAfter        time.Time         `json:"not_after"`
	DNSNames        []string          `json:"dns_names"`
	Fingerprints    map[string]string `json:"fingerprints"`
	Message         string            `json:"message"`
}

// DomainVariantRequest is the domain variant generation request.
type DomainVariantRequest struct {
	BaseDomain   string   `json:"base_domain"`   // Base domain
	VariantTypes []string `json:"variant_types"` // Variant types: homoglyph, subdomain, tld, hyphenation, insertion
	KeySize      int      `json:"key_size"`      // Key size
	KeyType      string   `json:"key_type"`      // Key type
	ValidityDays int      `json:"validity_days"` // Validity period in days
	OutputDir    string   `json:"output_dir"`    // Output directory
	Organization string   `json:"organization"`  // Organization name

	// CA signing options (optional)
	CACertPath string `json:"ca_cert_path,omitempty"`
	CAKeyPath  string `json:"ca_key_path,omitempty"`
}

// DomainVariantResult is the domain variant generation result.
type DomainVariantResult struct {
	BaseDomain string         `json:"base_domain"`
	Variants   []VariantEntry `json:"variants"`
	TotalCount int            `json:"total_count"`
	Message    string         `json:"message"`
}

// VariantEntry is a single domain variant entry.
type VariantEntry struct {
	Domain       string            `json:"domain"`
	VariantType  string            `json:"variant_type"`
	CertPath     string            `json:"cert_path,omitempty"`
	KeyPath      string            `json:"key_path,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}

// CloneCertificate clones a certificate (copies subject info, generates new key and certificate).
func CloneCertificate(req CloneCertRequest) (*CloneCertResult, error) {
	// Set defaults
	if req.KeyType == "" {
		req.KeyType = "rsa"
	}
	if req.KeySize == 0 {
		if req.KeyType == "rsa" {
			req.KeySize = 2048
		} else if req.KeyType == "ecdsa" {
			req.KeySize = 256
		}
	}
	if req.ValidityDays == 0 {
		req.ValidityDays = 365
	}
	if req.OutputCertPath == "" {
		req.OutputCertPath = "cloned-cert.pem"
	}
	if req.OutputKeyPath == "" {
		req.OutputKeyPath = "cloned-cert-key.pem"
	}

	// Load source certificate
	sourceCert, err := ReadCertFromFile(req.SourceCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load source certificate: %v", err)
	}

	// Generate new key pair
	publicKey, signer, privateKeyBytes, err := generateKeyPair(req.KeyType, req.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	// Generate new random serial number (different from source certificate)
	serialNumber, err := generateRandomSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Create clone certificate template (copy most attributes from source certificate)
	originalSubject := sourceCert.Subject

	clonedSubject := originalSubject
	if req.ModifySubject {
		clonedSubject = pkix.Name{
			CommonName:   req.NewCommonName,
			Organization: nonEmptySlice(req.NewOrganization, originalSubject.Organization),
			Country:      originalSubject.Country,
			Province:     originalSubject.Province,
			Locality:     originalSubject.Locality,
		}
		if req.NewCommonName == "" {
			clonedSubject.CommonName = originalSubject.CommonName
		}
	}

	// Calculate validity period
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(req.ValidityDays) * 24 * time.Hour)

	// Merge DNS names
	dnsNames := sourceCert.DNSNames
	if req.ModifySubject && req.NewCommonName != "" {
		// Replace SANs related to original domain
		dnsNames = replaceDNSNames(dnsNames, sourceCert.Subject.CommonName, req.NewCommonName)
	}
	dnsNames = append(dnsNames, req.AddDNSNames...)

	// Merge IP addresses
	ipAddresses := sourceCert.IPAddresses
	ipAddresses = append(ipAddresses, req.AddIPAddresses...)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               clonedSubject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              sourceCert.KeyUsage,
		ExtKeyUsage:           sourceCert.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  sourceCert.IsCA,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	// If source certificate has path length constraint, copy it too
	if sourceCert.MaxPathLen > 0 {
		template.MaxPathLen = sourceCert.MaxPathLen
		template.MaxPathLenZero = sourceCert.MaxPathLenZero
	}

	// Ed25519 does not support KeyEncipherment
	if req.KeyType == "ed25519" {
		template.KeyUsage &^= x509.KeyUsageKeyEncipherment
		if template.KeyUsage == 0 {
			template.KeyUsage = x509.KeyUsageDigitalSignature
		}
	}

	// Ensure SAN is not empty
	if len(template.DNSNames) == 0 && len(template.IPAddresses) == 0 {
		template.DNSNames = append(template.DNSNames, clonedSubject.CommonName)
	}

	// Generate certificate
	var certDER []byte
	if req.CACertPath != "" && req.CAKeyPath != "" {
		// Use CA signing
		caCert, caSigner, err := loadCertAndSigner(req.CACertPath, req.CAKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA: %v", err)
		}
		certDER, err = x509.CreateCertificate(rand.Reader, &template, caCert, publicKey, caSigner)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA-signed clone certificate: %v", err)
		}
	} else {
		// Self-signed
		certDER, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey, signer)
		if err != nil {
			return nil, fmt.Errorf("failed to create self-signed clone certificate: %v", err)
		}
	}

	// Save certificate and private key
	if err := saveCertAndKey(certDER, privateKeyBytes, req.OutputCertPath, req.OutputKeyPath); err != nil {
		return nil, fmt.Errorf("failed to save certificate files: %v", err)
	}

	// Parse certificate to generate fingerprints
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %v", err)
	}

	fingerprints := GenerateFingerprints(cert)

	keyAlgorithm := fmt.Sprintf("%s (%d bits)", req.KeyType, req.KeySize)

	result := &CloneCertResult{
		CertificatePath: req.OutputCertPath,
		PrivateKeyPath:  req.OutputKeyPath,
		OriginalSubject: originalSubject.String(),
		ClonedSubject:   clonedSubject.String(),
		KeyAlgorithm:    keyAlgorithm,
		KeySize:         req.KeySize,
		SerialNumber:    serialNumber.String(),
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		DNSNames:        dnsNames,
		Fingerprints:    fingerprints,
		Message:         fmt.Sprintf("Successfully cloned certificate from %s", req.SourceCertPath),
	}

	return result, nil
}

// GenerateDomainVariants generates domain variant certificates (for security testing)
func GenerateDomainVariants(req DomainVariantRequest) (*DomainVariantResult, error) {
	// Set defaults
	if req.KeyType == "" {
		req.KeyType = "rsa"
	}
	if req.KeySize == 0 {
		req.KeySize = 2048
	}
	if req.ValidityDays == 0 {
		req.ValidityDays = 365
	}
	if len(req.VariantTypes) == 0 {
		req.VariantTypes = []string{"homoglyph", "subdomain", "tld", "hyphenation"}
	}
	if req.OutputDir == "" {
		req.OutputDir = "."
	}

	// Generate domain variants
	variants := generateDomainVariants(req.BaseDomain, req.VariantTypes)

	result := &DomainVariantResult{
		BaseDomain: req.BaseDomain,
		Variants:   make([]VariantEntry, 0),
		Message:    fmt.Sprintf("Generated %d domain variants for %s", len(variants), req.BaseDomain),
	}

	// Generate certificate for each variant
	for i, variant := range variants {
		variantCN := variant.Domain
		outputCert := fmt.Sprintf("%s/%s.pem", req.OutputDir, sanitizeFilename(variantCN))
		outputKey := fmt.Sprintf("%s/%s-key.pem", req.OutputDir, sanitizeFilename(variantCN))

		// Generate key pair
		publicKey, signer, privateKeyBytes, err := generateKeyPair(req.KeyType, req.KeySize)
		if err != nil {
			// Skip this variant, continue with others
			result.Variants = append(result.Variants, VariantEntry{
				Domain:      variantCN,
				VariantType: variant.Type,
			})
			continue
		}

		serialNumber, err := generateRandomSerial()
		if err != nil {
			result.Variants = append(result.Variants, VariantEntry{
				Domain:      variantCN,
				VariantType: variant.Type,
			})
			continue
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName:   variantCN,
				Organization: nonEmptySlice(req.Organization, []string{}),
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Duration(req.ValidityDays) * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{variantCN},
		}

		if req.KeyType == "ed25519" {
			template.KeyUsage = x509.KeyUsageDigitalSignature
		}

		var certDER []byte
		if req.CACertPath != "" && req.CAKeyPath != "" {
			caCert, caSigner, err := loadCertAndSigner(req.CACertPath, req.CAKeyPath)
			if err != nil {
				result.Variants = append(result.Variants, VariantEntry{
					Domain:      variantCN,
					VariantType: variant.Type,
				})
				continue
			}
			certDER, err = x509.CreateCertificate(rand.Reader, &template, caCert, publicKey, caSigner)
			if err != nil {
				result.Variants = append(result.Variants, VariantEntry{
					Domain:      variantCN,
					VariantType: variant.Type,
				})
				continue
			}
		} else {
			certDER, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey, signer)
			if err != nil {
				result.Variants = append(result.Variants, VariantEntry{
					Domain:      variantCN,
					VariantType: variant.Type,
				})
				continue
			}
		}

		if err := saveCertAndKey(certDER, privateKeyBytes, outputCert, outputKey); err != nil {
			result.Variants = append(result.Variants, VariantEntry{
				Domain:      variantCN,
				VariantType: variant.Type,
			})
			continue
		}

		// Generate fingerprints
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			result.Variants = append(result.Variants, VariantEntry{
				Domain:      variantCN,
				VariantType: variant.Type,
				CertPath:    outputCert,
				KeyPath:     outputKey,
			})
			continue
		}

		result.Variants = append(result.Variants, VariantEntry{
			Domain:       variantCN,
			VariantType:  variant.Type,
			CertPath:     outputCert,
			KeyPath:      outputKey,
			Fingerprints: GenerateFingerprints(cert),
		})

		// Limit to 50 variants to avoid disk space issues
		if i >= 49 {
			result.Message = fmt.Sprintf("Generated 50 domain variants for %s (limited to 50)", req.BaseDomain)
			break
		}
	}

	result.TotalCount = len(result.Variants)
	return result, nil
}

// domainVariant is the internal structure for domain variants
type domainVariant struct {
	Domain string
	Type   string
}

// generateDomainVariants generates a list of domain variants
func generateDomainVariants(baseDomain string, types []string) []domainVariant {
	variants := make([]domainVariant, 0)

	// Split domain
	parts := strings.Split(baseDomain, ".")
	if len(parts) < 2 {
		return []domainVariant{{Domain: baseDomain, Type: "original"}}
	}
	subdomain := strings.Join(parts[:len(parts)-1], ".")
	tld := strings.Join(parts[len(parts)-1:], ".")

	for _, t := range types {
		switch t {
		case "homoglyph":
			// Homoglyph substitution (visually similar characters)
			variants = append(variants, generateHomoglyphVariants(baseDomain, subdomain, tld)...)

		case "subdomain":
			// Subdomain variants
			variants = append(variants, generateSubdomainVariants(baseDomain, tld)...)

		case "tld":
			// TLD variants
			variants = append(variants, generateTLDVariants(subdomain)...)

		case "hyphenation":
			// Hyphenation variants
			variants = append(variants, generateHyphenVariants(subdomain, tld)...)

		case "insertion":
			// Character insertion variants
			variants = append(variants, generateInsertionVariants(subdomain, tld)...)
		}
	}

	return variants
}

// homoglyphMap is the homoglyph mapping table (common Unicode substitution characters)
var homoglyphMap = map[rune][]rune{
	'a': {'à', 'á', 'â', 'ä', 'ɑ'}, // Latin/Alpha
	'e': {'è', 'é', 'ê', 'ë', 'ε'}, // Latin/Epsilon
	'i': {'ì', 'í', 'î', 'ï', 'ɩ'}, // Latin/Iota
	'o': {'ò', 'ó', 'ô', 'ö', 'ο'}, // Latin/Omicron
	'u': {'ù', 'ú', 'û', 'ü'},
	'c': {'ϲ', 'ç'}, // Greek/C-cedilla
	'k': {'κ'},      // Greek Kappa
	'l': {'ӏ', 'ł'}, // Cyrillic/L with stroke
	'n': {'η', 'ñ'}, // Greek Eta
	's': {'ѕ'},      // Cyrillic s
	't': {'τ'},      // Greek Tau
	'0': {'ο', 'ο'}, // Omicron as zero
}

// generateHomoglyphVariants generates homoglyph variants
func generateHomoglyphVariants(baseDomain, subdomain, tld string) []domainVariant {
	variants := make([]domainVariant, 0)

	// Try replacing each character in the subdomain
	for i, c := range subdomain {
		if replacements, ok := homoglyphMap[c]; ok {
			for _, r := range replacements {
				newSub := subdomain[:i] + string(r) + subdomain[i+1:]
				variants = append(variants, domainVariant{
					Domain: newSub + "." + tld,
					Type:   "homoglyph",
				})
			}
		}
	}

	// Limit count
	if len(variants) > 10 {
		variants = variants[:10]
	}

	return variants
}

// generateSubdomainVariants generates subdomain variants
func generateSubdomainVariants(baseDomain, tld string) []domainVariant {
	prefixes := []string{"www", "mail", "ftp", "admin", "test", "dev", "staging", "api", "vpn", "cdn"}
	variants := make([]domainVariant, 0, len(prefixes))

	// Split existing subdomain
	parts := strings.Split(baseDomain, ".")
	base := parts[0]
	rest := strings.Join(parts[1:], ".")

	for _, prefix := range prefixes {
		variants = append(variants, domainVariant{
			Domain: prefix + "." + base + "." + rest,
			Type:   "subdomain",
		})
	}

	return variants
}

// generateTLDVariants generates TLD variants
func generateTLDVariants(subdomain string) []domainVariant {
	commonTLDs := []string{"com", "net", "org", "io", "co", "info", "biz", "xyz", "cc", "ru", "cn", "tk"}
	variants := make([]domainVariant, 0, len(commonTLDs))

	for _, tld := range commonTLDs {
		variants = append(variants, domainVariant{
			Domain: subdomain + "." + tld,
			Type:   "tld",
		})
	}

	return variants
}

// generateHyphenVariants generates hyphenation variants
func generateHyphenVariants(subdomain, tld string) []domainVariant {
	variants := make([]domainVariant, 0)

	// Insert hyphens at different positions in the subdomain
	for i := 1; i < len(subdomain); i++ {
		if subdomain[i-1] != '-' && subdomain[i] != '-' {
			newSub := subdomain[:i] + "-" + subdomain[i:]
			variants = append(variants, domainVariant{
				Domain: newSub + "." + tld,
				Type:   "hyphenation",
			})
		}
	}

	// Limit count
	if len(variants) > 10 {
		variants = variants[:10]
	}

	return variants
}

// generateInsertionVariants generates character insertion variants
func generateInsertionVariants(subdomain, tld string) []domainVariant {
	variants := make([]domainVariant, 0)

	// Insert single characters at different positions in the subdomain
	insertChars := []string{"s", "x", "z", "o", "e"}

	for _, c := range insertChars {
		// Insert at the end
		variants = append(variants, domainVariant{
			Domain: subdomain + c + "." + tld,
			Type:   "insertion",
		})
		// Insert at the beginning
		variants = append(variants, domainVariant{
			Domain: c + subdomain + "." + tld,
			Type:   "insertion",
		})
	}

	return variants
}

// replaceDNSNames replaces the old domain with the new domain in DNS names
func replaceDNSNames(dnsNames []string, oldDomain, newDomain string) []string {
	result := make([]string, 0, len(dnsNames))
	for _, name := range dnsNames {
		if name == oldDomain {
			result = append(result, newDomain)
		} else if strings.HasSuffix(name, "."+oldDomain) {
			sub := strings.TrimSuffix(name, "."+oldDomain)
			result = append(result, sub+"."+newDomain)
		} else {
			result = append(result, name)
		}
	}
	return result
}
