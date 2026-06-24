package pkg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// IntermediateCARequest is the intermediate CA certificate generation request.
type IntermediateCARequest struct {
	CommonName        string   `json:"common_name"`         // Intermediate CA common name
	Organization      string   `json:"organization"`        // Organization
	Country           string   `json:"country"`             // Country
	Province          string   `json:"province"`            // Province
	Locality          string   `json:"locality"`            // Locality
	DNSNames          []string `json:"dns_names"`           // DNS names
	IPAddresses       []net.IP `json:"ip_addresses"`        // IP addresses
	ValidityDays      int      `json:"validity_days"`       // Validity period in days
	KeySize           int      `json:"key_size"`            // Key size
	KeyType           string   `json:"key_type"`            // Key type: rsa, ecdsa, ed25519
	PathLenConstraint int      `json:"path_len_constraint"` // Path length constraint (-1 = unlimited)
	OutputCertPath    string   `json:"output_cert_path"`    // Certificate output path
	OutputKeyPath     string   `json:"output_key_path"`     // Private key output path

	// Parent CA info (for signing)
	ParentCertPath string `json:"parent_cert_path"` // Parent CA certificate file path
	ParentKeyPath  string `json:"parent_key_path"`  // Parent CA private key file path
}

// SignCertRequest is the CA-signed terminal certificate request.
type SignCertRequest struct {
	CommonName     string   `json:"common_name"`      // Terminal certificate common name
	Organization   string   `json:"organization"`     // Organization
	Country        string   `json:"country"`          // Country
	Province       string   `json:"province"`         // Province
	Locality       string   `json:"locality"`         // Locality
	DNSNames       []string `json:"dns_names"`        // DNS names (SAN)
	IPAddresses    []net.IP `json:"ip_addresses"`     // IP addresses (SAN)
	ValidityDays   int      `json:"validity_days"`    // Validity period in days
	KeySize        int      `json:"key_size"`         // Key size
	KeyType        string   `json:"key_type"`         // Key type: rsa, ecdsa, ed25519
	OutputCertPath string   `json:"output_cert_path"` // Certificate output path
	OutputKeyPath  string   `json:"output_key_path"`  // Private key output path
	KeyUsage       string   `json:"key_usage"`        // Key usage: server, client, both

	// CA info (issuer)
	CACertPath string `json:"ca_cert_path"` // CA certificate file path
	CAKeyPath  string `json:"ca_key_path"`  // CA private key file path
}

// CAIssueResult is the CA signing result.
type CAIssueResult struct {
	CertificatePath string            `json:"certificate_path"`
	PrivateKeyPath  string            `json:"private_key_path"`
	CASubject       string            `json:"ca_subject"`
	IssuedSubject   string            `json:"issued_subject"`
	SerialNumber    string            `json:"serial_number"`
	NotBefore       time.Time         `json:"not_before"`
	NotAfter        time.Time         `json:"not_after"`
	Fingerprints    map[string]string `json:"fingerprints"`
	Message         string            `json:"message"`
}

// GenerateIntermediateCA generates an intermediate CA certificate (signed by parent CA).
func GenerateIntermediateCA(req IntermediateCARequest) (*CAIssueResult, error) {
	// Set defaults
	if req.KeyType == "" {
		req.KeyType = "rsa"
	}
	if req.KeySize == 0 {
		if req.KeyType == "rsa" {
			req.KeySize = 4096 // Intermediate CA defaults to 4096-bit RSA
		} else if req.KeyType == "ecdsa" {
			req.KeySize = 384 // P-384
		}
	}
	if req.ValidityDays == 0 {
		req.ValidityDays = 1825 // Intermediate CA defaults to 5-year validity
	}
	if req.CommonName == "" {
		req.CommonName = "Intermediate CA"
	}
	if req.PathLenConstraint == 0 {
		req.PathLenConstraint = 0 // Default: no further intermediate CA signing allowed
	}
	if req.OutputCertPath == "" {
		req.OutputCertPath = fmt.Sprintf("%s.pem", sanitizeFilename(req.CommonName))
	}
	if req.OutputKeyPath == "" {
		req.OutputKeyPath = fmt.Sprintf("%s-key.pem", sanitizeFilename(req.CommonName))
	}

	// Load parent CA certificate and private key
	parentCert, parentSigner, err := loadCertAndSigner(req.ParentCertPath, req.ParentKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load parent CA: %v", err)
	}

	// Verify parent certificate is a CA
	if !parentCert.IsCA {
		return nil, fmt.Errorf("parent certificate is not a CA certificate")
	}

	// Generate key pair for intermediate CA
	publicKey, _, privateKeyBytes, err := generateKeyPair(req.KeyType, req.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	// Generate random serial number
	serialNumber, err := generateRandomSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: nonEmptySlice(req.Organization, parentCert.Subject.Organization),
			Country:      nonEmptySlice(req.Country, parentCert.Subject.Country),
			Province:     nonEmptySlice(req.Province, parentCert.Subject.Province),
			Locality:     nonEmptySlice(req.Locality, parentCert.Subject.Locality),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(req.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            req.PathLenConstraint,
		MaxPathLenZero:        req.PathLenConstraint == 0,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
	}

	// Sign intermediate CA certificate using parent CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, parentCert, publicKey, parentSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate CA certificate: %v", err)
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

	result := &CAIssueResult{
		CertificatePath: req.OutputCertPath,
		PrivateKeyPath:  req.OutputKeyPath,
		CASubject:       parentCert.Subject.String(),
		IssuedSubject:   cert.Subject.String(),
		SerialNumber:    serialNumber.String(),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		Fingerprints:    fingerprints,
		Message:         fmt.Sprintf("Successfully generated intermediate CA certificate signed by %s", parentCert.Subject.CommonName),
	}

	return result, nil
}

// SignCertificate signs a terminal certificate using a CA certificate.
func SignCertificate(req SignCertRequest) (*CAIssueResult, error) {
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
	if req.CommonName == "" {
		req.CommonName = "localhost"
	}
	if req.KeyUsage == "" {
		req.KeyUsage = "server"
	}
	if req.OutputCertPath == "" {
		req.OutputCertPath = fmt.Sprintf("%s.pem", sanitizeFilename(req.CommonName))
	}
	if req.OutputKeyPath == "" {
		req.OutputKeyPath = fmt.Sprintf("%s-key.pem", sanitizeFilename(req.CommonName))
	}

	// Load CA certificate and private key
	caCert, caSigner, err := loadCertAndSigner(req.CACertPath, req.CAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %v", err)
	}

	// Verify CA certificate is a CA
	if !caCert.IsCA {
		return nil, fmt.Errorf("signer certificate is not a CA certificate")
	}

	// Generate key pair for terminal certificate
	publicKey, _, privateKeyBytes, err := generateKeyPair(req.KeyType, req.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	// Generate random serial number
	serialNumber, err := generateRandomSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: nonEmptySlice(req.Organization, caCert.Subject.Organization),
			Country:      nonEmptySlice(req.Country, caCert.Subject.Country),
			Province:     nonEmptySlice(req.Province, caCert.Subject.Province),
			Locality:     nonEmptySlice(req.Locality, caCert.Subject.Locality),
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Duration(req.ValidityDays) * 24 * time.Hour),
		DNSNames:    req.DNSNames,
		IPAddresses: req.IPAddresses,
	}

	// Set key usage and extended key usage
	switch req.KeyUsage {
	case "server":
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "both":
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return nil, fmt.Errorf("unsupported key_usage: %s (use server, client, or both)", req.KeyUsage)
	}

	// Ed25519 does not support KeyEncipherment
	if req.KeyType == "ed25519" {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	// If no DNS names specified, add CommonName
	if len(req.DNSNames) == 0 && req.CommonName != "" {
		template.DNSNames = append(template.DNSNames, req.CommonName)
	}

	// Sign terminal certificate using CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, publicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
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

	result := &CAIssueResult{
		CertificatePath: req.OutputCertPath,
		PrivateKeyPath:  req.OutputKeyPath,
		CASubject:       caCert.Subject.String(),
		IssuedSubject:   cert.Subject.String(),
		SerialNumber:    serialNumber.String(),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		Fingerprints:    fingerprints,
		Message:         fmt.Sprintf("Successfully signed certificate using CA %s", caCert.Subject.CommonName),
	}

	return result, nil
}

// --- Helper Functions ---

// generateRandomSerial generates a random certificate serial number (at least 64-bit entropy).
func generateRandomSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit random serial number
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}
	return serial, nil
}

// loadCertAndSigner loads a certificate and its corresponding private key signer from files.
func loadCertAndSigner(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	// Load certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate file %s: %v", certPath, err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM from %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Load private key
	signer, err := ReadSignerFromFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	// Verify public key match
	if !keyMatchesCert(signer, cert) {
		return nil, nil, fmt.Errorf("private key does not match certificate public key")
	}

	return cert, signer, nil
}

// keyMatchesCert verifies that the private key matches the certificate's public key.
func keyMatchesCert(signer crypto.Signer, cert *x509.Certificate) bool {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		sp, ok := signer.Public().(*rsa.PublicKey)
		if !ok {
			return false
		}
		return pub.N.Cmp(sp.N) == 0 && pub.E == sp.E
	case *ecdsa.PublicKey:
		sp, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return pub.X.Cmp(sp.X) == 0 && pub.Y.Cmp(sp.Y) == 0
	case ed25519.PublicKey:
		sp, ok := signer.Public().(ed25519.PublicKey)
		if !ok {
			return false
		}
		return pub.Equal(sp)
	default:
		return false
	}
}

// generateKeyPair generates a key pair, returning the public key, signer, and private key bytes.
func generateKeyPair(keyType string, keySize int) (crypto.PublicKey, crypto.Signer, []byte, error) {
	switch keyType {
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate RSA key: %v", err)
		}
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to marshal RSA key: %v", err)
		}
		return &privateKey.PublicKey, privateKey, pkcs8Key, nil

	case "ecdsa":
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate ECDSA key: %v", err)
		}
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to marshal ECDSA key: %v", err)
		}
		return &privateKey.PublicKey, privateKey, pkcs8Key, nil

	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate Ed25519 key: %v", err)
		}
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to marshal Ed25519 key: %v", err)
		}
		return pub, priv, pkcs8Key, nil

	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type: %s (use rsa, ecdsa, or ed25519)", keyType)
	}
}

// saveCertAndKey saves the certificate and private key to files.
func saveCertAndKey(certDER, privateKeyBytes []byte, certPath, keyPath string) error {
	// Save certificate
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	// Save private key
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}); err != nil {
		return fmt.Errorf("failed to write key: %v", err)
	}

	return nil
}

// nonEmptySlice returns a non-empty string slice, or fallback if empty.
func nonEmptySlice(val string, fallback []string) []string {
	if val != "" {
		return []string{val}
	}
	return fallback
}

// sanitizeFilename sanitizes illegal characters in filenames.
func sanitizeFilename(name string) string {
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			result = append(result, c)
		} else if c == ' ' || c == ':' || c == '/' {
			result = append(result, '_')
		}
	}
	if len(result) == 0 {
		return "cert"
	}
	return string(result)
}

// ReadSignerFromFile reads a crypto.Signer private key from a file.
func ReadSignerFromFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode key PEM")
	}

	// Try PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try EC
			key, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %v", err)
			}
		}
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T does not implement crypto.Signer", key)
	}

	return signer, nil
}
