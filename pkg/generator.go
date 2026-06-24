package pkg

import (
	"bytes"
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

// CertificateRequest is the certificate generation request.
type CertificateRequest struct {
	CommonName     string   `json:"common_name"`      // Common name
	Organization   string   `json:"organization"`     // Organization
	Country        string   `json:"country"`          // Country
	Province       string   `json:"province"`         // Province
	Locality       string   `json:"locality"`         // Locality
	DNSNames       []string `json:"dns_names"`        // DNS names
	IPAddresses    []net.IP `json:"ip_addresses"`     // IP addresses
	ValidityDays   int      `json:"validity_days"`    // Validity period in days
	KeySize        int      `json:"key_size"`         // RSA key length
	KeyType        string   `json:"key_type"`         // Key type: rsa, ecdsa, ed25519
	IsCA           bool     `json:"is_ca"`            // Whether this is a CA certificate
	OutputCertPath string   `json:"output_cert_path"` // Certificate output path
	OutputKeyPath  string   `json:"output_key_path"`  // Private key output path
}

// GenerationResult is the certificate generation result.
type GenerationResult struct {
	CertificatePath string            `json:"certificate_path"`
	PrivateKeyPath  string            `json:"private_key_path"`
	Fingerprints    map[string]string `json:"fingerprints"`
	Message         string            `json:"message"`
}

// GenerateSelfSignedCert generates a self-signed certificate.
func GenerateSelfSignedCert(req CertificateRequest) (*GenerationResult, error) {
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
	if req.OutputCertPath == "" {
		req.OutputCertPath = fmt.Sprintf("%s.pem", req.CommonName)
	}
	if req.OutputKeyPath == "" {
		req.OutputKeyPath = fmt.Sprintf("%s-key.pem", req.CommonName)
	}

	// Generate private key and public key
	var publicKey crypto.PublicKey
	var privateKeyBytes []byte

	switch req.KeyType {
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, req.KeySize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA private key: %v", err)
		}
		publicKey = &privateKey.PublicKey
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA private key: %v", err)
		}
		privateKeyBytes = pkcs8Key

	case "ecdsa":
		var curve elliptic.Curve
		switch req.KeySize {
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
			return nil, fmt.Errorf("failed to generate ECDSA private key: %v", err)
		}
		publicKey = &privateKey.PublicKey
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %v", err)
		}
		privateKeyBytes = pkcs8Key

	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ed25519 private key: %v", err)
		}
		publicKey = pub
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Ed25519 private key: %v", err)
		}
		privateKeyBytes = pkcs8Key

	default:
		return nil, NewCertError("generate", req.CommonName, fmt.Errorf("unsupported key type: %s (use rsa, ecdsa, or ed25519)", req.KeyType))
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
			Country:      []string{req.Country},
			Province:     []string{req.Province},
			Locality:     []string{req.Locality},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(req.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
	}

	// Ed25519 does not support KeyEncipherment, set DigitalSignature only
	if req.KeyType == "ed25519" {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	// If this is a CA certificate, set the corresponding attributes
	if req.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.BasicConstraintsValid = true
	}

	// If no DNS names specified, add CommonName
	if len(req.DNSNames) == 0 && req.CommonName != "" {
		template.DNSNames = append(template.DNSNames, req.CommonName)
	}

	// Generate self-signed certificate (self-signed: use own template as parent)
	// For Ed25519, the signature algorithm is automatically selected by the Go standard library
	// The actual private key must be passed in for signing
	var signer crypto.Signer
	switch req.KeyType {
	case "rsa":
		k, _ := x509.ParsePKCS8PrivateKey(privateKeyBytes)
		signer = k.(crypto.Signer)
	case "ecdsa":
		k, _ := x509.ParsePKCS8PrivateKey(privateKeyBytes)
		signer = k.(crypto.Signer)
	case "ed25519":
		k, _ := x509.ParsePKCS8PrivateKey(privateKeyBytes)
		signer = k.(crypto.Signer)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Save certificate to file
	certFile, err := os.Create(req.OutputCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to write certificate: %v", err)
	}

	// Save private key to file
	keyFile, err := os.Create(req.OutputKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key file: %v", err)
	}
	defer keyFile.Close()

	err = pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to write private key: %v", err)
	}

	// Parse certificate to generate fingerprints
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %v", err)
	}

	// Generate fingerprints
	fingerprints := GenerateFingerprints(cert)

	result := &GenerationResult{
		CertificatePath: req.OutputCertPath,
		PrivateKeyPath:  req.OutputKeyPath,
		Fingerprints:    fingerprints,
		Message:         fmt.Sprintf("Successfully generated %s certificate and private key", req.KeyType),
	}

	return result, nil
}

// GenerateCSR generates a Certificate Signing Request.
func GenerateCSR(req CertificateRequest) (string, error) {
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

	var signer crypto.Signer

	switch req.KeyType {
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, req.KeySize)
		if err != nil {
			return "", fmt.Errorf("failed to generate RSA private key: %v", err)
		}
		signer = privateKey

	case "ecdsa":
		var curve elliptic.Curve
		switch req.KeySize {
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
			return "", fmt.Errorf("failed to generate ECDSA private key: %v", err)
		}
		signer = privateKey

	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("failed to generate Ed25519 private key: %v", err)
		}
		signer = priv

	default:
		return "", fmt.Errorf("unsupported key type: %s (use rsa, ecdsa, or ed25519)", req.KeyType)
	}

	// Create CSR template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
			Country:      []string{req.Country},
			Province:     []string{req.Province},
			Locality:     []string{req.Locality},
		},
		DNSNames:    req.DNSNames,
		IPAddresses: req.IPAddresses,
	}

	// Generate CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %v", err)
	}

	// Convert to PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM), nil
}

// ValidateCertificateFiles validates the generated certificate files.
func ValidateCertificateFiles(certPath, keyPath string) error {
	// Check certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Check private key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %v", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Verify private key and certificate match
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key type does not match private key type (expected RSA)")
		}
		if priv.PublicKey.N.Cmp(rsaPublicKey.N) != 0 {
			return fmt.Errorf("RSA private key and certificate do not match")
		}

	case *ecdsa.PrivateKey:
		ecdsaPublicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key type does not match private key type (expected ECDSA)")
		}
		if priv.PublicKey.X.Cmp(ecdsaPublicKey.X) != 0 || priv.PublicKey.Y.Cmp(ecdsaPublicKey.Y) != 0 {
			return fmt.Errorf("ECDSA private key and certificate do not match")
		}

	case ed25519.PrivateKey:
		ed25519PublicKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key type does not match private key type (expected Ed25519)")
		}
		derivedPub := priv.Public().(ed25519.PublicKey)
		if !bytes.Equal(derivedPub, ed25519PublicKey) {
			return fmt.Errorf("Ed25519 private key and certificate do not match")
		}

	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	return nil
}
