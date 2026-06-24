package pkg

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// RevokedEntry is a revoked certificate entry.
type RevokedEntry struct {
	SerialNumber   string    `json:"serial_number"`   // Serial number of the revoked certificate
	RevocationTime time.Time `json:"revocation_time"` // Revocation time
	Reason         string    `json:"reason"`          // Revocation reason
	ReasonCode     int       `json:"reason_code"`     // Revocation reason code (RFC 5280)
}

// CRLGenerateRequest is the CRL generation request.
type CRLGenerateRequest struct {
	CACertPath   string         `json:"ca_cert_path"`  // CA certificate file path
	CAKeyPath    string         `json:"ca_key_path"`   // CA private key file path
	RevokedCerts []RevokedEntry `json:"revoked_certs"` // List of revoked certificates
	NextUpdate   int            `json:"next_update"`   // Next update time (in days, default 30)
	Number       int64          `json:"number"`        // CRL number (default 1)
	OutputPath   string         `json:"output_path"`   // CRL output path
}

// CRLGenerateResult is the CRL generation result.
type CRLGenerateResult struct {
	CRLPath      string    `json:"crl_path"`      // CRL file path
	CRLNumber    int64     `json:"crl_number"`    // CRL number
	Issuer       string    `json:"issuer"`        // Issuer
	ThisUpdate   time.Time `json:"this_update"`   // This update time
	NextUpdate   time.Time `json:"next_update"`   // Next update time
	RevokedCount int       `json:"revoked_count"` // Number of revoked certificates
	Message      string    `json:"message"`       // Result message
}

// CRL revocation reason code mapping (RFC 5280 Section 5.3.1)
var revocationReasons = map[string]int{
	"unspecified":            0,
	"key-compromise":         1,
	"ca-compromise":          2,
	"affiliation-changed":    3,
	"superseded":             4,
	"cessation-of-operation": 5,
	"certificate-hold":       6,
	"remove-from-crl":        8,
	"privilege-withdrawn":    9,
	"aa-compromise":          10,
}

// GenerateCRL generates a Certificate Revocation List.
func GenerateCRL(req CRLGenerateRequest) (*CRLGenerateResult, error) {
	// Set defaults
	if req.NextUpdate <= 0 {
		req.NextUpdate = 30 // Default: update in 30 days
	}
	if req.Number == 0 {
		req.Number = 1
	}
	if req.OutputPath == "" {
		req.OutputPath = "crl.pem"
	}

	// Load CA certificate and private key
	caCert, caSigner, err := loadCertAndSigner(req.CACertPath, req.CAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %v", err)
	}

	// Verify CA certificate has CRL signing permission
	if caCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, fmt.Errorf("CA certificate does not have CRLSign key usage")
	}

	// Build revoked certificate list
	revokedList, err := buildRevokedCertificateList(req.RevokedCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to build revoked certificate list: %v", err)
	}

	// Create CRL template
	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.Add(time.Duration(req.NextUpdate) * 24 * time.Hour)

	template := x509.RevocationList{
		RevokedCertificateEntries: revokedList,
		Number:                    big.NewInt(req.Number),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
	}

	// Sign CRL with CA private key
	crlDER, err := x509.CreateRevocationList(rand.Reader, &template, caCert, caSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %v", err)
	}

	// Save CRL to file
	crlFile, err := os.Create(req.OutputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL file: %v", err)
	}
	defer crlFile.Close()

	if err := pem.Encode(crlFile, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	}); err != nil {
		return nil, fmt.Errorf("failed to write CRL: %v", err)
	}

	result := &CRLGenerateResult{
		CRLPath:      req.OutputPath,
		CRLNumber:    req.Number,
		Issuer:       caCert.Subject.String(),
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		RevokedCount: len(revokedList),
		Message:      fmt.Sprintf("Successfully generated CRL with %d revoked certificate(s)", len(revokedList)),
	}

	return result, nil
}

// buildRevokedCertificateList builds the revoked certificate entry list.
func buildRevokedCertificateList(entries []RevokedEntry) ([]x509.RevocationListEntry, error) {
	result := make([]x509.RevocationListEntry, 0, len(entries))

	for _, entry := range entries {
		// Parse serial number
		serial := new(big.Int)
		if _, ok := serial.SetString(entry.SerialNumber, 10); !ok {
			// Try hexadecimal
			if _, ok := serial.SetString(entry.SerialNumber, 16); !ok {
				return nil, fmt.Errorf("invalid serial number: %s", entry.SerialNumber)
			}
		}

		// Get reason code
		reasonCode := entry.ReasonCode
		if reasonCode == 0 && entry.Reason != "" {
			if code, ok := revocationReasons[entry.Reason]; ok {
				reasonCode = code
			}
		}

		revocationTime := entry.RevocationTime
		if revocationTime.IsZero() {
			revocationTime = time.Now().UTC()
		}

		rle := x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revocationTime,
		}

		// Only set reason code when it is not unspecified (0)
		if reasonCode > 0 {
			rle.ReasonCode = reasonCode
		}

		result = append(result, rle)
	}

	return result, nil
}

// ParseCRL parses a CRL file.
func ParseCRL(crlPath string) (*CRLInfo, error) {
	data, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL file: %v", err)
	}

	// Try PEM format
	var crlDER []byte
	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type != "X509 CRL" {
			return nil, fmt.Errorf("expected X509 CRL PEM block, got %s", block.Type)
		}
		crlDER = block.Bytes
	} else {
		// Try DER format
		crlDER = data
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %v", err)
	}

	return buildCRLInfo(crl), nil
}

// CRLInfo is the CRL parsing information.
type CRLInfo struct {
	Issuer        string            `json:"issuer"`
	ThisUpdate    time.Time         `json:"this_update"`
	NextUpdate    time.Time         `json:"next_update"`
	Number        string            `json:"number"`
	RevokedCerts  []RevokedCertInfo `json:"revoked_certs"`
	RevokedCount  int               `json:"revoked_count"`
	SignatureAlgo string            `json:"signature_algorithm"`
}

// RevokedCertInfo is the information of a revoked certificate.
type RevokedCertInfo struct {
	SerialNumber   string    `json:"serial_number"`
	RevocationTime time.Time `json:"revocation_time"`
	Reason         string    `json:"reason"`
	ReasonCode     int       `json:"reason_code"`
}

// buildCRLInfo builds CRLInfo from an x509.RevocationList.
func buildCRLInfo(crl *x509.RevocationList) *CRLInfo {
	info := &CRLInfo{
		Issuer:        crl.Issuer.String(),
		ThisUpdate:    crl.ThisUpdate,
		NextUpdate:    crl.NextUpdate,
		SignatureAlgo: crl.SignatureAlgorithm.String(),
		RevokedCerts:  make([]RevokedCertInfo, 0),
	}

	if crl.Number != nil {
		info.Number = crl.Number.String()
	}

	for _, entry := range crl.RevokedCertificateEntries {
		reasonCode := entry.ReasonCode

		info.RevokedCerts = append(info.RevokedCerts, RevokedCertInfo{
			SerialNumber:   entry.SerialNumber.String(),
			RevocationTime: entry.RevocationTime,
			Reason:         reasonCodeToString(reasonCode),
			ReasonCode:     reasonCode,
		})
	}

	info.RevokedCount = len(info.RevokedCerts)
	return info
}

// reasonCodeToString converts a revocation reason code to a human-readable string.
func reasonCodeToString(code int) string {
	reasons := map[int]string{
		0:  "unspecified",
		1:  "key-compromise",
		2:  "ca-compromise",
		3:  "affiliation-changed",
		4:  "superseded",
		5:  "cessation-of-operation",
		6:  "certificate-hold",
		8:  "remove-from-crl",
		9:  "privilege-withdrawn",
		10: "aa-compromise",
	}
	if reason, ok := reasons[code]; ok {
		return reason
	}
	return fmt.Sprintf("unknown (%d)", code)
}

// VerifyCRLSignature verifies whether the CRL signature was issued by the specified CA certificate.
func VerifyCRLSignature(crlPath, caCertPath string) (*CRLVerifyResult, error) {
	// Load CRL
	crlData, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL file: %v", err)
	}

	var crlDER []byte
	block, _ := pem.Decode(crlData)
	if block != nil {
		crlDER = block.Bytes
	} else {
		crlDER = crlData
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %v", err)
	}

	// Load CA certificate
	caCert, err := ReadCertFromFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %v", err)
	}

	// Verify signature
	err = crl.CheckSignatureFrom(caCert)
	isValid := err == nil

	result := &CRLVerifyResult{
		IsValid:   isValid,
		CRLIssuer: crl.Issuer.String(),
		CASubject: caCert.Subject.String(),
	}

	if isValid {
		result.Message = "CRL signature is valid (signed by the provided CA)"
	} else {
		result.Message = fmt.Sprintf("CRL signature verification failed: %v", err)
	}

	return result, nil
}

// CRLVerifyResult is the CRL verification result.
type CRLVerifyResult struct {
	IsValid   bool   `json:"is_valid"`
	CRLIssuer string `json:"crl_issuer"`
	CASubject string `json:"ca_subject"`
	Message   string `json:"message"`
}

// CheckCertRevokedByCRL checks whether a certificate is revoked in a CRL.
func CheckCertRevokedByCRL(certPath, crlPath string) (*CertRevocationCheckResult, error) {
	// Load certificate
	cert, err := ReadCertFromFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	// Parse CRL
	crlInfo, err := ParseCRL(crlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %v", err)
	}

	serialStr := cert.SerialNumber.String()
	isRevoked := false
	var revocationInfo *RevokedCertInfo

	for _, revoked := range crlInfo.RevokedCerts {
		if revoked.SerialNumber == serialStr {
			isRevoked = true
			revocationInfo = &revoked
			break
		}
	}

	result := &CertRevocationCheckResult{
		CertificateSerial: serialStr,
		CRLIssuer:         crlInfo.Issuer,
		IsRevoked:         isRevoked,
	}

	if isRevoked && revocationInfo != nil {
		result.RevocationTime = revocationInfo.RevocationTime
		result.Reason = revocationInfo.Reason
		result.ReasonCode = revocationInfo.ReasonCode
		result.Message = fmt.Sprintf("Certificate IS revoked (reason: %s, time: %s)",
			revocationInfo.Reason, revocationInfo.RevocationTime.Format(time.RFC3339))
	} else {
		result.Message = "Certificate is NOT revoked in this CRL"
	}

	return result, nil
}

// CertRevocationCheckResult is the certificate revocation check result.
type CertRevocationCheckResult struct {
	CertificateSerial string    `json:"certificate_serial"`
	CRLIssuer         string    `json:"crl_issuer"`
	IsRevoked         bool      `json:"is_revoked"`
	RevocationTime    time.Time `json:"revocation_time,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	ReasonCode        int       `json:"reason_code,omitempty"`
	Message           string    `json:"message"`
}

// Ensure key types used in keyMatchesCert are imported
var (
	_ = &rsa.PublicKey{}
	_ = &ecdsa.PublicKey{}
	_ = ed25519.PublicKey{}
)
