package pkg

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// RevocationResult represents the result of a certificate revocation check.
type RevocationResult struct {
	Target         string     `json:"target"`
	OCSPStatus     OCSPStatus `json:"ocsp_status"`
	CRLStatus      CRLStatus  `json:"crl_status"`
	OverallStatus  string     `json:"overall_status"`
	RevocationInfo string     `json:"revocation_info,omitempty"`
	Error          string     `json:"error,omitempty"`
}

// OCSPStatus represents the result of an OCSP check.
type OCSPStatus struct {
	Checked          bool   `json:"checked"`
	Status           string `json:"status"` // Good, Revoked, Unknown
	RevokedAt        string `json:"revoked_at,omitempty"`
	RevocationReason string `json:"revocation_reason,omitempty"`
	ThisUpdate       string `json:"this_update,omitempty"`
	NextUpdate       string `json:"next_update,omitempty"`
	OCSPURL          string `json:"ocsp_url,omitempty"`
	Error            string `json:"error,omitempty"`
}

// CRLStatus represents the result of a CRL check.
type CRLStatus struct {
	Checked        bool     `json:"checked"`
	Status         string   `json:"status"` // Good, Revoked, Unknown
	RevokedSerials []string `json:"revoked_serials,omitempty"`
	CRLURL         string   `json:"crl_url,omitempty"`
	ThisUpdate     string   `json:"this_update,omitempty"`
	NextUpdate     string   `json:"next_update,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// CheckRevocation checks the revocation status of a certificate
// using both OCSP and CRL methods.
//
// For a domain target, it connects to the server and checks the leaf certificate.
// For a file target, it reads the certificate from the file.
func CheckRevocation(target string) (*RevocationResult, error) {
	result := &RevocationResult{
		Target: target,
	}

	var cert *x509.Certificate
	var issuer *x509.Certificate

	if IsFileTarget(target) {
		// Read certificate from file
		parsedCert, err := ReadCertFromFile(target)
		if err != nil {
			result.Error = fmt.Sprintf("failed to read certificate: %v", err)
			return result, nil
		}
		cert = parsedCert

		// For file-based checks, we don't have the issuer certificate
		// We can still check CRL, but OCSP requires the issuer
	} else {
		// Connect to the domain and get the certificate chain
		conn, err := TLSDial(target)
		if err != nil {
			result.Error = fmt.Sprintf("failed to connect: %v", err)
			return result, nil
		}
		defer conn.Close()

		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			result.Error = "no certificates found"
			return result, nil
		}

		cert = state.PeerCertificates[0]
		if len(state.PeerCertificates) > 1 {
			issuer = state.PeerCertificates[1]
		}
	}

	// Check OCSP
	result.OCSPStatus = checkOCSP(cert, issuer)

	// Check CRL
	result.CRLStatus = checkCRL(cert)

	// Determine overall status
	result.OverallStatus = determineOverallStatus(result.OCSPStatus, result.CRLStatus)

	return result, nil
}

// checkOCSP performs an OCSP check for the given certificate.
func checkOCSP(cert *x509.Certificate, issuer *x509.Certificate) OCSPStatus {
	status := OCSPStatus{}

	// Get OCSP server URL from certificate
	if len(cert.OCSPServer) == 0 {
		status.Error = "no OCSP server URL in certificate"
		return status
	}

	status.OCSPURL = cert.OCSPServer[0]
	status.Checked = true

	// We need the issuer certificate to create the OCSP request
	if issuer == nil {
		status.Status = "Unknown"
		status.Error = "issuer certificate not available (required for OCSP)"
		return status
	}

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(issuer, cert, &ocsp.RequestOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		status.Status = "Unknown"
		status.Error = fmt.Sprintf("failed to create OCSP request: %v", err)
		return status
	}

	// Send OCSP request via HTTP
	ocspURL := cert.OCSPServer[0]
	req, err := http.NewRequest("POST", ocspURL, nil)
	if err != nil {
		status.Status = "Unknown"
		status.Error = fmt.Sprintf("failed to create HTTP request: %v", err)
		return status
	}

	// Some OCSP servers accept GET with base64-encoded request
	getURL := fmt.Sprintf("%s/%s", ocspURL, base64.StdEncoding.EncodeToString(ocspReq))
	req, err = http.NewRequest("GET", getURL, nil)
	if err != nil {
		status.Status = "Unknown"
		status.Error = fmt.Sprintf("failed to create HTTP GET request: %v", err)
		return status
	}
	req.Header.Set("User-Agent", "cert-hacker/1.0")
	req.Header.Set("Accept", "application/ocsp-response")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		status.Status = "Unknown"
		status.Error = fmt.Sprintf("OCSP request failed: %v", err)
		return status
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		status.Status = "Unknown"
		status.Error = fmt.Sprintf("failed to read OCSP response: %v", err)
		return status
	}

	// Parse OCSP response
	ocspResp, err := ocsp.ParseResponse(respBody, issuer)
	if err != nil {
		status.Status = "Unknown"
		status.Error = fmt.Sprintf("failed to parse OCSP response: %v", err)
		return status
	}

	// Map OCSP status
	switch ocspResp.Status {
	case ocsp.Good:
		status.Status = "Good"
	case ocsp.Revoked:
		status.Status = "Revoked"
		status.RevokedAt = ocspResp.RevokedAt.Format(time.RFC3339)
		status.RevocationReason = revocationReasonString(ocspResp.RevocationReason)
	case ocsp.Unknown:
		status.Status = "Unknown"
	default:
		status.Status = "Unknown"
	}

	if !ocspResp.ThisUpdate.IsZero() {
		status.ThisUpdate = ocspResp.ThisUpdate.Format(time.RFC3339)
	}
	if !ocspResp.NextUpdate.IsZero() {
		status.NextUpdate = ocspResp.NextUpdate.Format(time.RFC3339)
	}

	return status
}

// checkCRL performs a CRL check for the given certificate.
func checkCRL(cert *x509.Certificate) CRLStatus {
	status := CRLStatus{}

	// Get CRL Distribution Points from certificate
	if len(cert.CRLDistributionPoints) == 0 {
		status.Error = "no CRL Distribution Points in certificate"
		return status
	}

	status.CRLURL = cert.CRLDistributionPoints[0]
	status.Checked = true

	// Download the CRL
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", cert.CRLDistributionPoints[0], nil)
	if err != nil {
		status.Status = "Unknown"
		status.Error = fmt.Sprintf("failed to create CRL request: %v", err)
		return status
	}
	req.Header.Set("User-Agent", "cert-hacker/1.0")

	resp, err := client.Do(req)
	if err != nil {
		status.Status = "Unknown"
		status.Error = fmt.Sprintf("CRL download failed: %v", err)
		return status
	}
	defer resp.Body.Close()

	crlData, err := io.ReadAll(resp.Body)
	if err != nil {
		status.Status = "Unknown"
		status.Error = fmt.Sprintf("failed to read CRL data: %v", err)
		return status
	}

	// Parse the CRL
	crl, err := x509.ParseRevocationList(crlData)
	if err != nil {
		// Try PEM decoding first
		block, _ := pem.Decode(crlData)
		if block != nil {
			crl, err = x509.ParseRevocationList(block.Bytes)
		}
		if err != nil {
			status.Status = "Unknown"
			status.Error = fmt.Sprintf("failed to parse CRL: %v", err)
			return status
		}
	}

	// Check if the certificate's serial number is in the CRL
	certSerial := cert.SerialNumber
	isRevoked := false

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(certSerial) == 0 {
			isRevoked = true
			status.RevokedSerials = append(status.RevokedSerials, revoked.SerialNumber.String())
		}
	}

	if isRevoked {
		status.Status = "Revoked"
	} else {
		status.Status = "Good"
	}

	if !crl.ThisUpdate.IsZero() {
		status.ThisUpdate = crl.ThisUpdate.Format(time.RFC3339)
	}
	if !crl.NextUpdate.IsZero() {
		status.NextUpdate = crl.NextUpdate.Format(time.RFC3339)
	}

	return status
}

// determineOverallStatus determines the overall revocation status
// based on OCSP and CRL results.
func determineOverallStatus(ocsp OCSPStatus, crl CRLStatus) string {
	// If either says revoked, it's revoked
	if ocsp.Status == "Revoked" || crl.Status == "Revoked" {
		return "Revoked"
	}

	// If both say good, it's good
	if ocsp.Status == "Good" && crl.Status == "Good" {
		return "Good"
	}

	// If one says good and other is unknown, lean towards good
	if ocsp.Status == "Good" || crl.Status == "Good" {
		return "Good"
	}

	// Both unknown or unavailable
	return "Unknown"
}

// revocationReasonString converts a CRL revocation reason code to a string.
func revocationReasonString(reason int) string {
	reasons := map[int]string{
		0:  "unspecified",
		1:  "key compromise",
		2:  "CA compromise",
		3:  "affiliation changed",
		4:  "superseded",
		5:  "cessation of operation",
		6:  "certificate hold",
		8:  "remove from CRL",
		9:  "privilege withdrawn",
		10: "AA compromise",
	}

	if r, ok := reasons[reason]; ok {
		return r
	}
	return fmt.Sprintf("unknown reason (%d)", reason)
}
