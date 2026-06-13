package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// ChainVerifyResult represents the result of a certificate chain verification.
type ChainVerifyResult struct {
	Target          string             `json:"target"`
	IsValid         bool               `json:"is_valid"`
	ChainLength     int                `json:"chain_length"`
	TrustAnchor     string             `json:"trust_anchor,omitempty"`
	VerifiedChains  [][]CertChainEntry `json:"verified_chains"`
	Errors          []string           `json:"errors,omitempty"`
	Warnings        []string           `json:"warnings,omitempty"`
}

// CertChainEntry represents a single certificate in a verified chain.
type CertChainEntry struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	IsCA         bool   `json:"is_ca"`
	IsSelfSigned bool   `json:"is_self_signed"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	Fingerprint  string `json:"fingerprint_sha256"`
}

// VerifyCertChain performs comprehensive certificate chain verification
// against the system trust store. It returns detailed information about
// each verified chain path and any errors found.
func VerifyCertChain(target string) (*ChainVerifyResult, error) {
	result := &ChainVerifyResult{
		Target:         target,
		VerifiedChains: [][]CertChainEntry{},
		Errors:         []string{},
		Warnings:       []string{},
	}

	host, port := parseHostPort(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	// Connect with certificate verification enabled to get verified chains
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{InsecureSkipVerify: true}, // We verify manually below
	)
	if err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("TLS connection failed: %v", err))
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.ChainLength = len(state.PeerCertificates)

	if result.ChainLength == 0 {
		result.IsValid = false
		result.Errors = append(result.Errors, "No certificates found in chain")
		return result, nil
	}

	// Set trust anchor
	lastCert := state.PeerCertificates[len(state.PeerCertificates)-1]
	result.TrustAnchor = lastCert.Subject.CommonName

	// Build intermediate pool
	leafCert := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	// Verify with system roots
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		result.Warnings = append(result.Warnings, "System cert pool unavailable")
		rootCAs = x509.NewCertPool()
	}

	// First try: verify with DNS name matching
	verifyOpts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         rootCAs,
		Intermediates: intermediates,
	}

	chains, err := leafCert.Verify(verifyOpts)
	if err != nil {
		// Second try: verify without DNS name matching
		verifyOptsNoDNS := x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: intermediates,
		}
		chainsNoDNS, errNoDNS := leafCert.Verify(verifyOptsNoDNS)
		if errNoDNS == nil && len(chainsNoDNS) > 0 {
			result.IsValid = true
			result.Warnings = append(result.Warnings, "Chain is valid but name verification failed (possible hostname mismatch)")
			chains = chainsNoDNS
		} else {
			result.IsValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Chain verification failed: %v", err))

			// Also try using the chain's last cert as trust anchor (self-signed case)
			selfSignedRoots := x509.NewCertPool()
			selfSignedRoots.AddCert(lastCert)
			verifyOptsSelf := x509.VerifyOptions{
				Roots:         selfSignedRoots,
				Intermediates: intermediates,
			}
			chainsSelf, errSelf := leafCert.Verify(verifyOptsSelf)
			if errSelf == nil && len(chainsSelf) > 0 {
				result.Warnings = append(result.Warnings, "Chain is valid against its own root (self-signed or private CA)")
				chains = chainsSelf
			}
		}
	} else {
		result.IsValid = true
	}

	// Convert verified chains to our format
	for _, chain := range chains {
		var chainEntries []CertChainEntry
		for _, cert := range chain {
			fingerprints := GenerateFingerprints(cert)
			entry := CertChainEntry{
				Subject:      cert.Subject.String(),
				Issuer:       cert.Issuer.String(),
				IsCA:         cert.IsCA,
				IsSelfSigned: cert.Subject.String() == cert.Issuer.String(),
				NotBefore:    cert.NotBefore.Format(time.RFC3339),
				NotAfter:     cert.NotAfter.Format(time.RFC3339),
				Fingerprint:  fingerprints["sha256"],
			}
			chainEntries = append(chainEntries, entry)
		}
		result.VerifiedChains = append(result.VerifiedChains, chainEntries)
	}

	// Additional checks on chain certificates
	now := time.Now()
	for i, cert := range state.PeerCertificates {
		// Check for expiring certificates
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		if daysUntilExpiry <= 30 && daysUntilExpiry > 0 {
			name := cert.Subject.CommonName
			if name == "" {
				name = fmt.Sprintf("Certificate #%d in chain", i+1)
			}
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s expires in %d days", name, daysUntilExpiry))
		}

		// Check for weak signature algorithms (SHA1, MD5) in intermediate/root
		sigAlg := cert.SignatureAlgorithm.String()
		if i > 0 && (sigAlg == "SHA1WithRSA" || sigAlg == "MD5WithRSA" ||
			sigAlg == "ECDSAWithSHA1" || sigAlg == "MD2WithRSA" ||
			sigAlg == "DSAWithSHA1") {
			name := cert.Subject.CommonName
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s uses weak signature: %s", name, sigAlg))
		}
	}

	return result, nil
}
