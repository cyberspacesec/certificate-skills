package pkg

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BundleCheckResult represents the result of certificate bundle completeness checking.
type BundleCheckResult struct {
	Target            string   `json:"target"`
	ChainComplete     bool     `json:"chain_complete"`
	ChainLength       int      `json:"chain_length"`
	MissingIntermediates []MissingIntermediate `json:"missing_intermediates,omitempty"`
	CanAIAFill        bool     `json:"can_aia_fill"`        // Can AIA fetch fill the gap?
	AIAFillResolved   bool     `json:"aia_fill_resolved"`   // Did AIA fetch resolve the chain?
	IssuerURLs        []string `json:"issuer_urls,omitempty"`
	Detail            string   `json:"detail,omitempty"`
}

// MissingIntermediate represents a missing intermediate certificate.
type MissingIntermediate struct {
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	AIAIssuerURL  string `json:"aia_issuer_url,omitempty"`
	FetchStatus   string `json:"fetch_status,omitempty"` // "fetched", "failed", "no_url"
}

// CheckBundleCompleteness checks if the server provides a complete certificate chain.
// If intermediates are missing, it attempts to fetch them via AIA CA Issuers URLs.
func CheckBundleCompleteness(target string) (*BundleCheckResult, error) {
	result := &BundleCheckResult{}

	conn, err := TLSDial(target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	chain := state.PeerCertificates
	leaf := chain[0]
	result.Target = target
	result.ChainLength = len(chain)

	// Collect AIA issuer URLs from the leaf
	if len(leaf.IssuingCertificateURL) > 0 {
		result.IssuerURLs = leaf.IssuingCertificateURL
	}

	// Try to verify the chain against system roots
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		intermediatePool.AddCert(chain[i])
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediatePool,
	}

	_, verifyErr := leaf.Verify(opts)
	if verifyErr == nil {
		result.ChainComplete = true
		result.Detail = "Certificate chain is complete and verifies"
		return result, nil
	}

	// Chain verification failed - try to diagnose why
	result.ChainComplete = false

	// Check if the leaf's issuer is in the chain
	issuerInChain := false
	for i := 1; i < len(chain); i++ {
		if chain[i].Subject.String() == leaf.Issuer.String() {
			issuerInChain = true
			break
		}
	}

	if !issuerInChain {
		missing := MissingIntermediate{
			Subject: leaf.Issuer.String(),
			Issuer:  leaf.Issuer.String(),
		}

		// Try to fetch the missing intermediate via AIA
		if len(leaf.IssuingCertificateURL) > 0 {
			result.CanAIAFill = true
			missing.AIAIssuerURL = leaf.IssuingCertificateURL[0]

			fetchedCert, fetchErr := fetchIntermediateFromAIA(leaf.IssuingCertificateURL[0])
			if fetchErr == nil && fetchedCert != nil {
				missing.FetchStatus = "fetched"

				// Try re-verifying with the fetched intermediate
				newPool := x509.NewCertPool()
				for i := 1; i < len(chain); i++ {
					newPool.AddCert(chain[i])
				}
				newPool.AddCert(fetchedCert)

				opts2 := x509.VerifyOptions{
					Intermediates: newPool,
				}

				_, err2 := leaf.Verify(opts2)
				if err2 == nil {
					result.AIAFillResolved = true
				}
			} else {
				missing.FetchStatus = "failed"
			}
		} else {
			missing.FetchStatus = "no_url"
			result.CanAIAFill = false
		}

		result.MissingIntermediates = append(result.MissingIntermediates, missing)
	}

	// Also check intermediates for missing issuers
	for i := 1; i < len(chain); i++ {
		cert := chain[i]
		issuerFound := false

		// Check if this intermediate's issuer is in the chain
		for j := 1; j < len(chain); j++ {
			if i != j && chain[j].Subject.String() == cert.Issuer.String() {
				issuerFound = true
				break
			}
		}

		if !issuerFound {
			// Check if this intermediate is self-signed (root)
			if cert.Subject.String() == cert.Issuer.String() {
				continue // Self-signed root, might not be in chain
			}

			// Intermediate's issuer is missing
			missing := MissingIntermediate{
				Subject: cert.Issuer.String(),
				Issuer:  cert.Issuer.String(),
			}

			if len(cert.IssuingCertificateURL) > 0 {
				missing.AIAIssuerURL = cert.IssuingCertificateURL[0]
				result.CanAIAFill = true
				missing.FetchStatus = "available"
			} else {
				missing.FetchStatus = "no_url"
			}

			result.MissingIntermediates = append(result.MissingIntermediates, missing)
		}
	}

	// Build detail string
	if result.AIAFillResolved {
		result.Detail = "Chain incomplete but can be fixed by fetching missing intermediate(s) via AIA"
	} else if len(result.MissingIntermediates) > 0 {
		subjects := make([]string, len(result.MissingIntermediates))
		for i, m := range result.MissingIntermediates {
			subjects[i] = m.Subject
		}
		result.Detail = fmt.Sprintf("Missing intermediate(s): %s", strings.Join(subjects, ", "))
	} else {
		result.Detail = fmt.Sprintf("Chain verification failed: %v", verifyErr)
	}

	return result, nil
}

// fetchIntermediateFromAIA fetches an intermediate certificate from an AIA CA Issuers URL.
func fetchIntermediateFromAIA(url string) (*x509.Certificate, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch AIA URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AIA URL returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read AIA response: %v", err)
	}

	// Try DER format first (most common for AIA)
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}

	// Try PEM format
	cert, err = parseCertFromPEM(data)
	if err == nil {
		return cert, nil
	}

	return nil, fmt.Errorf("failed to parse certificate from AIA response")
}

// parseCertFromPEM attempts to parse a certificate from PEM data.
func parseCertFromPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}
