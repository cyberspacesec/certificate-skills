package pkg

import (
	"encoding/pem"
	"fmt"
	"os"
)

// DownloadResult is the certificate download result.
type DownloadResult struct {
	Target      string   `json:"target"`
	SavedFiles  []string `json:"saved_files"`
	ChainLength int      `json:"chain_length"`
	Message     string   `json:"message"`
}

// DownloadCertsFromDomain downloads the certificate chain from a domain and saves it to files.
func DownloadCertsFromDomain(target string, outputDir string) (*DownloadResult, error) {
	if outputDir == "" {
		outputDir = "."
	}

	// Parse hostname for file naming
	host, _ := parseHostPort(target)

	savedFiles := []string{}

	// Connect to target to retrieve raw certificates
	conn, err := TLSDial(target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	// Save entire certificate chain to a single file
	chainPath := fmt.Sprintf("%s/%s-chain.pem", outputDir, host)
	chainFile, err := os.Create(chainPath)
	if err != nil {
		return nil, WrapFileError(chainPath, err)
	}
	defer chainFile.Close()

	for _, cert := range certs {
		err := pem.Encode(chainFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to write certificate to chain file: %v", err)
		}
	}
	savedFiles = append(savedFiles, chainPath)

	// Save leaf certificate to a separate file
	if len(certs) > 0 {
		leafPath := fmt.Sprintf("%s/%s.pem", outputDir, host)
		leafFile, err := os.Create(leafPath)
		if err != nil {
			return nil, WrapFileError(leafPath, err)
		}
		defer leafFile.Close()

		err = pem.Encode(leafFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certs[0].Raw,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to write leaf certificate: %v", err)
		}
		savedFiles = append(savedFiles, leafPath)
	}

	result := &DownloadResult{
		Target:      target,
		SavedFiles:  savedFiles,
		ChainLength: len(certs),
		Message:     fmt.Sprintf("Downloaded %d certificates for %s", len(certs), target),
	}

	return result, nil
}
