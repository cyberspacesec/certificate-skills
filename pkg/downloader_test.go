package pkg

import (
	"os"
	"testing"
)

func TestDownloadResult_Fields(t *testing.T) {
	result := &DownloadResult{
		Target:      "example.com:443",
		SavedFiles:  []string{"/tmp/example.com-chain.pem", "/tmp/example.com.pem"},
		ChainLength: 3,
		Message:     "Downloaded 3 certificates for example.com:443",
	}
	if result.Target != "example.com:443" {
		t.Error("Target mismatch")
	}
	if result.ChainLength != 3 {
		t.Error("ChainLength mismatch")
	}
	if len(result.SavedFiles) != 2 {
		t.Error("Expected 2 saved files")
	}
}

func TestDownloadCertsFromDomainLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "cert-download-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	result, err := DownloadCertsFromDomain("google.com:443", tmpDir)
	if err != nil {
		t.Fatalf("DownloadCertsFromDomain failed: %v", err)
	}
	if result.ChainLength == 0 {
		t.Error("Expected non-zero chain length")
	}
	if len(result.SavedFiles) == 0 {
		t.Error("Expected saved files")
	}

	// Verify files exist
	for _, f := range result.SavedFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			t.Errorf("File %s should exist", f)
		}
	}
}

func TestDownloadCertsFromDomain_EmptyOutputDir(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	// When outputDir is empty, it should default to current directory
	// We test this by providing "." as output dir
	result, err := DownloadCertsFromDomain("google.com:443", ".")
	if err != nil {
		t.Fatalf("DownloadCertsFromDomain failed: %v", err)
	}
	// Clean up downloaded files
	for _, f := range result.SavedFiles {
		os.Remove(f)
	}
}
