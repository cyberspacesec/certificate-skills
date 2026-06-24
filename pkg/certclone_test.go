package pkg

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCloneCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate source certificate
	srcReq := CertificateRequest{
		CommonName:     "source.example.com",
		Organization:   "Source Org",
		Country:        "US",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		DNSNames:       []string{"source.example.com", "www.source.example.com"},
		OutputCertPath: filepath.Join(tmpDir, "source.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "source-key.pem"),
	}
	GenerateSelfSignedCert(srcReq)

	// Clone the certificate
	cloneReq := CloneCertRequest{
		SourceCertPath: filepath.Join(tmpDir, "source.pem"),
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		OutputCertPath: filepath.Join(tmpDir, "cloned.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "cloned-key.pem"),
	}

	result, err := CloneCertificate(cloneReq)
	if err != nil {
		t.Fatalf("Failed to clone certificate: %v", err)
	}

	if result.OriginalSubject == "" {
		t.Error("Original subject should not be empty")
	}

	if result.ClonedSubject == "" {
		t.Error("Cloned subject should not be empty")
	}

	// Verify cloned cert has different serial
	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	clonedCert, _ := x509.ParseCertificate(block.Bytes)

	srcData, _ := os.ReadFile(filepath.Join(tmpDir, "source.pem"))
	srcBlock, _ := pem.Decode(srcData)
	srcCert, _ := x509.ParseCertificate(srcBlock.Bytes)

	if clonedCert.SerialNumber.Cmp(srcCert.SerialNumber) == 0 {
		t.Error("Cloned cert should have different serial number")
	}

	if clonedCert.Subject.CommonName != srcCert.Subject.CommonName {
		t.Errorf("Expected same CN, got cloned=%s source=%s", clonedCert.Subject.CommonName, srcCert.Subject.CommonName)
	}
}

func TestCloneCertificateWithModifiedSubject(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate source
	srcReq := CertificateRequest{
		CommonName:     "old.example.com",
		Organization:   "Old Org",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		DNSNames:       []string{"old.example.com", "www.old.example.com"},
		OutputCertPath: filepath.Join(tmpDir, "source.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "source-key.pem"),
	}
	GenerateSelfSignedCert(srcReq)

	// Clone with modified subject
	cloneReq := CloneCertRequest{
		SourceCertPath:  filepath.Join(tmpDir, "source.pem"),
		ModifySubject:   true,
		NewCommonName:   "new.example.com",
		NewOrganization: "New Org",
		KeyType:         "ecdsa",
		KeySize:         256,
		ValidityDays:    365,
		OutputCertPath:  filepath.Join(tmpDir, "cloned-mod.pem"),
		OutputKeyPath:   filepath.Join(tmpDir, "cloned-mod-key.pem"),
	}

	result, err := CloneCertificate(cloneReq)
	if err != nil {
		t.Fatalf("Failed to clone with modified subject: %v", err)
	}

	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	clonedCert, _ := x509.ParseCertificate(block.Bytes)

	if clonedCert.Subject.CommonName != "new.example.com" {
		t.Errorf("Expected CN 'new.example.com', got '%s'", clonedCert.Subject.CommonName)
	}

	// Check SAN was updated
	foundNew := false
	for _, san := range clonedCert.DNSNames {
		if san == "new.example.com" {
			foundNew = true
		}
	}
	if !foundNew {
		t.Error("Cloned cert should have new.example.com in SANs")
	}
}

func TestCloneCertificateWithCASigning(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caReq := CertificateRequest{
		CommonName:     "Clone Test CA",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
	}
	GenerateSelfSignedCert(caReq)

	// Generate source
	srcReq := CertificateRequest{
		CommonName:     "source.example.com",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		OutputCertPath: filepath.Join(tmpDir, "source.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "source-key.pem"),
	}
	GenerateSelfSignedCert(srcReq)

	// Clone with CA signing
	cloneReq := CloneCertRequest{
		SourceCertPath: filepath.Join(tmpDir, "source.pem"),
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		CACertPath:     filepath.Join(tmpDir, "ca.pem"),
		CAKeyPath:      filepath.Join(tmpDir, "ca-key.pem"),
		OutputCertPath: filepath.Join(tmpDir, "cloned-ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "cloned-ca-key.pem"),
	}

	result, err := CloneCertificate(cloneReq)
	if err != nil {
		t.Fatalf("Failed to clone with CA signing: %v", err)
	}

	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	clonedCert, _ := x509.ParseCertificate(block.Bytes)

	if clonedCert.Issuer.CommonName != "Clone Test CA" {
		t.Errorf("Expected issuer 'Clone Test CA', got '%s'", clonedCert.Issuer.CommonName)
	}
}

func TestGenerateDomainVariants(t *testing.T) {
	tmpDir := t.TempDir()

	req := DomainVariantRequest{
		BaseDomain:   "example.com",
		VariantTypes: []string{"tld"},
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
		OutputDir:    tmpDir,
	}

	result, err := GenerateDomainVariants(req)
	if err != nil {
		t.Fatalf("Failed to generate domain variants: %v", err)
	}

	if result.TotalCount == 0 {
		t.Error("Expected at least one variant")
	}

	if result.BaseDomain != "example.com" {
		t.Errorf("Expected base domain 'example.com', got '%s'", result.BaseDomain)
	}

	// Check that at least one variant was generated with a cert file
	hasCert := false
	for _, v := range result.Variants {
		if v.CertPath != "" {
			hasCert = true
			if _, err := os.Stat(v.CertPath); os.IsNotExist(err) {
				t.Errorf("Cert file %s does not exist", v.CertPath)
			}
			break
		}
	}
	if !hasCert {
		t.Error("Expected at least one variant with a generated certificate")
	}
}

func TestReplaceDNSNames(t *testing.T) {
	tests := []struct {
		dnsNames []string
		old      string
		new      string
		expected []string
	}{
		{
			[]string{"old.example.com", "www.old.example.com", "other.example.com"},
			"old.example.com",
			"new.example.com",
			[]string{"new.example.com", "www.new.example.com", "other.example.com"},
		},
		{
			[]string{"example.com"},
			"example.com",
			"new.com",
			[]string{"new.com"},
		},
	}

	for _, tc := range tests {
		result := replaceDNSNames(tc.dnsNames, tc.old, tc.new)
		if len(result) != len(tc.expected) {
			t.Errorf("replaceDNSNames(%v, %q, %q) length = %d, want %d",
				tc.dnsNames, tc.old, tc.new, len(result), len(tc.expected))
			continue
		}
		for i := range result {
			if result[i] != tc.expected[i] {
				t.Errorf("replaceDNSNames(%v, %q, %q)[%d] = %q, want %q",
					tc.dnsNames, tc.old, tc.new, i, result[i], tc.expected[i])
			}
		}
	}
}
