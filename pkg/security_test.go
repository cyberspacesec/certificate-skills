package pkg

import (
	"os"
	"testing"
)

func TestAnalyzeSecurity_ScoreCalculation(t *testing.T) {
	analysis := &SecurityAnalysis{
		Issues: []SecurityIssue{
			{Severity: "Critical", Type: "Test", Description: "test", Impact: "test"},
			{Severity: "High", Type: "Test", Description: "test", Impact: "test"},
			{Severity: "Medium", Type: "Test", Description: "test", Impact: "test"},
			{Severity: "Low", Type: "Test", Description: "test", Impact: "test"},
		},
	}

	analysis.calculateOverallScore()

	expectedScore := 100 - 30 - 20 - 10 - 5 // = 35
	if analysis.OverallScore != expectedScore {
		t.Errorf("Score should be %d, got %d", expectedScore, analysis.OverallScore)
	}

	if analysis.SecurityLevel != "Critical" {
		t.Errorf("SecurityLevel should be Critical for score 35, got %s", analysis.SecurityLevel)
	}
}

func TestAnalyzeSecurity_ScoreFloor(t *testing.T) {
	analysis := &SecurityAnalysis{
		Issues: []SecurityIssue{
			{Severity: "Critical", Type: "Test1", Description: "test", Impact: "test"},
			{Severity: "Critical", Type: "Test2", Description: "test", Impact: "test"},
			{Severity: "Critical", Type: "Test3", Description: "test", Impact: "test"},
			{Severity: "Critical", Type: "Test4", Description: "test", Impact: "test"},
		},
	}

	analysis.calculateOverallScore()

	if analysis.OverallScore < 0 {
		t.Errorf("Score should not be negative, got %d", analysis.OverallScore)
	}
	if analysis.OverallScore != 0 {
		t.Errorf("Score should be clamped to 0, got %d", analysis.OverallScore)
	}
}

func TestAnalyzeSecurity_ScoreGood(t *testing.T) {
	analysis := &SecurityAnalysis{
		Issues: []SecurityIssue{},
	}

	analysis.calculateOverallScore()

	if analysis.OverallScore != 100 {
		t.Errorf("Score should be 100 with no issues, got %d", analysis.OverallScore)
	}
	if analysis.SecurityLevel != "Good" {
		t.Errorf("SecurityLevel should be Good for score 100, got %s", analysis.SecurityLevel)
	}
}

func TestAnalyzeSecurity_InvalidDomain(t *testing.T) {
	_, err := AnalyzeSecurity("this-domain-does-not-exist-xyz123.invalid")
	if err == nil {
		t.Error("Expected error for invalid domain")
	}
}

func TestBatchAnalyzeSecurity(t *testing.T) {
	// Use a simple test that doesn't require network - just verify the structure
	targets := []string{"this-domain-does-not-exist-xyz123.invalid"}
	result := BatchAnalyzeSecurity(targets)

	if result.TotalCount != 1 {
		t.Errorf("TotalCount should be 1, got %d", result.TotalCount)
	}

	if len(result.Results) == 0 {
		t.Error("Results should not be empty")
	}

	// The failed domain should have SecurityLevel "Error"
	if result.Results[0].SecurityLevel != "Error" {
		t.Errorf("Failed domain should have SecurityLevel Error, got %s", result.Results[0].SecurityLevel)
	}

	if result.Summary.CriticalCount != 1 {
		t.Errorf("CriticalCount should be 1 for failed domain, got %d", result.Summary.CriticalCount)
	}
}

func TestAnalyzeCertificate_SelfSigned(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-selfsigned",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	certInfo, err := GetCertFromFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("GetCertFromFile failed: %v", err)
	}

	// Self-signed cert should have Subject == Issuer
	if certInfo.Subject != certInfo.Issuer {
		t.Errorf("Self-signed cert should have Subject == Issuer, got Subject=%s Issuer=%s", certInfo.Subject, certInfo.Issuer)
	}
}
