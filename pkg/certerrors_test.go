package pkg

import (
	"errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	sentinels := []error{
		ErrConnectionFailed,
		ErrDNSResolution,
		ErrCertNotFound,
		ErrCertParseFailed,
		ErrInvalidTarget,
		ErrTLSTimeout,
		ErrOCSPFailed,
		ErrCRLFailed,
		ErrAIAFetchFailed,
		ErrChainVerification,
		ErrFileNotFound,
		ErrKeyMismatch,
		ErrInvalidFingerprint,
		ErrCTLogSearch,
	}

	for _, sentinel := range sentinels {
		if sentinel.Error() == "" {
			t.Errorf("sentinel error %v has empty message", sentinel)
		}
	}
}

func TestCertError(t *testing.T) {
	err := NewCertError("connect", "example.com", ErrConnectionFailed)

	// Test Error() string format
	expected := "connect example.com: connection failed"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}

	// Test Unwrap() returns the inner sentinel
	if !errors.Is(err, ErrConnectionFailed) {
		t.Error("errors.Is should match ErrConnectionFailed")
	}

	// Test errors.Is does NOT match other sentinels
	if errors.Is(err, ErrCertNotFound) {
		t.Error("errors.Is should NOT match ErrCertNotFound")
	}
}

func TestWrapConnectionError(t *testing.T) {
	inner := errors.New("dial tcp: i/o timeout")
	err := WrapConnectionError("example.com", inner)

	if !errors.Is(err, ErrConnectionFailed) {
		t.Error("WrapConnectionError should wrap ErrConnectionFailed")
	}
}

func TestWrapCertParseError(t *testing.T) {
	inner := errors.New("unexpected DER")
	err := WrapCertParseError("cert.pem", inner)

	if !errors.Is(err, ErrCertParseFailed) {
		t.Error("WrapCertParseError should wrap ErrCertParseFailed")
	}
}

func TestWrapOCSPError(t *testing.T) {
	err := WrapOCSPError("example.com", errors.New("timeout"))

	if !errors.Is(err, ErrOCSPFailed) {
		t.Error("WrapOCSPError should wrap ErrOCSPFailed")
	}
}

func TestWrapCRLError(t *testing.T) {
	err := WrapCRLError("example.com", errors.New("download failed"))

	if !errors.Is(err, ErrCRLFailed) {
		t.Error("WrapCRLError should wrap ErrCRLFailed")
	}
}

func TestWrapChainError(t *testing.T) {
	err := WrapChainError("example.com", errors.New("verify failed"))

	if !errors.Is(err, ErrChainVerification) {
		t.Error("WrapChainError should wrap ErrChainVerification")
	}
}

func TestWrapFileError(t *testing.T) {
	err := WrapFileError("cert.pem", errors.New("no such file"))

	if !errors.Is(err, ErrFileNotFound) {
		t.Error("WrapFileError should wrap ErrFileNotFound")
	}
}

func TestCertErrorFields(t *testing.T) {
	err := NewCertError("parse", "test.pem", ErrCertParseFailed)

	// Use errors.As for type assertion (idiomatic Go)
	var certErr *CertError
	if !errors.As(err, &certErr) {
		t.Fatal("expected *CertError")
	}

	if certErr.Op != "parse" {
		t.Errorf("Op = %q, want %q", certErr.Op, "parse")
	}
	if certErr.Target != "test.pem" {
		t.Errorf("Target = %q, want %q", certErr.Target, "test.pem")
	}
	if certErr.Err != ErrCertParseFailed {
		t.Errorf("Err = %v, want %v", certErr.Err, ErrCertParseFailed)
	}
}
