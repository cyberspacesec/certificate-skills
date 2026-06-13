package pkg

import (
	"errors"
	"fmt"
)

// Sentinel errors for programmatic error classification.
// Library consumers can use errors.Is() to distinguish error types.
var (
	// ErrConnectionFailed indicates a TCP/TLS connection failure.
	ErrConnectionFailed = errors.New("connection failed")

	// ErrDNSResolution indicates a DNS resolution failure.
	ErrDNSResolution = errors.New("DNS resolution failed")

	// ErrCertNotFound indicates no certificate was found.
	ErrCertNotFound = errors.New("no certificate found")

	// ErrCertParseFailed indicates a certificate parsing failure.
	ErrCertParseFailed = errors.New("certificate parse failed")

	// ErrInvalidTarget indicates an invalid target (empty, malformed).
	ErrInvalidTarget = errors.New("invalid target")

	// ErrTLSTimeout indicates a TLS handshake timeout.
	ErrTLSTimeout = errors.New("TLS handshake timeout")

	// ErrOCSPFailed indicates an OCSP check failure.
	ErrOCSPFailed = errors.New("OCSP check failed")

	// ErrCRLFailed indicates a CRL check failure.
	ErrCRLFailed = errors.New("CRL check failed")

	// ErrAIAFetchFailed indicates an AIA URL fetch failure.
	ErrAIAFetchFailed = errors.New("AIA fetch failed")

	// ErrChainVerification indicates certificate chain verification failure.
	ErrChainVerification = errors.New("chain verification failed")

	// ErrFileNotFound indicates a certificate file was not found.
	ErrFileNotFound = errors.New("file not found")

	// ErrKeyMismatch indicates certificate and key do not match.
	ErrKeyMismatch = errors.New("certificate and key do not match")

	// ErrInvalidFingerprint indicates an invalid fingerprint format.
	ErrInvalidFingerprint = errors.New("invalid fingerprint format")

	// ErrCTLogSearch indicates a CT log search failure.
	ErrCTLogSearch = errors.New("CT log search failed")
)

// CertError wraps an error with a target and a sentinel error type.
// Use errors.Is(err, ErrConnectionFailed) etc. for classification.
type CertError struct {
	Target string
	Op     string
	Err    error
}

func (e *CertError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Op, e.Target, e.Err)
}

func (e *CertError) Unwrap() error {
	return e.Err
}

// NewCertError creates a new CertError wrapping a sentinel error.
func NewCertError(op, target string, err error) *CertError {
	return &CertError{Target: target, Op: op, Err: err}
}

// WrapConnectionError wraps a connection error with target context.
func WrapConnectionError(target string, err error) error {
	return NewCertError("connect", target, fmt.Errorf("%w: %v", ErrConnectionFailed, err))
}

// WrapCertParseError wraps a certificate parse error with context.
func WrapCertParseError(target string, err error) error {
	return NewCertError("parse", target, fmt.Errorf("%w: %v", ErrCertParseFailed, err))
}

// WrapOCSPError wraps an OCSP check error.
func WrapOCSPError(target string, err error) error {
	return NewCertError("ocsp", target, fmt.Errorf("%w: %v", ErrOCSPFailed, err))
}

// WrapCRLError wraps a CRL check error.
func WrapCRLError(target string, err error) error {
	return NewCertError("crl", target, fmt.Errorf("%w: %v", ErrCRLFailed, err))
}

// WrapChainError wraps a chain verification error.
func WrapChainError(target string, err error) error {
	return NewCertError("verify_chain", target, fmt.Errorf("%w: %v", ErrChainVerification, err))
}
