package pkg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// DialOptions controls TLS connection behavior.
type DialOptions struct {
	// Timeout is the maximum time to wait for a connection.
	// Defaults to 10 seconds if zero.
	Timeout time.Duration

	// TLSConfig is an optional base TLS config.
	// If nil, a default config with InsecureSkipVerify=true is used
	// (because we analyze certificates, not validate them).
	TLSConfig *tls.Config
}

// defaultDialOptions returns the default dial options.
func defaultDialOptions() DialOptions {
	return DialOptions{
		Timeout: 10 * time.Second,
	}
}

// TLSDialWithContext establishes a TLS connection to the target with context support.
// It parses the target (host:port), applies the given options, and returns the
// established *tls.Conn. The caller must close the connection.
//
// InsecureSkipVerify is set to true by default because this toolkit analyzes
// certificates rather than validates them — we need to connect even if the
// certificate chain is invalid.
func TLSDialWithContext(ctx context.Context, target string, opts DialOptions) (*tls.Conn, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	host, port := parseHostPort(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	tlsConfig := opts.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	dialer := &net.Dialer{Timeout: opts.Timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, WrapConnectionError(target, err)
	}

	return conn, nil
}

// TLSDial establishes a TLS connection to the target using default options.
// This is the primary connection function used throughout the toolkit.
func TLSDial(target string) (*tls.Conn, error) {
	return TLSDialWithContext(context.Background(), target, defaultDialOptions())
}

// TLSDialWithConfig establishes a TLS connection with a custom TLS config.
func TLSDialWithConfig(target string, tlsConfig *tls.Config) (*tls.Conn, error) {
	return TLSDialWithContext(context.Background(), target, DialOptions{
		Timeout:   10 * time.Second,
		TLSConfig: tlsConfig,
	})
}

// TLSDialWithTimeout establishes a TLS connection with a custom timeout.
func TLSDialWithTimeout(target string, timeout time.Duration) (*tls.Conn, error) {
	return TLSDialWithContext(context.Background(), target, DialOptions{
		Timeout: timeout,
	})
}

// TLSDialRaw establishes a raw TLS connection with the given config and returns
// both the connection and the raw dialer. Used for advanced scenarios like
// custom cipher/pro protocol probing.
func TLSDialRaw(target string, tlsConfig *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	host, port := parseHostPort(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, WrapConnectionError(target, err)
	}

	return conn, nil
}

// insecureTLSConfig returns a TLS config with InsecureSkipVerify set to true.
// This is the default config for analysis tools that need to connect regardless
// of certificate validity.
func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
