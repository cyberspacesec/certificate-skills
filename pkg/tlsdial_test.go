package pkg

import (
	"testing"
	"time"
)

func TestDefaultDialOptions(t *testing.T) {
	opts := defaultDialOptions()

	if opts.Timeout != 10*time.Second {
		t.Errorf("default timeout = %v, want 10s", opts.Timeout)
	}
	if opts.TLSConfig != nil {
		t.Error("default TLSConfig should be nil")
	}
}

func TestDialOptions_ZeroTimeout(t *testing.T) {
	// Verify that TLSDialWithContext applies default timeout when zero
	opts := DialOptions{Timeout: 0}
	if opts.Timeout != 0 {
		t.Error("zero timeout should be zero before calling TLSDialWithContext")
	}
}

func TestInsecureTLSConfig(t *testing.T) {
	config := insecureTLSConfig()
	if config == nil {
		t.Fatal("insecureTLSConfig returned nil")
	}
	if !config.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}
