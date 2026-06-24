package pkg

import (
	"crypto/tls"
	"fmt"
)

// SessionResumptionResult represents the result of a TLS session resumption check.
type SessionResumptionResult struct {
	Target                string `json:"target"`
	SupportsSessionID     bool   `json:"supports_session_id"`
	SupportsSessionTicket bool   `json:"supports_session_ticket"`
	TLSVersion            string `json:"tls_version"`
	Error                 string `json:"error,omitempty"`
}

// CheckSessionResumption tests whether a server supports TLS session resumption
// using either session IDs or session tickets (TLS session tickets / RFC 5077).
func CheckSessionResumption(target string) (*SessionResumptionResult, error) {
	result := &SessionResumptionResult{
		Target: target,
	}

	host, port := parseHostPort(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	// First connection: get session state with session cache enabled
	config := &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
	}

	conn1, err := TLSDialWithConfig(target, config)
	if err != nil {
		result.Error = fmt.Sprintf("failed to connect: %v", err)
		return result, nil
	}

	state1 := conn1.ConnectionState()
	result.TLSVersion = getTLSVersionName(state1.Version)

	// Check for session ticket support
	result.SupportsSessionTicket = state1.DidResume || len(state1.PeerCertificates) > 0

	// Get the session for resumption attempt
	session, _ := config.ClientSessionCache.Get(addr)

	conn1.Close()

	// Second connection: attempt session resumption
	conn2, err := TLSDialWithConfig(target, config)
	if err != nil {
		// Can't test resumption, but first connection was OK
		result.SupportsSessionTicket = false
		result.SupportsSessionID = false
		return result, nil
	}
	defer conn2.Close()

	state2 := conn2.ConnectionState()

	// If the second connection resumed, DidResume will be true
	if state2.DidResume {
		// The session was resumed - check which method
		result.SupportsSessionTicket = true
		result.SupportsSessionID = session != nil
	} else {
		// Session was not resumed
		result.SupportsSessionTicket = false
		result.SupportsSessionID = false
	}

	return result, nil
}
