package pkg

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// HSTSResult represents the result of an HSTS check.
type HSTSResult struct {
	Enabled           bool   `json:"enabled"`
	MaxAge            int    `json:"max_age"`
	IncludeSubDomains bool   `json:"include_sub_domains"`
	Preload           bool   `json:"preload"`
	RawHeader         string `json:"raw_header"`
	Error             string `json:"error,omitempty"`
}

// CheckHSTS checks if a domain has HSTS (HTTP Strict Transport Security) enabled
// by making an HTTPS request and inspecting the response headers.
func CheckHSTS(domain string) *HSTSResult {
	host, port := parseHostPort(domain)

	// Create custom transport that skips cert verification (we're checking headers, not cert validity)
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
		TLSClientConfig: insecureTLSConfig(),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		// Don't follow redirects — check the first response
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	target := fmt.Sprintf("https://%s:%s/", host, port)
	if port == "443" {
		target = fmt.Sprintf("https://%s/", host)
	}

	resp, err := client.Get(target)
	if err != nil {
		return &HSTSResult{
			Enabled: false,
			Error:   fmt.Sprintf("failed to connect: %v", err),
		}
	}
	defer resp.Body.Close()

	hstsHeader := resp.Header.Get("Strict-Transport-Security")
	if hstsHeader == "" {
		return &HSTSResult{
			Enabled: false,
		}
	}

	return parseHSTSHeader(hstsHeader)
}

// parseHSTSHeader parses a Strict-Transport-Security header value.
func parseHSTSHeader(header string) *HSTSResult {
	result := &HSTSResult{
		Enabled:   true,
		RawHeader: header,
	}

	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			var maxAge int
			fmt.Sscanf(part, "max-age=%d", &maxAge)
			result.MaxAge = maxAge
		}
		if strings.EqualFold(part, "includeSubDomains") {
			result.IncludeSubDomains = true
		}
		if strings.EqualFold(part, "preload") {
			result.Preload = true
		}
	}

	return result
}
