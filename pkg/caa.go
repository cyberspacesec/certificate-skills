package pkg

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// CAAResult represents the result of a CAA record check.
type CAAResult struct {
	Target      string      `json:"target"`
	HasCAA      bool        `json:"has_caa"`
	Records     []CAARecord `json:"records"`
	IssuerCA    string      `json:"issuer_ca,omitempty"`
	IsCompliant bool        `json:"is_compliant"`
	Violations  []string    `json:"violations,omitempty"`
	Error       string      `json:"error,omitempty"`
}

// CAARecord represents a single CAA DNS record.
type CAARecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`   // issue, issuewild, iodef
	Value string `json:"value"`
}

// CheckCAA checks DNS CAA (Certification Authority Authorization) records
// for a domain and verifies if the issuing CA is authorized.
func CheckCAA(target string) (*CAAResult, error) {
	result := &CAAResult{
		Target:     target,
		Records:    []CAARecord{},
		Violations: []string{},
	}

	host, _ := parseHostPort(target)

	// Query CAA records
	caaRecords, err := queryCAARecords(host)
	if err != nil {
		// No CAA records is valid - it means any CA can issue
		result.HasCAA = false
		result.IsCompliant = true
		return result, nil
	}

	if len(caaRecords) == 0 {
		result.HasCAA = false
		result.IsCompliant = true
		return result, nil
	}

	result.HasCAA = true
	result.Records = caaRecords

	// Get the certificate's issuer to check CAA compliance
	sslInfo, err := GetCertFromDomain(target)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get certificate: %v", err)
		return result, nil
	}

	if len(sslInfo.PeerCerts.Certificates) == 0 {
		result.Error = "no certificates found"
		return result, nil
	}

	cert := sslInfo.PeerCerts.Certificates[0]
	result.IssuerCA = cert.Issuer

	// Check CAA compliance
	result.IsCompliant, result.Violations = checkCAACompliance(caaRecords, cert.Issuer)

	return result, nil
}

// queryCAARecords queries DNS for CAA records.
func queryCAARecords(domain string) ([]CAARecord, error) {
	// Use Go's net resolver to look up CAA records
	// CAA record type is 257 (RFC 6844)
	txtRecords, err := net.LookupTXT(domain)
	_ = txtRecords // CAA is not the same as TXT, but we try the standard resolver

	// Try using the standard resolver with CAA type
	// Unfortunately, Go's standard net library doesn't support CAA lookups directly.
	// We implement a basic CAA lookup using the net package's raw DNS query capability.

	records, err := lookupCAA(domain)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// lookupCAA performs a CAA record lookup using DNS.
func lookupCAA(domain string) ([]CAARecord, error) {
	// Use a custom DNS resolver that supports CAA records
	// We'll try multiple approaches:

	// Approach 1: Try net.LookupTXT with CAA-prefix patterns (some DNS providers expose CAA via TXT)
	// Approach 2: Use a direct DNS query

	// For now, we use a direct UDP DNS query for CAA records (type 257)
	return dnsQueryCAA(domain)
}

// dnsQueryCAA performs a direct DNS query for CAA records.
func dnsQueryCAA(domain string) ([]CAARecord, error) {
	// Build DNS query packet for CAA records (type 257)
	// DNS header
	query := []byte{
		0xAA, 0xBB, // ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}

	// QNAME: encode domain name
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00) // Root label

	// QTYPE: CAA = 257 (0x0101)
	query = append(query, 0x01, 0x01)
	// QCLASS: IN = 1
	query = append(query, 0x00, 0x01)

	// Send query to DNS server
	var lastErr error
	dnsServers := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}

	for _, server := range dnsServers {
		conn, err := net.DialTimeout("udp", server, 3*time.Second)
		if err != nil {
			lastErr = err
			continue
		}

		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write(query)
		if err != nil {
			conn.Close()
			lastErr = err
			continue
		}

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if n < 12 {
			lastErr = fmt.Errorf("DNS response too short")
			continue
		}

		// Parse DNS response
		return parseCAAResponse(buf[:n], domain)
	}

	return nil, fmt.Errorf("DNS query failed: %v", lastErr)
}

// parseCAAResponse parses a DNS response for CAA records.
func parseCAAResponse(data []byte, domain string) ([]CAARecord, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// Check response code
	rcode := data[3] & 0x0F
	if rcode != 0 {
		// NXDOMAIN or other error - no CAA records
		return nil, fmt.Errorf("DNS error code: %d", rcode)
	}

	// Count answers
	answerCount := int(data[6])<<8 | int(data[7])
	if answerCount == 0 {
		return []CAARecord{}, nil
	}

	// Skip header
	offset := 12

	// Skip question section
	for offset < len(data) {
		if data[offset] == 0 {
			offset += 5 // null label + QTYPE(2) + QCLASS(2)
			break
		}
		offset += int(data[offset]) + 1
	}

	var records []CAARecord

	// Parse answer section
	for i := 0; i < answerCount && offset < len(data); i++ {
		// Skip name (could be compressed)
		offset = skipDNSName(data, offset)

		if offset+10 > len(data) {
			break
		}

		// Read TYPE, CLASS, TTL, RDLENGTH
		rtype := int(data[offset])<<8 | int(data[offset+1])
		offset += 2 // skip type
		offset += 2 // skip class
		offset += 4 // skip TTL
		rdlength := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+rdlength > len(data) {
			break
		}

		rdata := data[offset : offset+rdlength]

		// CAA record type is 257
		if rtype == 257 && len(rdata) >= 2 {
			flag := rdata[0]
			tagLength := int(rdata[1])
			if 2+tagLength <= len(rdata) {
				tag := string(rdata[2 : 2+tagLength])
				value := string(rdata[2+tagLength:])
				records = append(records, CAARecord{
					Flag:  flag,
					Tag:   tag,
					Value: value,
				})
			}
		}

		offset += rdlength
	}

	return records, nil
}

// skipDNSName skips a DNS name in a response packet, handling compression pointers.
func skipDNSName(data []byte, offset int) int {
	for offset < len(data) {
		b := data[offset]
		if b == 0 {
			offset++
			break
		}
		if b&0xC0 == 0xC0 {
			// Compression pointer
			offset += 2
			break
		}
		offset += int(b) + 1
	}
	return offset
}

// checkCAACompliance checks if the certificate issuer is authorized by CAA records.
func checkCAACompliance(records []CAARecord, issuer string) (bool, []string) {
	violations := []string{}
	compliant := true

	// Extract the CA name from the issuer string
	// Issuer format: "CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,..."
	issuerName := extractCAName(issuer)

	// Find issue records
	var issueRecords []CAARecord
	var issueWildRecords []CAARecord
	var iodefRecords []CAARecord

	for _, rec := range records {
		switch rec.Tag {
		case "issue":
			issueRecords = append(issueRecords, rec)
		case "issuewild":
			issueWildRecords = append(issueWildRecords, rec)
		case "iodef":
			iodefRecords = append(iodefRecords, rec)
		}
	}

	// Check if any issue record authorizes this CA
	if len(issueRecords) > 0 {
		authorized := false
		for _, rec := range issueRecords {
			// CAA issue value format: "domain.name [;key=value]*"
			caaDomain := strings.Fields(rec.Value)[0]
			if caaDomain == ";" || caaDomain == "" {
				// ";" means no CA is authorized
				continue
			}
			if caaDomainMatches(caaDomain, issuerName) {
				authorized = true
				break
			}
		}
		if !authorized {
			compliant = false
			violations = append(violations, fmt.Sprintf("CAA record does not authorize %s to issue certificates", issuerName))
		}
	}

	// If there are iodef records, note them
	if len(iodefRecords) > 0 {
		// Just informational, not a violation
	}

	return compliant, violations
}

// extractCAName extracts the CA name from an issuer string.
func extractCAName(issuer string) string {
	// Try to extract O= value, fallback to CN=
	parts := strings.Split(issuer, ",")
	orgName := ""
	commonName := ""

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "O=") {
			orgName = strings.TrimPrefix(part, "O=")
		}
		if strings.HasPrefix(part, "CN=") {
			commonName = strings.TrimPrefix(part, "CN=")
		}
	}

	// Use organization name for matching as CAA uses CA domain names
	if orgName != "" {
		return orgName
	}
	return commonName
}

// caaDomainMatches checks if a CAA domain matches an issuer name.
// This is a fuzzy match since CAA uses domain names and cert issuers have
// organization names.
func caaDomainMatches(caaDomain, issuerName string) bool {
	caaLower := strings.ToLower(caaDomain)
	issuerLower := strings.ToLower(issuerName)

	// Direct match
	if caaLower == issuerLower {
		return true
	}

	// Check if the issuer name contains the CAA domain
	if strings.Contains(issuerLower, caaLower) {
		return true
	}

	// Check if the CAA domain is a substring of the issuer
	if strings.Contains(caaLower, issuerLower) {
		return true
	}

	return false
}
