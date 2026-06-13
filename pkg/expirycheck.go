package pkg

import (
	"fmt"
	"time"
)

// ExpiryMonitorResult represents the result of a certificate expiry monitoring check.
type ExpiryMonitorResult struct {
	Targets       []ExpiryEntry `json:"targets"`
	TotalCount    int           `json:"total_count"`
	ExpiredCount  int           `json:"expired_count"`
	CriticalCount int           `json:"critical_count"` // ≤ 7 days
	WarningCount  int           `json:"warning_count"`  // ≤ 30 days
	HealthyCount  int           `json:"healthy_count"`  // > 30 days
	ErrorCount    int           `json:"error_count"`
}

// ExpiryEntry represents the expiry status of a single target.
type ExpiryEntry struct {
	Target          string `json:"target"`
	DaysUntilExpiry int    `json:"days_until_expiry"`
	ExpirationDate  string `json:"expiration_date"`
	Status          string `json:"status"` // Expired, Critical, Warning, Healthy
	Issuer          string `json:"issuer,omitempty"`
	Subject         string `json:"subject,omitempty"`
	Error           string `json:"error,omitempty"`
}

// CertExpiryMonitor checks the expiration status of certificates for
// multiple targets. Useful for monitoring certificate lifecycles.
func CertExpiryMonitor(targets []string) *ExpiryMonitorResult {
	result := &ExpiryMonitorResult{
		Targets: make([]ExpiryEntry, 0, len(targets)),
	}

	now := time.Now()

	for _, target := range targets {
		entry := ExpiryEntry{Target: target}

		var certInfo *CertInfo
		var err error

		if IsFileTarget(target) {
			certInfo, err = GetCertFromFile(target)
		} else {
			sslInfo, sslErr := GetCertFromDomain(target)
			if sslErr != nil {
				err = sslErr
			} else if len(sslInfo.PeerCerts.Certificates) > 0 {
				cert := sslInfo.PeerCerts.Certificates[0]
				certInfo = &cert
			}
		}

		if err != nil {
			entry.Error = fmt.Sprintf("failed to check: %v", err)
			entry.Status = "Error"
			result.ErrorCount++
			result.Targets = append(result.Targets, entry)
			continue
		}

		if certInfo == nil {
			entry.Error = "no certificate found"
			entry.Status = "Error"
			result.ErrorCount++
			result.Targets = append(result.Targets, entry)
			continue
		}

		entry.Subject = certInfo.Subject
		entry.Issuer = certInfo.Issuer
		entry.ExpirationDate = certInfo.NotAfter.Format("2006-01-02 15:04:05 UTC")
		entry.DaysUntilExpiry = int(certInfo.NotAfter.Sub(now).Hours() / 24)

		if entry.DaysUntilExpiry < 0 {
			entry.Status = "Expired"
			result.ExpiredCount++
		} else if entry.DaysUntilExpiry <= 7 {
			entry.Status = "Critical"
			result.CriticalCount++
		} else if entry.DaysUntilExpiry <= 30 {
			entry.Status = "Warning"
			result.WarningCount++
		} else {
			entry.Status = "Healthy"
			result.HealthyCount++
		}

		result.Targets = append(result.Targets, entry)
	}

	result.TotalCount = len(targets)

	return result
}
