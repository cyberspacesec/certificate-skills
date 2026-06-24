package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/cyberspacesec/certificate-skills/internal/display"
	"github.com/cyberspacesec/certificate-skills/pkg"
	"github.com/spf13/cobra"
)

// --- Flag helper functions ---

func mustGetString(cmd *cobra.Command, name string) string {
	val, _ := cmd.Flags().GetString(name)
	return val
}

func mustGetInt(cmd *cobra.Command, name string) int {
	val, _ := cmd.Flags().GetInt(name)
	return val
}

func mustGetBool(cmd *cobra.Command, name string) bool {
	val, _ := cmd.Flags().GetBool(name)
	return val
}

// --- Utility functions ---

func isFileTarget(target string) bool {
	fileExts := []string{".pem", ".crt", ".cer", ".der", ".p7b", ".p7c"}
	lower := strings.ToLower(target)
	for _, ext := range fileExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func boolIcon(val bool) string {
	return display.BoolIcon(val)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseIPAddresses(ipStr string) []net.IP {
	if ipStr == "" {
		return nil
	}
	var ips []net.IP
	for _, ipStr := range strings.Split(ipStr, ",") {
		ipStr = strings.TrimSpace(ipStr)
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// subSectionHeader renders a smaller section header for sub-sections.
func subSectionHeader(title string) string {
	return display.Dim(fmt.Sprintf("  ── %s ──", title))
}

// --- Display helper functions ---

func displayCertInfo(certInfo *pkg.CertInfo, format string) {
	if format == "json" {
		data, _ := json.MarshalIndent(certInfo, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println(display.SectionHeader("Certificate Information"))
	fmt.Println(display.BulletKeyValue("Subject", certInfo.Subject))
	fmt.Println(display.BulletKeyValue("Issuer", certInfo.Issuer))
	fmt.Println(display.BulletKeyValue("Serial Number", certInfo.SerialNumber))
	fmt.Println(display.BulletKeyValue("Not Before", certInfo.NotBefore.Format("2006-01-02 15:04:05 UTC")))
	fmt.Println(display.BulletKeyValue("Not After", certInfo.NotAfter.Format("2006-01-02 15:04:05 UTC")))
	fmt.Println(display.BulletKeyValue("Public Key Algorithm", certInfo.PublicKeyAlgorithm))
	fmt.Println(display.BulletKeyValue("Signature Algorithm", certInfo.SignatureAlgorithm))
	fmt.Println(display.BulletKeyValue("Key Size", fmt.Sprintf("%d bits", certInfo.KeySize)))
	fmt.Println(display.BulletKeyValue("Is CA", boolIcon(certInfo.IsCA)))
	fmt.Println(display.BulletKeyValue("Version", fmt.Sprintf("V%d", certInfo.Version)))

	if len(certInfo.DNSNames) > 0 {
		fmt.Println(display.BulletKeyValue("DNS Names", strings.Join(certInfo.DNSNames, ", ")))
	}
	if len(certInfo.IPAddresses) > 0 {
		fmt.Println(display.BulletKeyValue("IP Addresses", strings.Join(certInfo.IPAddresses, ", ")))
	}
	if len(certInfo.KeyUsage) > 0 {
		fmt.Println(display.BulletKeyValue("Key Usage", strings.Join(certInfo.KeyUsage, ", ")))
	}
	if len(certInfo.ExtKeyUsage) > 0 {
		fmt.Println(display.BulletKeyValue("Extended Key Usage", strings.Join(certInfo.ExtKeyUsage, ", ")))
	}

	fmt.Println(subSectionHeader("Fingerprints"))
	displayFingerprints(certInfo.Fingerprints, format)
}

func displaySSLInfo(sslInfo *pkg.SSLInfo, format string) {
	if format == "json" {
		data, _ := json.MarshalIndent(sslInfo, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println(display.SectionHeader("SSL/TLS Connection Information"))
	fmt.Println(display.BulletKeyValue("TLS Version", sslInfo.TLSVersion))
	fmt.Println(display.BulletKeyValue("Cipher Suite", sslInfo.CipherSuite))
	fmt.Println(display.BulletKeyValue("Handshake Time", sslInfo.HandshakeTime.String()))
	fmt.Println(display.BulletKeyValue("HTTP/2 Support", boolIcon(sslInfo.SupportsHTTP2)))
	fmt.Println(display.BulletKeyValue("OCSP Stapling", boolIcon(sslInfo.HasOCSPStaple)))

	fmt.Println(subSectionHeader("Certificate Chain"))
	fmt.Println(display.BulletKeyValue("Chain Length", fmt.Sprintf("%d", sslInfo.PeerCerts.ChainLength)))
	fmt.Println(display.BulletKeyValue("Chain Valid", boolIcon(sslInfo.PeerCerts.IsValid)))
	fmt.Println(display.BulletKeyValue("Trust Anchor", sslInfo.PeerCerts.TrustAnchor))

	for i, cert := range sslInfo.PeerCerts.Certificates {
		fmt.Printf("\n  Certificate #%d:\n", i+1)
		fmt.Println(display.BulletKeyValue("  Subject", cert.Subject))
		fmt.Println(display.BulletKeyValue("  Issuer", cert.Issuer))
		fmt.Println(display.BulletKeyValue("  Not After", cert.NotAfter.Format("2006-01-02")))
		fmt.Println(display.BulletKeyValue("  Is CA", boolIcon(cert.IsCA)))
	}
}

func displayFingerprints(fingerprints map[string]string, format string) {
	if format == "json" {
		data, _ := json.MarshalIndent(fingerprints, "", "  ")
		fmt.Println(string(data))
		return
	}

	for _, alg := range []string{"sha256", "sha1", "md5"} {
		if fp, ok := fingerprints[alg]; ok {
			fmt.Println(display.BulletKeyValue(strings.ToUpper(alg), fp))
		}
	}
	if pkFP, ok := fingerprints["public_key_sha256"]; ok {
		fmt.Println(display.BulletKeyValue("Public Key SHA-256", pkFP))
	}
}

func displayBatchResults(results []pkg.BatchResult, format string) {
	if format == "json" {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
		return
	}

	for _, result := range results {
		fmt.Println(display.SectionHeader(fmt.Sprintf("Target: %s", result.Target)))
		if result.Error != nil {
			fmt.Println(display.Error(fmt.Sprintf("Error: %v", result.Error)))
			continue
		}
		if result.SSLInfo != nil {
			displaySSLInfo(result.SSLInfo, format)
		} else if result.CertInfo != nil {
			displayCertInfo(result.CertInfo, format)
		}
	}
}

func displaySecurityAnalysis(analysis *pkg.SecurityAnalysis, format string) {
	if format == "json" {
		data, _ := json.MarshalIndent(analysis, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println(display.SectionHeader("Security Analysis"))
	fmt.Println(display.BulletKeyValue("Target", analysis.Target))
	fmt.Println(display.BulletKeyValue("Overall Score", fmt.Sprintf("%d/100", analysis.OverallScore)))
	fmt.Println(display.BulletKeyValue("Security Level", analysis.SecurityLevel))

	// Certificate Check
	fmt.Println(subSectionHeader("Certificate Check"))
	cc := analysis.CertificateCheck
	fmt.Println(display.BulletKeyValue("Valid", boolIcon(cc.IsValid)))
	fmt.Println(display.BulletKeyValue("Self-Signed", boolIcon(cc.IsSelfSigned)))
	fmt.Println(display.BulletKeyValue("Expired", boolIcon(cc.IsExpired)))
	fmt.Println(display.BulletKeyValue("Expiring Soon", boolIcon(cc.IsExpiringSoon)))
	fmt.Println(display.BulletKeyValue("Days Until Expiry", fmt.Sprintf("%d", cc.DaysUntilExpiry)))
	fmt.Println(display.BulletKeyValue("Key Size", fmt.Sprintf("%d bits", cc.KeySize)))
	fmt.Println(display.BulletKeyValue("Signature Algorithm", cc.SignatureAlg))
	fmt.Println(display.BulletKeyValue("Weak Signature", boolIcon(cc.WeakSignature)))
	fmt.Println(display.BulletKeyValue("Has SAN", boolIcon(cc.HasSAN)))
	fmt.Println(display.BulletKeyValue("Wildcard Certificate", boolIcon(cc.WildcardCert)))
	fmt.Println(display.BulletKeyValue("Chain Valid", boolIcon(cc.ChainValid)))

	// TLS Check
	fmt.Println(subSectionHeader("TLS Check"))
	tc := analysis.TLSCheck
	fmt.Println(display.BulletKeyValue("TLS Version", tc.Version))
	fmt.Println(display.BulletKeyValue("Cipher Suite", tc.CipherSuite))
	fmt.Println(display.BulletKeyValue("Secure Version", boolIcon(tc.IsSecureVersion)))
	fmt.Println(display.BulletKeyValue("Secure Cipher Suite", boolIcon(tc.IsSecureCipherSuite)))
	fmt.Println(display.BulletKeyValue("HTTP/2 Support", boolIcon(tc.SupportsHTTP2)))
	fmt.Println(display.BulletKeyValue("OCSP Stapling", boolIcon(tc.HasOCSPStaple)))

	if tc.HSTS != nil {
		fmt.Println(subSectionHeader("HSTS"))
		fmt.Println(display.BulletKeyValue("Enabled", boolIcon(tc.HSTS.Enabled)))
		if tc.HSTS.Enabled {
			fmt.Println(display.BulletKeyValue("Max-Age", fmt.Sprintf("%d", tc.HSTS.MaxAge)))
			fmt.Println(display.BulletKeyValue("Include SubDomains", boolIcon(tc.HSTS.IncludeSubDomains)))
			fmt.Println(display.BulletKeyValue("Preload", boolIcon(tc.HSTS.Preload)))
		}
	}

	// Expiration Check
	fmt.Println(subSectionHeader("Expiration Check"))
	ec := analysis.ExpirationCheck
	fmt.Println(display.BulletKeyValue("Days Until Expiry", fmt.Sprintf("%d", ec.DaysUntilExpiry)))
	fmt.Println(display.BulletKeyValue("Expiration Date", ec.ExpirationDate))
	fmt.Println(display.BulletKeyValue("Status", ec.Status))
	fmt.Println(display.BulletKeyValue("Message", ec.Message))

	// Security Issues
	if len(analysis.Issues) > 0 {
		fmt.Println(subSectionHeader("Security Issues"))
		for _, issue := range analysis.Issues {
			var icon string
			switch issue.Severity {
			case "Critical":
				icon = "🔴"
			case "High":
				icon = "🟠"
			case "Medium":
				icon = "🟡"
			default:
				icon = "🟢"
			}
			fmt.Printf("  %s [%s] %s: %s\n", icon, issue.Severity, issue.Type, issue.Description)
			fmt.Printf("     Impact: %s\n", issue.Impact)
		}
	}

	// Recommendations
	if len(analysis.Recommendations) > 0 {
		fmt.Println(subSectionHeader("Recommendations"))
		for i, rec := range analysis.Recommendations {
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
	}
}

func displayGenerationResult(result *pkg.GenerationResult, format string) {
	if format == "json" {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println(display.SectionHeader("Certificate Generated Successfully"))
	fmt.Println(display.BulletKeyValue("Certificate Path", result.CertificatePath))
	fmt.Println(display.BulletKeyValue("Private Key Path", result.PrivateKeyPath))
	fmt.Println(display.BulletKeyValue("Message", result.Message))

	fmt.Println(subSectionHeader("Fingerprints"))
	displayFingerprints(result.Fingerprints, format)
}
