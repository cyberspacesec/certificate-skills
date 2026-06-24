package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cyberspacesec/certificate-skills/internal/display"
	"github.com/cyberspacesec/certificate-skills/pkg"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [domain:port]",
	Short: "Analyze SSL/TLS connection security",
	Long: `Perform comprehensive security analysis of SSL/TLS connections including:
- Certificate validation and expiration check
- TLS protocol version and cipher suite analysis
- Security vulnerability assessment
- Detailed security recommendations

Examples:
  cert-skills analyze google.com
  cert-skills analyze example.com:8443
  cert-skills analyze google.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Println(display.SectionHeader(fmt.Sprintf("Security Analysis: %s", target)))

		analysis, err := pkg.AnalyzeSecurity(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error performing security analysis: %v\n", err)
			os.Exit(1)
		}

		displaySecurityAnalysis(analysis, outputFormat)
	},
}

var batchAnalyzeCmd = &cobra.Command{
	Use:   "batch-analyze --targets domain1,domain2,domain3",
	Short: "Batch analyze SSL/TLS security for multiple domains",
	Long: `Perform security analysis on multiple domains simultaneously.
Returns individual scores plus a summary with counts per security level.

Examples:
  cert-skills batch-analyze --targets google.com,github.com,cloudflare.com
  cert-skills batch-analyze --targets google.com,github.com --output json`,
	Run: func(cmd *cobra.Command, args []string) {
		targetsStr, _ := cmd.Flags().GetString("targets")
		outputFormat, _ := cmd.Flags().GetString("output")

		if targetsStr == "" {
			fmt.Fprintf(os.Stderr, "Error: --targets is required\n")
			os.Exit(1)
		}

		targets := strings.Split(targetsStr, ",")
		for i, t := range targets {
			targets[i] = strings.TrimSpace(t)
		}

		if len(targets) > 50 {
			fmt.Fprintf(os.Stderr, "Error: maximum 50 targets allowed per batch\n")
			os.Exit(1)
		}

		fmt.Printf("Batch analyzing %d domains...\n", len(targets))

		result := pkg.BatchAnalyzeSecurity(targets)

		if outputFormat == "csv" {
			headers := []string{"target", "score", "security_level", "is_self_signed", "is_expired", "days_until_expiry", "key_size", "signature_algorithm", "tls_version", "cipher_suite", "hsts_enabled", "issues"}
			rows := make([][]string, 0, len(result.Results))
			for _, a := range result.Results {
				issues := ""
				for i, issue := range a.Issues {
					if i > 0 {
						issues += "; "
					}
					issues += issue.Severity + ":" + issue.Type
				}
				hstsEnabled := "false"
				if a.TLSCheck.HSTS != nil && a.TLSCheck.HSTS.Enabled {
					hstsEnabled = "true"
				}
				rows = append(rows, []string{
					a.Target,
					display.FormatInt(a.OverallScore),
					a.SecurityLevel,
					display.FormatBool(a.CertificateCheck.IsSelfSigned),
					display.FormatBool(a.CertificateCheck.IsExpired),
					display.FormatInt(a.CertificateCheck.DaysUntilExpiry),
					display.FormatInt(a.CertificateCheck.KeySize),
					a.CertificateCheck.SignatureAlg,
					a.TLSCheck.Version,
					a.TLSCheck.CipherSuite,
					hstsEnabled,
					issues,
				})
			}
			if err := display.WriteCSV(headers, rows, ""); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
				os.Exit(1)
			}
			return
		}

		if outputFormat == "json" {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(data))
			return
		}

		fmt.Printf("\nBatch Security Analysis Report\n")
		fmt.Println(display.Separator())
		fmt.Printf("Total Targets: %d\n", result.TotalCount)
		fmt.Printf("Summary: ✅ Good: %d | ⚠️ Medium: %d | 🚨 Low: %d | 💀 Critical: %d\n",
			result.Summary.GoodCount, result.Summary.MediumCount,
			result.Summary.LowCount, result.Summary.CriticalCount)
		fmt.Printf("Average Score: %d/100\n\n", result.Summary.AverageScore)

		for i, a := range result.Results {
			var levelIcon string
			switch a.SecurityLevel {
			case "Good":
				levelIcon = "✅"
			case "Medium":
				levelIcon = "⚠️"
			case "Low":
				levelIcon = "🚨"
			case "Critical":
				levelIcon = "💀"
			case "Error":
				levelIcon = "❌"
			default:
				levelIcon = "❓"
			}
			fmt.Printf("[%d/%d] %s %s — Score: %d/100 %s\n", i+1, result.TotalCount, a.Target, levelIcon, a.OverallScore, a.SecurityLevel)
			if len(a.Issues) > 0 {
				for _, issue := range a.Issues {
					fmt.Printf("  - [%s] %s\n", issue.Severity, issue.Type)
				}
			}
		}
	},
}

var scanCertSecurityCmd = &cobra.Command{
	Use:   "scan-cert-security [domain:port]",
	Short: "Scan certificate-specific security issues",
	Long: `Perform certificate-specific security checks (not TLS protocol).
Checks for weak signatures, short keys, missing SANs, hostname mismatches,
excessive validity, self-signed, expired, wildcard risks, and more.

Examples:
  cert-skills scan-cert-security google.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.ScanCertSecurity(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Security Scan"))
		fmt.Println(display.Separator())
		fmt.Printf("Target: %s\n\n", result.Target)

		for _, c := range result.Checks {
			var icon string
			if c.Passed {
				icon = "✅"
			} else {
				switch c.Severity {
				case "Critical":
					icon = "💀"
				case "High":
					icon = "🚨"
				case "Medium":
					icon = "⚠️"
				default:
					icon = "🔸"
				}
			}
			status := "PASS"
			if !c.Passed {
				status = "FAIL"
			}
			fmt.Printf("%s [%s] %s (%s) - %s\n", icon, c.Code, c.Name, status, c.Detail)
		}

		fmt.Printf("\nSummary: %d/%d passed, %d failed, IsSecure: %v\n",
			result.Summary.Passed, result.Summary.TotalChecked, result.Summary.Failed, result.Summary.IsSecure)
	},
}

var scanVulnsCmd = &cobra.Command{
	Use:   "scan-vulns [domain:port]",
	Short: "Scan for known TLS vulnerabilities",
	Long: `Scan a target server for known TLS vulnerabilities including:
Heartbleed, POODLE, ROBOT, CCS Injection, FREAK, Logjam,
Sweet32, BEAST, CRIME, DROWN, and insecure renegotiation.

Examples:
  cert-skills scan-vulns google.com
  cert-skills scan-vulns example.com:8443 --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Scanning TLS vulnerabilities for: %s\n", target)

		result, err := pkg.VulnerabilityScan(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning vulnerabilities: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(data))
			return
		}

		fmt.Printf("\nTLS Vulnerability Scan Results\n")
		fmt.Println(display.Separator())
		fmt.Printf("Target: %s\n\n", result.Target)

		for _, v := range result.Vulnerabilities {
			var icon string
			if v.Vulnerable {
				switch v.Severity {
				case "Critical":
					icon = "💀"
				case "High":
					icon = "🚨"
				case "Medium":
					icon = "⚠️"
				case "Low":
					icon = "🔸"
				}
			} else {
				icon = "✅"
			}

			status := "NOT VULNERABLE"
			if v.Vulnerable {
				status = "VULNERABLE"
			}

			fmt.Printf("%s %s [%s] - %s (%s)\n", icon, v.Name, v.Code, status, v.Severity)
			if v.Detail != "" {
				fmt.Printf("   %s\n", v.Detail)
			}
		}

		fmt.Printf("\nSummary:\n")
		fmt.Printf("  Total Checked:  %d\n", result.Summary.TotalChecked)
		fmt.Printf("  Vulnerable:     %d\n", result.Summary.Vulnerable)
		fmt.Printf("  Secure:         %d\n", result.Summary.Secure)
		if result.Summary.CriticalCount > 0 {
			fmt.Printf("  Critical:       %d 💀\n", result.Summary.CriticalCount)
		}
		if result.Summary.LowCount > 0 {
			fmt.Printf("  High:           %d 🚨\n", result.Summary.LowCount)
		}
		if result.Summary.MediumCount > 0 {
			fmt.Printf("  Medium:         %d ⚠️\n", result.Summary.MediumCount)
		}

		if result.Summary.IsSecure {
			fmt.Printf("\n✅ No TLS vulnerabilities detected\n")
		} else {
			fmt.Printf("\n❌ Vulnerabilities detected: %s\n", strings.Join(result.Summary.VulnerableList, ", "))
		}
	},
}

var expiryMonitorCmd = &cobra.Command{
	Use:   "expiry-monitor --targets domain1,domain2",
	Short: "Monitor certificate expiration for multiple targets",
	Long: `Monitor certificate expiration for multiple domains or files.
Returns expiry status for each target categorized as Expired, Critical
(<=7 days), Warning (<=30 days), or Healthy (>30 days).

Examples:
  cert-skills expiry-monitor --targets google.com,github.com,cloudflare.com
  cert-skills expiry-monitor --targets google.com,github.com --output json`,
	Run: func(cmd *cobra.Command, args []string) {
		targetsStr, _ := cmd.Flags().GetString("targets")
		outputFormat, _ := cmd.Flags().GetString("output")

		if targetsStr == "" {
			fmt.Fprintf(os.Stderr, "Error: --targets is required\n")
			os.Exit(1)
		}

		targets := strings.Split(targetsStr, ",")
		for i, t := range targets {
			targets[i] = strings.TrimSpace(t)
		}

		if len(targets) > 50 {
			fmt.Fprintf(os.Stderr, "Error: maximum 50 targets allowed\n")
			os.Exit(1)
		}

		fmt.Printf("Monitoring certificate expiry for %d targets...\n", len(targets))

		result := pkg.CertExpiryMonitor(targets)

		if outputFormat == "csv" {
			headers := []string{"target", "status", "days_until_expiry", "expiration_date", "issuer", "subject", "error"}
			rows := make([][]string, 0, len(result.Targets))
			for _, entry := range result.Targets {
				rows = append(rows, []string{
					entry.Target,
					entry.Status,
					display.FormatInt(entry.DaysUntilExpiry),
					entry.ExpirationDate,
					entry.Issuer,
					entry.Subject,
					entry.Error,
				})
			}
			if err := display.WriteCSV(headers, rows, ""); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
				os.Exit(1)
			}
			return
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Expiry Monitor"))
		fmt.Printf("==========================\n")
		fmt.Printf("Total: %d | Expired: %d | Critical: %d | Warning: %d | Healthy: %d | Error: %d\n",
			result.TotalCount, result.ExpiredCount, result.CriticalCount,
			result.WarningCount, result.HealthyCount, result.ErrorCount)

		for _, entry := range result.Targets {
			var icon string
			switch entry.Status {
			case "Expired":
				icon = "💀"
			case "Critical":
				icon = "🚨"
			case "Warning":
				icon = "⚠️"
			case "Healthy":
				icon = "✅"
			default:
				icon = "❌"
			}
			fmt.Printf("%s %s — %s", icon, entry.Target, entry.Status)
			if entry.Error == "" {
				fmt.Printf(" (%d days, expires %s)", entry.DaysUntilExpiry, entry.ExpirationDate)
			} else {
				fmt.Printf(" (%s)", entry.Error)
			}
			fmt.Println()
		}
	},
}

func init() {
	// batch-analyze command parameters
	batchAnalyzeCmd.Flags().StringP("targets", "t", "", "Comma-separated list of domains to analyze")

	// expiry-monitor command parameters
	expiryMonitorCmd.Flags().StringP("targets", "t", "", "Comma-separated list of domains or files to monitor")

	// Register analysis commands with rootCmd
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(batchAnalyzeCmd)
	rootCmd.AddCommand(scanCertSecurityCmd)
	rootCmd.AddCommand(scanVulnsCmd)
	rootCmd.AddCommand(expiryMonitorCmd)
}
