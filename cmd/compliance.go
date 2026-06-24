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

var checkHSTSCmd = &cobra.Command{
	Use:   "check-hsts [domain]",
	Short: "Check HSTS (HTTP Strict Transport Security) status",
	Long: `Check if a domain has HSTS (HTTP Strict Transport Security) enabled
by making an HTTPS request and inspecting the response headers.
Returns HSTS status, max-age, includeSubDomains, and preload directives.

Examples:
  cert-skills check-hsts google.com
  cert-skills check-hsts example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Checking HSTS status for: %s\n", target)

		result := pkg.CheckHSTS(target)

		if outputFormat == "json" {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("HSTS Check Results"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", target))
		if result.Error != "" {
			fmt.Printf("Error: %s\n", result.Error)
			os.Exit(1)
		}
		if result.Enabled {
			fmt.Printf("HSTS Enabled: ✅ Yes\n")
			fmt.Printf("Max-Age: %d seconds (%.1f days)\n", result.MaxAge, float64(result.MaxAge)/86400.0)
			fmt.Printf("IncludeSubDomains: %s\n", boolIcon(result.IncludeSubDomains))
			fmt.Printf("Preload: %s\n", boolIcon(result.Preload))
			if result.RawHeader != "" {
				fmt.Printf("Raw Header: %s\n", result.RawHeader)
			}
		} else {
			fmt.Printf("HSTS Enabled: ❌ No\n")
			fmt.Printf("\n⚠️  HSTS is not enabled. This makes the site vulnerable to SSL stripping attacks.\n")
			fmt.Printf("   Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n")
		}
	},
}

var checkCAACmd = &cobra.Command{
	Use:   "check-caa [domain]",
	Short: "Check DNS CAA records",
	Long: `Check DNS CAA (Certification Authority Authorization) records for a domain.
Verifies if the issuing CA is authorized by CAA policy.

Examples:
  cert-skills check-caa google.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckCAA(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("CAA Record Check"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		fmt.Printf("Has CAA: %s\n", display.BoolIcon(result.HasCAA))
		if result.HasCAA {
			fmt.Printf("Compliant: %s\n", display.BoolIcon(result.IsCompliant))
			for _, rec := range result.Records {
				fmt.Printf("  %s %s %s\n", rec.Tag, rec.Value, fmt.Sprintf("(flag=%d)", rec.Flag))
			}
			if len(result.Violations) > 0 {
				fmt.Printf("\nViolations:\n")
				for _, v := range result.Violations {
					fmt.Printf("  ❌ %s\n", v)
				}
			}
		}
	},
}

var checkSCTCmd = &cobra.Command{
	Use:   "check-sct [domain:port]",
	Short: "Check Signed Certificate Timestamps",
	Long: `Verify Signed Certificate Timestamps (SCTs) in a certificate.
Checks CA/Browser Forum CT requirements.

Examples:
  cert-skills check-sct google.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckSCT(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("SCT Check Results"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		if result.Error != "" {
			fmt.Printf("Error: %s\n", result.Error)
			os.Exit(1)
		}
		fmt.Printf("Has SCTs: %s\n", display.BoolIcon(result.HasSCTs))
		fmt.Printf("SCT Count: %d\n", result.SCTCount)
		fmt.Printf("Required: %d\n", result.RequiredSCTs)
		fmt.Printf("Meets Requirement: %s\n", display.BoolIcon(result.MeetsRequirement))
		for i, sct := range result.SCTs {
			fmt.Printf("\n  SCT %d:\n", i+1)
			fmt.Printf("    Version: %d\n", sct.Version)
			fmt.Printf("    Log ID: %s\n", sct.LogID)
			fmt.Printf("    Timestamp: %s\n", sct.TimestampStr)
			fmt.Printf("    Source: %s\n", sct.Source)
		}
	},
}

var checkOCSPMustStapleCmd = &cobra.Command{
	Use:   "check-ocsp-must-staple [domain:port]",
	Short: "Check OCSP Must-Staple compliance",
	Long: `Check if a certificate has the OCSP Must-Staple extension (RFC 7633)
and whether the server provides an OCSP staple. Must-Staple certificates
that fail to staple cause hard-failures in compliant clients.

Examples:
  cert-skills check-ocsp-must-staple example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckOCSPMustStaple(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("OCSP Must-Staple Check"))
		fmt.Println(display.BulletKeyValue("Target", target))
		fmt.Println(display.BulletKeyValue("Has Must-Staple", display.BoolIcon(result.HasMustStaple)))
		fmt.Println(display.BulletKeyValue("Has OCSP Staple", display.BoolIcon(result.HasStaple)))
		fmt.Println(display.BulletKeyValue("Compliant", display.BoolIcon(result.IsCompliant)))
		if result.Violation != "" {
			fmt.Printf("  %s\n", display.Error(result.Violation))
		}
		fmt.Println(display.BulletKeyValue("Detail", result.Detail))
	},
}

var checkKeyUsageComplianceCmd = &cobra.Command{
	Use:   "check-key-usage [domain:port]",
	Short: "Check certificate key usage compliance",
	Long: `Validate that a certificate's key usage extensions comply with
RFC 5280 and CA/Browser Forum Baseline Requirements.

Examples:
  cert-skills check-key-usage example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckKeyUsageCompliance(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Key Usage Compliance"))
		fmt.Println(display.BulletKeyValue("Target", target))
		fmt.Println(display.BulletKeyValue("Is CA", display.BoolIcon(result.IsCA)))
		fmt.Println(display.BulletKeyValue("Compliant", display.BoolIcon(result.IsCompliant)))
		fmt.Println(display.BulletKeyValue("Key Usage", strings.Join(result.KeyUsage, ", ")))
		fmt.Println(display.BulletKeyValue("Ext Key Usage", strings.Join(result.ExtKeyUsage, ", ")))
		for _, issue := range result.Issues {
			fmt.Printf("  %s %s\n", display.SeverityStyle(issue.Severity), issue.Description)
		}
	},
}

var checkSerialEntropyCmd = &cobra.Command{
	Use:   "check-serial-entropy [domain:port]",
	Short: "Check certificate serial number entropy",
	Long: `Analyze the entropy of a certificate's serial number.
CA/Browser Forum Baseline Requirements mandate at least 64 bits of entropy.

Examples:
  cert-skills check-serial-entropy example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckSerialEntropy(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Serial Number Entropy"))
		fmt.Println(display.BulletKeyValue("Target", target))
		fmt.Println(display.BulletKeyValue("Serial", result.SerialHex))
		fmt.Println(display.BulletKeyValue("Bit Length", fmt.Sprintf("%d", result.BitLength)))
		fmt.Println(display.BulletKeyValue("Compliant", display.BoolIcon(result.IsCompliant)))
		fmt.Println(display.BulletKeyValue("Entropy", fmt.Sprintf("%.2f bits/byte", result.EntropyEstimate)))
		fmt.Println(display.BulletKeyValue("Hamming Ratio", fmt.Sprintf("%.3f", result.HammingRatio)))
		fmt.Println(display.BulletKeyValue("Sequential", display.BoolIcon(result.IsSequential)))
		for _, issue := range result.Issues {
			fmt.Printf("  %s\n", display.Warning(issue))
		}
	},
}

var checkPolicyAnalysisCmd = &cobra.Command{
	Use:   "check-policy [domain:port]",
	Short: "Analyze certificate policy OIDs",
	Long: `Analyze a certificate's policy OIDs beyond simple EV detection.
Identifies DV/OV/EV validation type, unknown policy OIDs, and missing
Certificate Policies extension on public CA-issued certificates.

Examples:
  cert-skills check-policy example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckPolicyAnalysis(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Policy Analysis"))
		fmt.Println(display.BulletKeyValue("Target", target))
		fmt.Println(display.BulletKeyValue("Validation Type", display.SeverityStyle(result.ValidationType)))
		fmt.Println(display.BulletKeyValue("Has Policies", display.BoolIcon(result.HasPolicies)))
		for _, policy := range result.PolicyOIDs {
			fmt.Println(display.BulletKeyValue(policy.OID, fmt.Sprintf("%s (%s)", policy.Description, policy.Type)))
		}
		fmt.Println(display.BulletKeyValue("Compliant", display.BoolIcon(result.IsCompliant)))
		for _, issue := range result.Issues {
			fmt.Printf("  %s\n", display.Warning(issue))
		}
	},
}

var checkNameConstraintsCmd = &cobra.Command{
	Use:   "check-name-constraints [domain:port]",
	Short: "Check CA name constraint compliance",
	Long: `Check CA certificate Name Constraints and verify leaf certificate
names comply with parent CA constraints. Detects trust boundary violations.

Examples:
  cert-skills check-name-constraints example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckNameConstraints(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Name Constraints Check"))
		fmt.Println(display.BulletKeyValue("Target", target))
		fmt.Println(display.BulletKeyValue("Has Constraints", display.BoolIcon(result.HasConstraints)))
		fmt.Println(display.BulletKeyValue("Compliant", display.BoolIcon(result.IsCompliant)))

		for _, ca := range result.ConstraintedCAs {
			fmt.Printf("  %s (position %d)\n", ca.Subject, ca.ChainPosition)
			if len(ca.PermittedDNS) > 0 {
				fmt.Println(display.BulletKeyValue("Permitted DNS", strings.Join(ca.PermittedDNS, ", ")))
			}
			if len(ca.ExcludedDNS) > 0 {
				fmt.Println(display.BulletKeyValue("Excluded DNS", strings.Join(ca.ExcludedDNS, ", ")))
			}
		}

		for _, v := range result.Violations {
			fmt.Printf("  %s %s (%s)\n", display.Error("Violation"), v.ViolatedName, v.ViolationType)
		}
	},
}

var checkBundleCompletenessCmd = &cobra.Command{
	Use:   "check-bundle [domain:port]",
	Short: "Check certificate bundle completeness",
	Long: `Check if the server provides a complete certificate chain.
If intermediates are missing, attempts to fetch them via AIA CA Issuers URLs.

Examples:
  cert-skills check-bundle example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckBundleCompleteness(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Bundle Check"))
		fmt.Println(display.BulletKeyValue("Target", target))
		fmt.Println(display.BulletKeyValue("Chain Complete", display.BoolIcon(result.ChainComplete)))
		fmt.Println(display.BulletKeyValue("Chain Length", fmt.Sprintf("%d", result.ChainLength)))

		if !result.ChainComplete {
			fmt.Println(display.BulletKeyValue("AIA Can Fill", display.BoolIcon(result.CanAIAFill)))
			fmt.Println(display.BulletKeyValue("AIA Resolved", display.BoolIcon(result.AIAFillResolved)))
			for _, m := range result.MissingIntermediates {
				fmt.Printf("  %s\n", display.Error(fmt.Sprintf("Missing: %s", m.Subject)))
				if m.AIAIssuerURL != "" {
					fmt.Println(display.BulletKeyValue("AIA URL", m.AIAIssuerURL))
				}
				fmt.Println(display.BulletKeyValue("Fetch Status", m.FetchStatus))
			}
		}
	},
}

var checkDistrustedCACmd = &cobra.Command{
	Use:   "check-distrusted-ca [domain:port]",
	Short: "Check for distrusted/compromised Certificate Authorities",
	Long: `Check if a certificate chain contains any known distrusted or
compromised Certificate Authorities (DigiNotar, WoSign, StartCom, Symantec legacy, etc.).

Examples:
  cert-skills check-distrusted-ca example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckDistrustedCA(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Distrusted CA Check"))
		fmt.Println(display.BulletKeyValue("Target", target))
		if result.IsDistrusted {
			fmt.Printf("  %s\n", display.Error("Chain contains distrusted CA(s)!"))
			for _, ca := range result.DistrustedCAs {
				fmt.Printf("  %s %s (position %d)\n", display.SeverityStyle(ca.Severity), ca.Name, ca.ChainPosition)
				fmt.Printf("     %s\n", display.Dim(ca.Reason))
				fmt.Printf("     %s\n", display.BulletKeyValue("Distrusted since", ca.DistrustDate))
			}
		} else {
			fmt.Printf("  %s\n", display.Success("No distrusted CAs in chain"))
		}
	},
}

var checkRevocationCmd = &cobra.Command{
	Use:   "check-revocation [domain:port or certificate-file]",
	Short: "Check certificate revocation status",
	Long: `Check the revocation status of a certificate using both OCSP
(Online Certificate Status Protocol) and CRL (Certificate Revocation List).

For domain targets, connects to the server and checks the leaf certificate.
For file targets, reads the certificate from the file (CRL only, OCSP requires issuer).

Examples:
  cert-skills check-revocation google.com
  cert-skills check-revocation /path/to/cert.pem
  cert-skills check-revocation example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Checking revocation status for: %s\n", target)

		result, err := pkg.CheckRevocation(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking revocation: %v\n", err)
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

		if result.Error != "" {
			fmt.Fprintf(os.Stderr, "Error: %s\n", result.Error)
			os.Exit(1)
		}

		fmt.Println(display.SectionHeader("Certificate Revocation Check"))
		fmt.Println(display.Separator())
		fmt.Printf("Target:         %s\n", result.Target)
		fmt.Printf("Overall Status: %s\n", result.OverallStatus)

		// OCSP results
		fmt.Printf("\nOCSP Status:\n")
		if result.OCSPStatus.Checked {
			var statusIcon string
			switch result.OCSPStatus.Status {
			case "Good":
				statusIcon = "✅"
			case "Revoked":
				statusIcon = "❌"
			default:
				statusIcon = "❓"
			}
			fmt.Printf("  Status:     %s %s\n", statusIcon, result.OCSPStatus.Status)
			if result.OCSPStatus.OCSPURL != "" {
				fmt.Printf("  OCSP URL:   %s\n", result.OCSPStatus.OCSPURL)
			}
			if result.OCSPStatus.RevokedAt != "" {
				fmt.Printf("  Revoked At: %s\n", result.OCSPStatus.RevokedAt)
			}
			if result.OCSPStatus.RevocationReason != "" {
				fmt.Printf("  Reason:     %s\n", result.OCSPStatus.RevocationReason)
			}
			if result.OCSPStatus.ThisUpdate != "" {
				fmt.Printf("  This Update: %s\n", result.OCSPStatus.ThisUpdate)
			}
			if result.OCSPStatus.NextUpdate != "" {
				fmt.Printf("  Next Update: %s\n", result.OCSPStatus.NextUpdate)
			}
			if result.OCSPStatus.Error != "" {
				fmt.Printf("  Error:      %s\n", result.OCSPStatus.Error)
			}
		} else {
			fmt.Printf("  Not checked: %s\n", result.OCSPStatus.Error)
		}

		// CRL results
		fmt.Printf("\nCRL Status:\n")
		if result.CRLStatus.Checked {
			var statusIcon string
			switch result.CRLStatus.Status {
			case "Good":
				statusIcon = "✅"
			case "Revoked":
				statusIcon = "❌"
			default:
				statusIcon = "❓"
			}
			fmt.Printf("  Status:     %s %s\n", statusIcon, result.CRLStatus.Status)
			if result.CRLStatus.CRLURL != "" {
				fmt.Printf("  CRL URL:    %s\n", result.CRLStatus.CRLURL)
			}
			if result.CRLStatus.ThisUpdate != "" {
				fmt.Printf("  This Update: %s\n", result.CRLStatus.ThisUpdate)
			}
			if result.CRLStatus.NextUpdate != "" {
				fmt.Printf("  Next Update: %s\n", result.CRLStatus.NextUpdate)
			}
			if result.CRLStatus.Error != "" {
				fmt.Printf("  Error:      %v\n", result.CRLStatus.Error)
			}
		} else {
			fmt.Printf("  Not checked: %s\n", result.CRLStatus.Error)
		}
	},
}

var verifyChainCmd = &cobra.Command{
	Use:   "verify-chain [domain:port]",
	Short: "Verify certificate chain",
	Long: `Verify a server's certificate chain against the system trust store.
Returns detailed information about each verified chain path, trust anchor,
and any errors or warnings.

Examples:
  cert-skills verify-chain google.com
  cert-skills verify-chain example.com:8443 --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Verifying certificate chain for: %s\n", target)

		result, err := pkg.VerifyCertChain(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Chain Verification"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		if result.IsValid {
			fmt.Printf("Chain Valid: ✅ Yes\n")
		} else {
			fmt.Printf("Chain Valid: ❌ No\n")
		}
		fmt.Printf("Chain Length: %d\n", result.ChainLength)
		if result.TrustAnchor != "" {
			fmt.Printf("Trust Anchor: %s\n", result.TrustAnchor)
		}

		if len(result.VerifiedChains) > 0 {
			for i, chain := range result.VerifiedChains {
				fmt.Printf("\nVerified Chain %d:\n", i+1)
				for j, entry := range chain {
					fmt.Printf("  %d. %s\n", j+1, entry.Subject)
					if entry.IsCA {
						fmt.Printf("     [CA Certificate]\n")
					}
				}
			}
		}

		if len(result.Errors) > 0 {
			fmt.Printf("\n❌ Errors:\n")
			for _, e := range result.Errors {
				fmt.Printf("  - %s\n", e)
			}
		}

		if len(result.Warnings) > 0 {
			fmt.Printf("\n⚠️  Warnings:\n")
			for _, w := range result.Warnings {
				fmt.Printf("  - %s\n", w)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(checkHSTSCmd)
	rootCmd.AddCommand(checkCAACmd)
	rootCmd.AddCommand(checkSCTCmd)
	rootCmd.AddCommand(checkOCSPMustStapleCmd)
	rootCmd.AddCommand(checkKeyUsageComplianceCmd)
	rootCmd.AddCommand(checkSerialEntropyCmd)
	rootCmd.AddCommand(checkPolicyAnalysisCmd)
	rootCmd.AddCommand(checkNameConstraintsCmd)
	rootCmd.AddCommand(checkBundleCompletenessCmd)
	rootCmd.AddCommand(checkDistrustedCACmd)
	rootCmd.AddCommand(checkRevocationCmd)
	rootCmd.AddCommand(verifyChainCmd)
}
