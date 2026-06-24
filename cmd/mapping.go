package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cyberspacesec/certificate-skills/internal/display"
	"github.com/cyberspacesec/certificate-skills/pkg"
	"github.com/spf13/cobra"
)

var searchCTCmd = &cobra.Command{
	Use:   "search-ct [domain]",
	Short: "Search Certificate Transparency logs",
	Long: `Search Certificate Transparency (CT) logs for certificates associated
with a domain. Discovers subdomains, certificate issuance history, and
unauthorized certificates. Essential for cyberspace mapping.

Examples:
  cert-skills search-ct example.com
  cert-skills search-ct example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Searching CT logs for: %s\n", domain)

		result, err := pkg.CTSearch(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error searching CT logs: %v\n", err)
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

		fmt.Printf("\nCertificate Transparency Search Results\n")
		fmt.Printf("========================================\n")
		fmt.Printf("Domain:        %s\n", result.Target)
		fmt.Printf("Total Found:   %d certificates\n\n", result.TotalCount)

		// Display unique subdomains found
		subdomainSet := make(map[string]bool)
		for _, cert := range result.Certificates {
			names := strings.Split(cert.NameValue, "\n")
			for _, name := range names {
				name = strings.TrimSpace(name)
				if name != "" {
					subdomainSet[name] = true
				}
			}
		}

		var subdomains []string
		for sd := range subdomainSet {
			subdomains = append(subdomains, sd)
		}
		sort.Strings(subdomains)

		fmt.Printf("Discovered Subdomains (%d):\n", len(subdomains))
		for _, sd := range subdomains {
			fmt.Printf("  - %s\n", sd)
		}

		// Show certificate details (first 10)
		if len(result.Certificates) > 0 {
			displayCount := len(result.Certificates)
			if displayCount > 10 {
				displayCount = 10
			}

			fmt.Printf("\nCertificates (showing %d of %d):\n", displayCount, len(result.Certificates))
			for i := 0; i < displayCount; i++ {
				cert := result.Certificates[i]
				fmt.Printf("\n  [%d] %s\n", i+1, cert.CommonName)
				if cert.IssuerName != "" {
					fmt.Printf("      Issuer: %s\n", cert.IssuerName)
				}
				if cert.NotBefore != "" {
					fmt.Printf("      Valid: %s → %s\n", cert.NotBefore, cert.NotAfter)
				}
			}

			if len(result.Certificates) > 10 {
				fmt.Printf("\n  ... and %d more certificates\n", len(result.Certificates)-10)
			}
		}
	},
}

var ctEnumerateCmd = &cobra.Command{
	Use:   "ct-enumerate [domain]",
	Short: "Enumerate subdomains via CT logs",
	Long: `Enumerate subdomains through Certificate Transparency logs.
Enhanced CT search focused on cyberspace mapping - discovers all subdomains,
groups by issuer, identifies wildcard domains, tracks active vs expired.

Examples:
  cert-skills ct-enumerate example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CTEnumerateSubdomains(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		if result.Error != "" {
			fmt.Fprintf(os.Stderr, "Error: %s\n", result.Error)
			os.Exit(1)
		}

		fmt.Println(display.SectionHeader("CT Subdomain Enumeration"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Domain", result.Target))
		fmt.Printf("Total Certs: %d\n", result.TotalCerts)
		fmt.Printf("Active: %d | Expired: %d\n", result.ActiveCerts, result.ExpiredCerts)
		fmt.Printf("\nUnique Subdomains (%d):\n", result.SubdomainCount)
		for _, sd := range result.UniqueSubdomains {
			fmt.Printf("  - %s\n", sd)
		}
		if len(result.WildcardDomains) > 0 {
			fmt.Printf("\nWildcard Domains (%d):\n", len(result.WildcardDomains))
			for _, wd := range result.WildcardDomains {
				fmt.Printf("  - %s\n", wd)
			}
		}
	},
}

var searchCTByFingerprintCmd = &cobra.Command{
	Use:   "search-ct-fingerprint [fingerprint]",
	Short: "Search CT logs by certificate fingerprint",
	Long: `Search Certificate Transparency logs for a specific certificate by its
SHA-256 fingerprint. Useful for tracking a specific certificate across CT logs.

Examples:
  cert-skills search-ct-fingerprint A1B2C3D4E5F6... --output json
  cert-skills search-ct-fingerprint a1b2c3d4e5f6:7890:abcd:ef01:2345:6789:abcd:ef01:2345:6789:abcd:ef01:2345:6789`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fingerprint := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CTSearchByFingerprint(fingerprint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		if result.Error != "" {
			fmt.Fprintf(os.Stderr, "Error: %s\n", result.Error)
			os.Exit(1)
		}

		fmt.Println(display.SectionHeader("CT Fingerprint Search Results"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Fingerprint", fingerprint))
		fmt.Printf("Total Certificates: %d\n\n", result.TotalCount)

		for i, cert := range result.Certificates {
			fmt.Printf("Certificate #%d:\n", i+1)
			fmt.Printf("  Common Name: %s\n", cert.CommonName)
			fmt.Printf("  Issuer: %s\n", cert.Issuer)
			fmt.Printf("  Not Before: %s\n", cert.NotBefore)
			fmt.Printf("  Not After: %s\n", cert.NotAfter)
			if cert.FingerprintSHA256 != "" {
				fmt.Printf("  SHA-256: %s\n", cert.FingerprintSHA256)
			}
			fmt.Println()
		}
	},
}

var jarmCmd = &cobra.Command{
	Use:   "jarm [domain:port]",
	Short: "Generate JARM TLS fingerprint",
	Long: `Generate a JARM fingerprint by sending multiple TLS Client Hello probes
to the target server and analyzing the responses. JARM is used for:
- Service and server identification
- C2 infrastructure detection
- Cyberspace mapping and reconnaissance

Examples:
  cert-skills jarm google.com
  cert-skills jarm example.com:8443 --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Generating JARM fingerprint for: %s\n", target)

		result, err := pkg.JARMScan(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating JARM fingerprint: %v\n", err)
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

		fmt.Printf("\nJARM Fingerprint\n")
		fmt.Println(display.Separator())
		fmt.Printf("Target:        %s\n", result.Target)
		fmt.Printf("JARM Hash:     %s\n", result.JARMHash)
		if result.TLSVersion != "" {
			fmt.Printf("TLS Version:   %s\n", result.TLSVersion)
		}
		if result.CipherSuite != "" {
			fmt.Printf("Cipher Suite:  %s\n", result.CipherSuite)
		}
	},
}

var ja3Cmd = &cobra.Command{
	Use:   "ja3 [domain:port]",
	Short: "Generate JA3/JA3S TLS fingerprints",
	Long: `Generate JA3 (client) and JA3S (server) TLS fingerprints by connecting
to the target server. JA3 fingerprints are MD5 hashes of TLS handshake
parameters used for service identification and cyberspace mapping.

Examples:
  cert-skills ja3 google.com
  cert-skills ja3 example.com:8443 --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Generating JA3/JA3S fingerprints for: %s\n", target)

		result, err := pkg.JA3Scan(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating JA3 fingerprints: %v\n", err)
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

		fmt.Printf("\nJA3/JA3S Fingerprints\n")
		fmt.Println(display.Separator())
		fmt.Printf("Target:        %s\n", result.Target)
		fmt.Printf("JA3 (Client):  %s\n", result.JA3Hash)
		fmt.Printf("JA3S (Server): %s\n", result.JA3SHash)
		fmt.Printf("TLS Version:   %s\n", result.TLSVersion)
		fmt.Printf("Cipher Suite:  %s\n", result.CipherSuite)
		if result.ALPN != "" {
			fmt.Printf("ALPN:          %s\n", result.ALPN)
		}
		fmt.Printf("\nRaw Strings:\n")
		fmt.Printf("  JA3:  %s\n", result.JA3Raw)
		fmt.Printf("  JA3S: %s\n", result.JA3SRaw)
	},
}

var getTrustedDomainsCmd = &cobra.Command{
	Use:   "get-trusted-domains [domain:port]",
	Short: "Extract trusted domains from certificate",
	Long: `Extract all domain names trusted by a certificate, including wildcard
expansions. Returns exact domains, wildcard domains, and base domains.
Key for cyberspace mapping.

Examples:
  cert-skills get-trusted-domains google.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.GetTrustedDomains(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Trusted Domains"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Common Name", result.CommonName))
		if result.Organization != "" {
			fmt.Println(display.BulletKeyValue("Organization", result.Organization))
		}
		fmt.Printf("\nExact Domains (%d):\n", len(result.ExactDomains))
		for _, d := range result.ExactDomains {
			fmt.Printf("  - %s\n", d)
		}
		if len(result.WildcardDomains) > 0 {
			fmt.Printf("\nWildcard Domains (%d):\n", len(result.WildcardDomains))
			for _, d := range result.WildcardDomains {
				fmt.Printf("  - %s\n", d)
			}
		}
		fmt.Printf("\nBase Domains (%d):\n", len(result.BaseDomains))
		for _, d := range result.BaseDomains {
			fmt.Printf("  - %s\n", d)
		}
	},
}

var verifyHostnameCmd = &cobra.Command{
	Use:   "verify-hostname [domain:port]",
	Short: "Verify certificate hostname matching",
	Long: `Verify that a server's certificate matches the requested hostname.
Detects hostname mismatches, wildcard matches, and RFC 6125 compliance.

Examples:
  cert-skills verify-hostname google.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.VerifyHostname(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Hostname Verification"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		fmt.Println(display.BulletKeyValue("Hostname", result.Hostname))
		if result.Error != "" {
			fmt.Printf("Error: %s\n", result.Error)
			os.Exit(1)
		}
		if result.IsValid {
			fmt.Printf("Valid: ✅ Yes (match type: %s)\n", result.MatchType)
			if result.MatchedSAN != "" {
				fmt.Printf("Matched SAN: %s\n", result.MatchedSAN)
			}
		} else {
			fmt.Printf("Valid: ❌ No\n")
			fmt.Printf("Mismatch: %s\n", result.MismatchInfo)
		}
		if len(result.Warnings) > 0 {
			fmt.Printf("\nWarnings:\n")
			for _, w := range result.Warnings {
				fmt.Printf("  ⚠️  %s\n", w)
			}
		}
	},
}

var detectEVCmd = &cobra.Command{
	Use:   "detect-ev [domain:port]",
	Short: "Detect Extended Validation certificate",
	Long: `Detect whether a domain's certificate is an Extended Validation (EV) certificate.
EV certificates provide the highest level of identity assurance and display
the organization name in the browser address bar.

Examples:
  cert-skills detect-ev google.com
  cert-skills detect-ev example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Detecting EV certificate for: %s\n", target)

		result, err := pkg.DetectEV(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("\nEV Certificate Detection\n")
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		if result.IsEV {
			fmt.Printf("EV Certificate: ✅ Yes\n")
			fmt.Printf("EV Issuer: %s\n", result.EVIssuer)
			if result.Organization != "" {
				fmt.Println(display.BulletKeyValue("Organization", result.Organization))
			}
			if result.BusinessCategory != "" {
				fmt.Printf("Business Category: %s\n", result.BusinessCategory)
			}
			if result.Jurisdiction != "" {
				fmt.Printf("Jurisdiction: %s\n", result.Jurisdiction)
			}
		} else {
			fmt.Printf("EV Certificate: ❌ No\n")
			if result.Reason != "" {
				fmt.Printf("Reason: %s\n", result.Reason)
			}
		}
	},
}

func init() {
	// Register cyberspace mapping commands with rootCmd
	rootCmd.AddCommand(searchCTCmd)
	rootCmd.AddCommand(ctEnumerateCmd)
	rootCmd.AddCommand(searchCTByFingerprintCmd)
	rootCmd.AddCommand(jarmCmd)
	rootCmd.AddCommand(ja3Cmd)
	rootCmd.AddCommand(getTrustedDomainsCmd)
	rootCmd.AddCommand(verifyHostnameCmd)
	rootCmd.AddCommand(detectEVCmd)
	rootCmd.AddCommand(matchFingerprintsCmd)
	rootCmd.AddCommand(matchFingerprintByHashCmd)
	rootCmd.AddCommand(detectChangeCmd)

	matchFingerprintByHashCmd.Flags().String("type", "", "Fingerprint type: jarm, ja3, cert_sha256, or spki")
	matchFingerprintByHashCmd.Flags().String("hash", "", "Fingerprint hash to match, with or without colons")
}

var matchFingerprintsCmd = &cobra.Command{
	Use:     "match-fp [domain:port]",
	Aliases: []string{"match-fingerprints"},
	Short:   "Match TLS fingerprints against known services",
	Long: `Collect JARM, JA3, and certificate fingerprints from a target and
match them against a built-in database of known services (CDN, cloud, C2, VPN, etc.).

Essential for cyberspace mapping and C2 infrastructure detection.

Examples:
  cert-skills match-fp google.com
  cert-skills match-fingerprints google.com
  cert-skills match-fp suspicious-server.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Matching fingerprints for: %s\n", target)

		result, err := pkg.MatchFingerprints(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error matching fingerprints: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Fingerprint Matching Results"))
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		if result.JARMHash != "" {
			fmt.Println(display.BulletKeyValue("JARM", result.JARMHash))
		}
		if result.JA3Hash != "" {
			fmt.Println(display.BulletKeyValue("JA3", result.JA3Hash))
		}
		if result.CertHash != "" {
			fmt.Println(display.BulletKeyValue("Cert SHA-256", result.CertHash))
		}
		if result.SPKIHash != "" {
			fmt.Println(display.BulletKeyValue("SPKI SHA-256", result.SPKIHash))
		}

		if len(result.Matches) > 0 {
			fmt.Printf("\nMatches Found (%d):\n", len(result.Matches))
			for _, m := range result.Matches {
				var icon string
				switch m.Category {
				case "c2":
					icon = "🚨"
				case "cdn":
					icon = "☁️"
				case "cloud":
					icon = "🌐"
				case "vpn":
					icon = "🔒"
				default:
					icon = "🔍"
				}
				fmt.Printf("  %s [%s] %s (confidence: %.0f%%, source: %s)\n",
					icon, strings.ToUpper(m.Category), m.Label, m.Confidence*100, m.Source)
			}
		} else {
			fmt.Printf("\nNo known fingerprint matches found.\n")
		}
	},
}

var matchFingerprintByHashCmd = &cobra.Command{
	Use:   "match-fingerprint-by-hash",
	Short: "Match a single TLS fingerprint hash against known services",
	Long: `Match a single JARM, JA3, certificate SHA-256, or SPKI SHA-256 hash
against the built-in fingerprint database of known services.

This command is offline and does not connect to the target service.

Examples:
  cert-skills match-fingerprint-by-hash --type jarm --hash 29d29d15d29d29d21c29d29d29d29dea0f89a2e5e6f1eadc8e8d8e8d8e8d05
  cert-skills match-fingerprint-by-hash --type cert_sha256 --hash ab:cd:ef --output json`,
	Run: func(cmd *cobra.Command, args []string) {
		fpType, _ := cmd.Flags().GetString("type")
		hash, _ := cmd.Flags().GetString("hash")
		outputFormat, _ := cmd.Flags().GetString("output")

		fpType = strings.TrimSpace(strings.ToLower(fpType))
		hash = strings.TrimSpace(hash)
		if fpType == "" || hash == "" {
			fmt.Fprintln(os.Stderr, "Error: both --type and --hash are required")
			os.Exit(1)
		}
		if !isSupportedFingerprintMatchType(fpType) {
			fmt.Fprintf(os.Stderr, "Error: unsupported --type %q (use jarm, ja3, cert_sha256, or spki)\n", fpType)
			os.Exit(1)
		}

		matches := pkg.MatchFingerprintByHash(fpType, hash)
		if outputFormat == "json" {
			data, _ := json.MarshalIndent(matches, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Fingerprint Hash Matching Results"))
		fmt.Println(display.BulletKeyValue("Type", fpType))
		fmt.Println(display.BulletKeyValue("Hash", hash))
		if len(matches) == 0 {
			fmt.Printf("\nNo known fingerprint matches found.\n")
			return
		}

		fmt.Printf("\nMatches Found (%d):\n", len(matches))
		for _, m := range matches {
			fmt.Printf("  [%s] %s (confidence: %.0f%%, source: %s)\n",
				strings.ToUpper(m.Category), m.Label, m.Confidence*100, m.Source)
		}
	},
}

func isSupportedFingerprintMatchType(fpType string) bool {
	switch fpType {
	case "jarm", "ja3", "cert_sha256", "spki":
		return true
	default:
		return false
	}
}

var detectChangeCmd = &cobra.Command{
	Use:   "detect-change [domain:port]",
	Short: "Detect certificate changes from previous snapshot",
	Long: `Capture a certificate snapshot and compare it against the most recent
previous snapshot on disk. Detects certificate renewal, key rotation, issuer
changes, JARM changes, and expiry. Essential for continuous monitoring in
cyberspace mapping.

The --snapshot-dir flag controls where snapshots are stored (default: ~/.cert-skills/snapshots).
Use --save to persist the new snapshot after comparison.

Examples:
  cert-skills detect-change google.com
  cert-skills detect-change google.com --save --output json
  cert-skills detect-change google.com --snapshot-dir /tmp/snaps`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")
		saveSnapshot, _ := cmd.Flags().GetBool("save")
		snapshotDir, _ := cmd.Flags().GetString("snapshot-dir")

		if snapshotDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				home = "/tmp"
			}
			snapshotDir = filepath.Join(home, ".cert-skills", "snapshots")
		}

		store := pkg.NewSnapshotStore(snapshotDir)

		fmt.Printf("Detecting certificate changes for: %s\n", target)

		// Load previous snapshot
		prev, err := store.LoadLatest(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not load previous snapshot: %v\n", err)
		}

		result, err := pkg.DetectChange(target, prev)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error detecting change: %v\n", err)
			os.Exit(1)
		}

		// Save new snapshot if requested
		if saveSnapshot && result.CurrentSnap != nil {
			if err := store.Save(result.CurrentSnap); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not save snapshot: %v\n", err)
			} else {
				fmt.Printf("Snapshot saved to: %s\n", snapshotDir)
			}
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Change Detection"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))

		if result.HasChanged {
			changeIcon := "🔄"
			switch result.ChangeType {
			case "new":
				changeIcon = "🆕"
			case "renewed":
				changeIcon = "🔄"
			case "replaced":
				changeIcon = "⚠️"
			case "expired":
				changeIcon = "❌"
			}
			fmt.Printf("Changed: %s Yes (%s)\n", changeIcon, result.ChangeType)
		} else {
			fmt.Printf("Changed: ✅ No changes detected\n")
		}

		if result.CurrentSnap != nil {
			fmt.Println(display.BulletKeyValue("Cert SHA-256", result.CurrentSnap.CertSHA256))
			fmt.Println(display.BulletKeyValue("SPKI SHA-256", result.CurrentSnap.SPKISHA256))
			fmt.Println(display.BulletKeyValue("Issuer", result.CurrentSnap.Issuer))
			if !result.CurrentSnap.NotAfter.IsZero() {
				fmt.Printf("Valid: %s → %s\n",
					result.CurrentSnap.NotBefore.Format("2006-01-02"),
					result.CurrentSnap.NotAfter.Format("2006-01-02"))
			}
			if result.CurrentSnap.JARMHash != "" {
				fmt.Println(display.BulletKeyValue("JARM", result.CurrentSnap.JARMHash))
			}
		}

		if len(result.Changes) > 0 {
			fmt.Printf("\nChanges Detected:\n")
			for _, c := range result.Changes {
				fmt.Printf("  • %s\n", c)
			}
		}
	},
}

func init() {
	detectChangeCmd.Flags().Bool("save", false, "Save the new snapshot to disk after comparison")
	detectChangeCmd.Flags().String("snapshot-dir", "", "Directory to store snapshots (default: ~/.cert-skills/snapshots)")
}
