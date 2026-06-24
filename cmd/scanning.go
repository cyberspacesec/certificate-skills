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

func init() {
	// scan-ciphers command parameters
	scanCiphersCmd.Flags().String("tls-version", "", "TLS version to scan (1.0, 1.1, 1.2, 1.3)")

	rootCmd.AddCommand(scanProtocolsCmd)
	rootCmd.AddCommand(scanCiphersCmd)
	rootCmd.AddCommand(checkPFSCmd)
	rootCmd.AddCommand(checkSessionResumptionCmd)
	rootCmd.AddCommand(checkWildcardCmd)
}

var scanProtocolsCmd = &cobra.Command{
	Use:   "scan-protocols [domain:port]",
	Short: "Scan supported TLS protocol versions",
	Long: `Probe a server for supported TLS protocol versions by attempting
to connect with each version (TLS 1.0, 1.1, 1.2, 1.3) individually.

Examples:
  cert-skills scan-protocols google.com
  cert-skills scan-protocols example.com:8443 --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Scanning TLS protocol versions for: %s\n", target)

		result, err := pkg.TLSProtocolScan(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning protocols: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("TLS Protocol Scan Results"))
		fmt.Println(display.Separator())
		fmt.Printf("Target: %s\n\n", result.Target)

		for _, p := range result.Protocols {
			icon := "❌"
			if p.Supported {
				icon = "✅"
			}
			fmt.Printf("%s %s", icon, p.Version)
			if p.Supported {
				// Check if it's insecure
				if p.Version == "TLS 1.0" || p.Version == "TLS 1.1" {
					fmt.Printf(" ⚠️ (Insecure)")
				} else {
					fmt.Printf(" ✅ (Secure)")
				}
			}
			fmt.Printf("\n")
		}

		fmt.Printf("\nSummary:\n")
		fmt.Printf("  Supported:   %s\n", strings.Join(result.Summary.SupportedVersions, ", "))
		fmt.Printf("  Unsupported: %s\n", strings.Join(result.Summary.UnsupportedVersions, ", "))
		fmt.Printf("  Min Version: %s\n", result.Summary.MinimumVersion)
		fmt.Printf("  Max Version: %s\n", result.Summary.MaximumVersion)
		if result.Summary.IsSecure {
			fmt.Printf("  Overall:     ✅ Secure (no insecure protocols supported)\n")
		} else {
			fmt.Printf("  Overall:     ⚠️ Insecure (insecure protocols supported)\n")
		}
	},
}

var scanCiphersCmd = &cobra.Command{
	Use:   "scan-ciphers [domain:port]",
	Short: "Scan supported cipher suites",
	Long: `Probe a server for supported cipher suites by attempting
to connect with individual cipher suites.

Examples:
  cert-skills scan-ciphers google.com
  cert-skills scan-ciphers example.com:8443 --tls-version 1.3
  cert-skills scan-ciphers google.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")
		tlsVersionStr, _ := cmd.Flags().GetString("tls-version")

		var tlsVersion uint16
		switch tlsVersionStr {
		case "1.0":
			tlsVersion = 0x0301
		case "1.1":
			tlsVersion = 0x0302
		case "1.2":
			tlsVersion = 0x0303
		case "1.3":
			tlsVersion = 0x0304
		default:
			tlsVersion = 0 // auto-detect
		}

		fmt.Printf("Scanning cipher suites for: %s\n", target)

		result, err := pkg.CipherSuiteScan(target, tlsVersion)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning cipher suites: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Cipher Suite Scan Results"))
		fmt.Println(display.Separator())
		fmt.Printf("Target: %s | TLS Version: %s\n\n", result.Target, result.TLSVersion)

		fmt.Printf("Supported Cipher Suites:\n")
		for _, cs := range result.CipherSuites {
			if cs.Supported {
				icon := "✅"
				if !cs.Secure {
					icon = "⚠️"
				}
				fmt.Printf("  %s %s\n", icon, cs.CipherSuite)
			}
		}

		if len(result.Summary.WeakSuites) > 0 {
			fmt.Printf("\n⚠️ Weak Cipher Suites Detected:\n")
			for _, w := range result.Summary.WeakSuites {
				fmt.Printf("  ❌ %s\n", w)
			}
		}

		fmt.Printf("\nSummary:\n")
		fmt.Printf("  Total Tested:    %d\n", result.Summary.TotalTested)
		fmt.Printf("  Supported:       %d (%d secure, %d weak)\n",
			result.Summary.SupportedCount, result.Summary.SecureCount, result.Summary.WeakCount)
		if result.Summary.IsSecure {
			fmt.Printf("  Overall:         ✅ Secure (no weak cipher suites)\n")
		} else {
			fmt.Printf("  Overall:         ⚠️ Insecure (weak cipher suites detected)\n")
		}
	},
}

var checkPFSCmd = &cobra.Command{
	Use:   "check-pfs [domain:port]",
	Short: "Check Perfect Forward Secrecy support",
	Long: `Check whether a server supports Perfect Forward Secrecy (PFS).
PFS ensures that past sessions cannot be decrypted even if the server's
private key is compromised. Checks ECDHE/DHE key exchange.

Examples:
  cert-skills check-pfs google.com
  cert-skills check-pfs example.com:8443 --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Checking PFS support for: %s\n", target)

		result, err := pkg.CheckPFS(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("\nPFS Check Results\n")
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		if result.Error != "" {
			fmt.Printf("Error: %s\n", result.Error)
			os.Exit(1)
		}
		if result.SupportsPFS {
			fmt.Printf("PFS Supported: ✅ Yes\n")
			fmt.Printf("Negotiated Cipher: %s\n", result.PFSCipher)
			fmt.Printf("Key Exchange: %s\n", result.KeyExchange)
			if result.ECDHECurve != "" {
				fmt.Printf("ECDHE Curve: %s\n", result.ECDHECurve)
			}
		} else {
			fmt.Printf("PFS Supported: ❌ No\n")
			fmt.Printf("Negotiated Cipher: %s\n", result.PFSCipher)
		}
		if len(result.PFSCiphers) > 0 {
			fmt.Printf("\nPFS Cipher Suites (%d):\n", len(result.PFSCiphers))
			for _, c := range result.PFSCiphers {
				fmt.Printf("  ✅ %s\n", c)
			}
		}
		if len(result.NonPFSCiphers) > 0 {
			fmt.Printf("\nNon-PFS Cipher Suites (%d):\n", len(result.NonPFSCiphers))
			for _, c := range result.NonPFSCiphers {
				fmt.Printf("  ⚠️  %s\n", c)
			}
		}
	},
}

var checkSessionResumptionCmd = &cobra.Command{
	Use:   "check-session-resumption [domain:port]",
	Short: "Check TLS session resumption support",
	Long: `Check whether a server supports TLS session resumption via
session IDs or session tickets (RFC 5077).

Examples:
  cert-skills check-session-resumption google.com
  cert-skills check-session-resumption example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Checking session resumption for: %s\n", target)

		result, err := pkg.CheckSessionResumption(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Session Resumption Check"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		if result.Error != "" {
			fmt.Printf("Error: %s\n", result.Error)
			os.Exit(1)
		}
		fmt.Printf("Session ID Resumption: %s\n", boolIcon(result.SupportsSessionID))
		fmt.Printf("Session Ticket Resumption: %s\n", boolIcon(result.SupportsSessionTicket))
		fmt.Printf("TLS Version: %s\n", result.TLSVersion)
	},
}

var checkWildcardCmd = &cobra.Command{
	Use:   "check-wildcard [domain:port]",
	Short: "Analyze wildcard certificate patterns",
	Long: `Detect and analyze wildcard certificate patterns in a domain's certificate.
Identifies wildcard SANs, classifies wildcard levels, assesses security risk,
and lists covered domains. Essential for cyberspace mapping.

Examples:
  cert-skills check-wildcard example.com
  cert-skills check-wildcard /path/to/cert.pem --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.CheckWildcard(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Wildcard Certificate Analysis"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		if result.Error != "" {
			fmt.Printf("Error: %s\n", result.Error)
			os.Exit(1)
		}
		if result.IsWildcard {
			fmt.Printf("Wildcard: ✅ Yes\n")
			fmt.Printf("Risk Level: %s\n", result.RiskLevel)
			fmt.Printf("Risk Reason: %s\n", result.RiskReason)
		} else {
			fmt.Printf("Wildcard: ❌ No\n")
		}
		if len(result.WildcardNames) > 0 {
			fmt.Printf("\nWildcard Names:\n")
			for _, w := range result.WildcardNames {
				fmt.Printf("  * %s\n", w)
			}
		}
		if len(result.ExactNames) > 0 {
			fmt.Printf("\nExact Names (%d):\n", len(result.ExactNames))
			for _, n := range result.ExactNames {
				fmt.Printf("  - %s\n", n)
			}
		}
	},
}
