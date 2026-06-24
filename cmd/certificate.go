package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cyberspacesec/certificate-skills/internal/display"
	"github.com/cyberspacesec/certificate-skills/pkg"
	"github.com/spf13/cobra"
)

func init() {
	// download command parameters
	downloadCmd.Flags().StringP("dir", "d", "", "Output directory for saved files")

	// compare command parameters
	compareCmd.Flags().StringP("target1", "1", "", "First certificate target (domain or file path)")
	compareCmd.Flags().StringP("target2", "2", "", "Second certificate target (domain or file path)")

	// validate command parameters
	validateCmd.Flags().StringP("cert", "c", "", "Path to certificate PEM file")
	validateCmd.Flags().StringP("key", "k", "", "Path to private key PEM file")

	// validate-fingerprint command parameters
	validateFingerprintCmd.Flags().StringP("fingerprint", "f", "", "Fingerprint hex string to validate")
	validateFingerprintCmd.Flags().StringP("hash-type", "", "", "Hash algorithm (md5, sha1, sha256)")

	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(parseCmd)
	rootCmd.AddCommand(fingerprintCmd)
	rootCmd.AddCommand(compareCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(validateFingerprintCmd)
}

var infoCmd = &cobra.Command{
	Use:   "info [domain:port or file] [domain2] [domain3]...",
	Short: "Display certificate information",
	Long: `Retrieve and display detailed information about certificates from domains or files.
Supports batch processing of multiple targets.

Examples:
  cert-skills info google.com
  cert-skills info google.com:443 baidu.com github.com
  cert-skills info certificate.pem
  cert-skills info google.com --output json`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targets := args
		outputFormat, _ := cmd.Flags().GetString("output")

		if len(targets) == 1 {
			target := targets[0]
			if isFileTarget(target) {
				certInfo, err := pkg.GetCertFromFile(target)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading certificate file: %v\n", err)
					os.Exit(1)
				}
				displayCertInfo(certInfo, outputFormat)
			} else {
				sslInfo, err := pkg.GetCertFromDomain(target)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error getting certificate from domain: %v\n", err)
					os.Exit(1)
				}
				displaySSLInfo(sslInfo, outputFormat)
			}
		} else {
			results := make([]pkg.BatchResult, 0, len(targets))
			for _, target := range targets {
				result := pkg.BatchResult{Target: target}
				if isFileTarget(target) {
					certInfo, err := pkg.GetCertFromFile(target)
					result.CertInfo = certInfo
					result.Error = err
				} else {
					sslInfo, err := pkg.GetCertFromDomain(target)
					result.SSLInfo = sslInfo
					result.Error = err
				}
				results = append(results, result)
			}
			displayBatchResults(results, outputFormat)
		}
	},
}

var downloadCmd = &cobra.Command{
	Use:   "download [domain:port]",
	Short: "Download certificate from a domain",
	Long:  `Download SSL/TLS certificate chain from a remote domain and save to PEM files.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		outputDir, _ := cmd.Flags().GetString("dir")
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.DownloadCertsFromDomain(domain, outputDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error downloading certificate: %v\n", err)
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

		fmt.Println(display.SectionHeader("Certificate Download Complete"))
		fmt.Println(display.Separator())
		fmt.Println(display.BulletKeyValue("Target", result.Target))
		fmt.Println(display.BulletKeyValue("Chain Length", fmt.Sprintf("%d certificates", result.ChainLength)))
		fmt.Printf("\nSaved Files:\n")
		for _, f := range result.SavedFiles {
			fmt.Printf("  - %s\n", f)
		}
	},
}

var parseCmd = &cobra.Command{
	Use:   "parse [certificate file]",
	Short: "Parse certificate file and display information",
	Long:  `Parse a certificate file (PEM/DER format) and display detailed information.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filename := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		certInfo, err := pkg.GetCertFromFile(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing certificate file: %v\n", err)
			os.Exit(1)
		}

		displayCertInfo(certInfo, outputFormat)
	},
}

var fingerprintCmd = &cobra.Command{
	Use:   "fingerprint [certificate file or domain:port]",
	Short: "Generate certificate fingerprints",
	Long:  `Generate various types of certificate fingerprints including SHA-1, SHA-256, and public key fingerprints for SSL pinning.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		var fingerprints map[string]string

		if isFileTarget(target) {
			certInfo, err := pkg.GetCertFromFile(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading certificate file: %v\n", err)
				os.Exit(1)
			}
			fingerprints = certInfo.Fingerprints
		} else {
			sslInfo, err := pkg.GetCertFromDomain(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting certificate from domain: %v\n", err)
				os.Exit(1)
			}
			fingerprints = sslInfo.PeerCerts.Certificates[0].Fingerprints
		}

		displayFingerprints(fingerprints, outputFormat)
	},
}

var compareCmd = &cobra.Command{
	Use:   "compare --target1 <domain-or-file> --target2 <domain-or-file>",
	Short: "Compare two certificates",
	Long: `Compare two SSL/TLS certificates to determine if they are identical or different.
Supports domain-to-domain, file-to-file, or domain-to-file comparisons.

Examples:
  cert-skills compare --target1 google.com --target2 github.com
  cert-skills compare --target1 cert1.pem --target2 cert2.pem
  cert-skills compare --target1 google.com --target2 /path/to/local.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		target1, _ := cmd.Flags().GetString("target1")
		target2, _ := cmd.Flags().GetString("target2")
		outputFormat, _ := cmd.Flags().GetString("output")

		if target1 == "" || target2 == "" {
			fmt.Fprintf(os.Stderr, "Error: both --target1 and --target2 are required\n")
			os.Exit(1)
		}

		var comparison *pkg.CertComparison
		var err error

		isFile1 := isFileTarget(target1)
		isFile2 := isFileTarget(target2)

		if isFile1 && isFile2 {
			comparison, err = pkg.CompareCertsFromFiles(target1, target2)
		} else if !isFile1 && !isFile2 {
			comparison, err = pkg.CompareCertsFromDomains(target1, target2)
		} else if isFile1 {
			cert1, err1 := pkg.ReadCertFromFile(target1)
			if err1 != nil {
				fmt.Fprintf(os.Stderr, "Error reading cert from %s: %v\n", target1, err1)
				os.Exit(1)
			}
			conn2, err2 := pkg.TLSDial(target2)
			if err2 != nil {
				fmt.Fprintf(os.Stderr, "Error connecting to %s: %v\n", target2, err2)
				os.Exit(1)
			}
			defer conn2.Close()
			certs2 := conn2.ConnectionState().PeerCertificates
			if len(certs2) == 0 {
				fmt.Fprintf(os.Stderr, "No certificates found for %s\n", target2)
				os.Exit(1)
			}
			comparison = pkg.CompareCerts(cert1, certs2[0])
		} else {
			conn1, err1 := pkg.TLSDial(target1)
			if err1 != nil {
				fmt.Fprintf(os.Stderr, "Error connecting to %s: %v\n", target1, err1)
				os.Exit(1)
			}
			defer conn1.Close()
			certs1 := conn1.ConnectionState().PeerCertificates
			if len(certs1) == 0 {
				fmt.Fprintf(os.Stderr, "No certificates found for %s\n", target1)
				os.Exit(1)
			}
			cert2, err2 := pkg.ReadCertFromFile(target2)
			if err2 != nil {
				fmt.Fprintf(os.Stderr, "Error reading cert from %s: %v\n", target2, err2)
				os.Exit(1)
			}
			comparison = pkg.CompareCerts(certs1[0], cert2)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error comparing certificates: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, err := json.MarshalIndent(comparison, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Comparison"))
		fmt.Println(display.Separator())
		if comparison.Match {
			fmt.Printf("✅ Certificates MATCH (identical SHA-256 fingerprint)\n")
		} else {
			fmt.Printf("❌ Certificates DO NOT MATCH\n")
		}
		fmt.Printf("\nMatch Details:\n")
		fmt.Printf("  SHA-256 Fingerprint: %s\n", boolIcon(comparison.MatchDetails.SHA256Match))
		fmt.Printf("  Public Key:          %s\n", boolIcon(comparison.MatchDetails.PublicKeyMatch))
		fmt.Printf("  Subject:             %s\n", boolIcon(comparison.MatchDetails.SubjectMatch))
		fmt.Printf("  Issuer:              %s\n", boolIcon(comparison.MatchDetails.IssuerMatch))

		fmt.Printf("\nCertificate 1: %s (Key: %s %d-bit)\n",
			comparison.Cert1Summary.Subject,
			comparison.Cert1Summary.PublicKeyAlgorithm,
			comparison.Cert1Summary.KeySize)
		fmt.Printf("Certificate 2: %s (Key: %s %d-bit)\n",
			comparison.Cert2Summary.Subject,
			comparison.Cert2Summary.PublicKeyAlgorithm,
			comparison.Cert2Summary.KeySize)

		if len(comparison.Differences) > 0 {
			fmt.Printf("\nDifferences:\n")
			for _, diff := range comparison.Differences {
				fmt.Printf("  %s:\n", diff.Field)
				fmt.Printf("    Cert 1: %s\n", diff.Cert1Val)
				fmt.Printf("    Cert 2: %s\n", diff.Cert2Val)
			}
		} else {
			fmt.Printf("\nNo differences found in checked fields.\n")
		}
	},
}

var validateCmd = &cobra.Command{
	Use:   "validate --cert <cert.pem> --key <key.pem>",
	Short: "Validate certificate and key files match",
	Long: `Validate that a certificate file and private key file are correctly formatted
PEM files and that the public key in the certificate matches the private key.
Supports RSA, ECDSA, and Ed25519 key types.

Examples:
  cert-skills validate --cert server.pem --key server-key.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		certPath, _ := cmd.Flags().GetString("cert")
		keyPath, _ := cmd.Flags().GetString("key")

		if certPath == "" || keyPath == "" {
			fmt.Fprintf(os.Stderr, "Error: both --cert and --key are required\n")
			os.Exit(1)
		}

		err := pkg.ValidateCertificateFiles(certPath, keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Validation failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✅ Certificate and key files are valid and match.\n")
		fmt.Printf("Certificate: %s\nPrivate Key: %s\n", certPath, keyPath)
	},
}

var validateFingerprintCmd = &cobra.Command{
	Use:   "validate-fingerprint --fingerprint <hex> --hash-type <type>",
	Short: "Validate a fingerprint format",
	Long: `Validate whether a fingerprint string has the correct format for a given hash algorithm.
Checks that the hex characters are valid and the length matches the expected hash output size.

Examples:
  cert-skills validate-fingerprint --fingerprint "ab:cd:ef:00:..." --hash-type sha256
  cert-skills validate-fingerprint --fingerprint "abcdef0011223344..." --hash-type sha1`,
	Run: func(cmd *cobra.Command, args []string) {
		fingerprint, _ := cmd.Flags().GetString("fingerprint")
		hashType, _ := cmd.Flags().GetString("hash-type")
		outputFormat, _ := cmd.Flags().GetString("output")

		if fingerprint == "" || hashType == "" {
			fmt.Fprintf(os.Stderr, "Error: both --fingerprint and --hash-type are required\n")
			os.Exit(1)
		}

		validHashTypes := map[string]bool{"md5": true, "sha1": true, "sha256": true}
		if !validHashTypes[hashType] {
			fmt.Fprintf(os.Stderr, "Error: invalid hash type '%s' (use md5, sha1, or sha256)\n", hashType)
			os.Exit(1)
		}

		valid := pkg.ValidateFingerprint(fingerprint, hashType)

		if outputFormat == "json" {
			result := map[string]interface{}{
				"fingerprint": fingerprint,
				"hash_type":   hashType,
				"is_valid":    valid,
			}
			if valid {
				result["message"] = fmt.Sprintf("Fingerprint is a valid %s hash", hashType)
			} else {
				result["message"] = fmt.Sprintf("Fingerprint is NOT a valid %s hash", hashType)
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		if valid {
			fmt.Printf("✅ Valid %s fingerprint\n", hashType)
		} else {
			fmt.Printf("❌ Invalid %s fingerprint (check length and hex characters)\n", hashType)
			os.Exit(1)
		}
	},
}
