package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cyberspacesec/certificate-hacker/pkg"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "cert-hacker",
	Short: "Certificate security toolkit",
	Long: `cert-hacker is a comprehensive certificate security toolkit that provides
various certificate-related operations including downloading, parsing, analyzing,
generating certificates and security testing tools.

This tool is designed for security researchers, system administrators, and
penetration testers who need to work with SSL/TLS certificates.`,
	Version: version,
}

func init() {
	// 添加全局参数
	rootCmd.PersistentFlags().StringP("output", "o", "text", "Output format (text, json)")

	// download 命令参数
	downloadCmd.Flags().StringP("dir", "d", "", "Output directory for saved files")

	// generate 命令参数
	generateCmd.Flags().StringP("common-name", "n", "", "Common name (CN) for the certificate (required)")
	generateCmd.Flags().StringP("organization", "", "", "Organization name")
	generateCmd.Flags().StringP("country", "", "", "Country code (2 letters)")
	generateCmd.Flags().StringP("province", "", "", "Province or state")
	generateCmd.Flags().StringP("locality", "", "", "Locality or city")
	generateCmd.Flags().StringP("dns-names", "", "", "Comma-separated list of DNS names")
	generateCmd.Flags().IntP("validity-days", "", 365, "Certificate validity period in days")
	generateCmd.Flags().IntP("key-size", "", 2048, "Key size (RSA: 2048/4096, ECDSA: 256/384/521)")
	generateCmd.Flags().StringP("key-type", "", "rsa", "Key type (rsa, ecdsa, ed25519)")
	generateCmd.Flags().BoolP("is-ca", "", false, "Generate a CA certificate")
	generateCmd.Flags().StringP("output-cert", "", "", "Output certificate file path")
	generateCmd.Flags().StringP("output-key", "", "", "Output private key file path")

	// generate-csr 命令参数
	generateCSRCmd.Flags().StringP("common-name", "n", "", "Common name (CN) for the CSR (required)")
	generateCSRCmd.Flags().StringP("organization", "", "", "Organization name")
	generateCSRCmd.Flags().StringP("country", "", "", "Country code (2 letters)")
	generateCSRCmd.Flags().StringP("province", "", "", "Province or state")
	generateCSRCmd.Flags().StringP("locality", "", "", "Locality or city")
	generateCSRCmd.Flags().StringP("dns-names", "", "", "Comma-separated list of DNS names")
	generateCSRCmd.Flags().IntP("key-size", "", 2048, "Key size (RSA: 2048/4096, ECDSA: 256/384/521)")
	generateCSRCmd.Flags().StringP("key-type", "", "rsa", "Key type (rsa, ecdsa, ed25519)")

	// compare 命令参数
	compareCmd.Flags().StringP("target1", "1", "", "First certificate target (domain or file path)")
	compareCmd.Flags().StringP("target2", "2", "", "Second certificate target (domain or file path)")

	// batch-analyze 命令参数
	batchAnalyzeCmd.Flags().StringP("targets", "t", "", "Comma-separated list of domains to analyze")

	// validate 命令参数
	validateCmd.Flags().StringP("cert", "c", "", "Path to certificate PEM file")
	validateCmd.Flags().StringP("key", "k", "", "Path to private key PEM file")

	// validate-fingerprint 命令参数
	validateFingerprintCmd.Flags().StringP("fingerprint", "f", "", "Fingerprint hex string to validate")
	validateFingerprintCmd.Flags().StringP("hash-type", "", "", "Hash algorithm (md5, sha1, sha256)")

	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(parseCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(generateCSRCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(batchAnalyzeCmd)
	rootCmd.AddCommand(fingerprintCmd)
	rootCmd.AddCommand(compareCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(validateFingerprintCmd)
	rootCmd.AddCommand(scanProtocolsCmd)
	rootCmd.AddCommand(scanCiphersCmd)
}

// --- Command Definitions ---

var infoCmd = &cobra.Command{
	Use:   "info [domain:port or file] [domain2] [domain3]...",
	Short: "Display certificate information",
	Long: `Retrieve and display detailed information about certificates from domains or files.
Supports batch processing of multiple targets.

Examples:
  cert-hacker info google.com
  cert-hacker info google.com:443 baidu.com github.com
  cert-hacker info certificate.pem
  cert-hacker info google.com --output json`,
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

		fmt.Printf("Certificate Download Complete!\n")
		fmt.Printf("=============================\n")
		fmt.Printf("Target: %s\n", result.Target)
		fmt.Printf("Chain Length: %d certificates\n", result.ChainLength)
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

var generateCmd = &cobra.Command{
	Use:   "generate [options]",
	Short: "Generate self-signed certificates",
	Long: `Generate self-signed certificates for testing and development purposes.

Examples:
  cert-hacker generate --common-name localhost
  cert-hacker generate --common-name example.com --dns-names www.example.com,api.example.com
  cert-hacker generate --common-name myserver --validity-days 730 --key-size 4096
  cert-hacker generate --common-name ca-root --is-ca --validity-days 3650
  cert-hacker generate --common-name example.com --key-type ecdsa
  cert-hacker generate --common-name example.com --key-type ed25519`,
	Run: func(cmd *cobra.Command, args []string) {
		commonName, _ := cmd.Flags().GetString("common-name")
		organization, _ := cmd.Flags().GetString("organization")
		country, _ := cmd.Flags().GetString("country")
		province, _ := cmd.Flags().GetString("province")
		locality, _ := cmd.Flags().GetString("locality")
		dnsNamesStr, _ := cmd.Flags().GetString("dns-names")
		validityDays, _ := cmd.Flags().GetInt("validity-days")
		keySize, _ := cmd.Flags().GetInt("key-size")
		keyType, _ := cmd.Flags().GetString("key-type")
		isCA, _ := cmd.Flags().GetBool("is-ca")
		outputCert, _ := cmd.Flags().GetString("output-cert")
		outputKey, _ := cmd.Flags().GetString("output-key")
		outputFormat, _ := cmd.Flags().GetString("output")

		if commonName == "" {
			fmt.Fprintf(os.Stderr, "Error: --common-name is required\n")
			os.Exit(1)
		}

		var dnsNames []string
		if dnsNamesStr != "" {
			dnsNames = strings.Split(dnsNamesStr, ",")
			for i, name := range dnsNames {
				dnsNames[i] = strings.TrimSpace(name)
			}
		}

		req := pkg.CertificateRequest{
			CommonName:     commonName,
			Organization:   organization,
			Country:        country,
			Province:       province,
			Locality:       locality,
			DNSNames:       dnsNames,
			ValidityDays:   validityDays,
			KeySize:        keySize,
			KeyType:        keyType,
			IsCA:           isCA,
			OutputCertPath: outputCert,
			OutputKeyPath:  outputKey,
		}

		fmt.Printf("Generating certificate for: %s\n", commonName)

		result, err := pkg.GenerateSelfSignedCert(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating certificate: %v\n", err)
			os.Exit(1)
		}

		if err := pkg.ValidateCertificateFiles(result.CertificatePath, result.PrivateKeyPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Certificate validation failed: %v\n", err)
		}

		displayGenerationResult(result, outputFormat)
	},
}

var generateCSRCmd = &cobra.Command{
	Use:   "generate-csr [options]",
	Short: "Generate a Certificate Signing Request (CSR)",
	Long: `Generate a CSR for submitting to a Certificate Authority.
The private key is generated but NOT saved to disk — only the CSR is output.

Examples:
  cert-hacker generate-csr --common-name example.com
  cert-hacker generate-csr --common-name example.com --key-type ecdsa
  cert-hacker generate-csr --common-name example.com --organization "My Org" --country US`,
	Run: func(cmd *cobra.Command, args []string) {
		commonName, _ := cmd.Flags().GetString("common-name")
		organization, _ := cmd.Flags().GetString("organization")
		country, _ := cmd.Flags().GetString("country")
		province, _ := cmd.Flags().GetString("province")
		locality, _ := cmd.Flags().GetString("locality")
		dnsNamesStr, _ := cmd.Flags().GetString("dns-names")
		keySize, _ := cmd.Flags().GetInt("key-size")
		keyType, _ := cmd.Flags().GetString("key-type")

		if commonName == "" {
			fmt.Fprintf(os.Stderr, "Error: --common-name is required\n")
			os.Exit(1)
		}

		var dnsNames []string
		if dnsNamesStr != "" {
			dnsNames = strings.Split(dnsNamesStr, ",")
			for i, name := range dnsNames {
				dnsNames[i] = strings.TrimSpace(name)
			}
		}

		req := pkg.CertificateRequest{
			CommonName:   commonName,
			Organization: organization,
			Country:      country,
			Province:     province,
			Locality:     locality,
			DNSNames:     dnsNames,
			KeySize:      keySize,
			KeyType:      keyType,
		}

		csrPEM, err := pkg.GenerateCSR(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating CSR: %v\n", err)
			os.Exit(1)
		}

		fmt.Print(csrPEM)
	},
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [domain:port]",
	Short: "Analyze SSL/TLS connection security",
	Long: `Perform comprehensive security analysis of SSL/TLS connections including:
- Certificate validation and expiration check
- TLS protocol version and cipher suite analysis
- Security vulnerability assessment
- Detailed security recommendations

Examples:
  cert-hacker analyze google.com
  cert-hacker analyze example.com:8443
  cert-hacker analyze google.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Analyzing SSL/TLS security for: %s\n", target)

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
  cert-hacker batch-analyze --targets google.com,github.com,cloudflare.com
  cert-hacker batch-analyze --targets google.com,github.com --output json`,
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
		fmt.Printf("==============================\n")
		fmt.Printf("Total Targets: %d\n", result.TotalCount)
		fmt.Printf("Summary: ✅ Good: %d | ⚠️ Medium: %d | 🚨 High: %d | 💀 Critical: %d\n",
			result.Summary.GoodCount, result.Summary.MediumCount,
			result.Summary.HighCount, result.Summary.CriticalCount)
		fmt.Printf("Average Score: %d/100\n\n", result.Summary.AverageScore)

		for i, a := range result.Results {
			var levelIcon string
			switch a.SecurityLevel {
			case "Good":
				levelIcon = "✅"
			case "Medium":
				levelIcon = "⚠️"
			case "High":
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
  cert-hacker compare --target1 google.com --target2 github.com
  cert-hacker compare --target1 cert1.pem --target2 cert2.pem
  cert-hacker compare --target1 google.com --target2 /path/to/local.pem`,
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

		fmt.Printf("\nCertificate Comparison\n")
		fmt.Printf("======================\n")
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
  cert-hacker validate --cert server.pem --key server-key.pem`,
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
  cert-hacker validate-fingerprint --fingerprint "ab:cd:ef:00:..." --hash-type sha256
  cert-hacker validate-fingerprint --fingerprint "abcdef0011223344..." --hash-type sha1`,
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

var scanProtocolsCmd = &cobra.Command{
	Use:   "scan-protocols [domain:port]",
	Short: "Scan supported TLS protocol versions",
	Long: `Probe a server for supported TLS protocol versions by attempting
to connect with each version (TLS 1.0, 1.1, 1.2, 1.3) individually.

Examples:
  cert-hacker scan-protocols google.com
  cert-hacker scan-protocols example.com:8443 --output json`,
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

		fmt.Printf("\nTLS Protocol Scan Results\n")
		fmt.Printf("=========================\n")
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
  cert-hacker scan-ciphers google.com
  cert-hacker scan-ciphers example.com:8443 --tls-version 1.3
  cert-hacker scan-ciphers google.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		fmt.Printf("Scanning cipher suites for: %s\n", target)

		result, err := pkg.CipherSuiteScan(target, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning cipher suites: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("\nCipher Suite Scan Results\n")
		fmt.Printf("=========================\n")
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

// --- Display Functions ---

func displayCertInfo(certInfo *pkg.CertInfo, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(certInfo, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Certificate Information:\n")
	fmt.Printf("========================\n")
	fmt.Printf("Subject: %s\n", certInfo.Subject)
	fmt.Printf("Issuer: %s\n", certInfo.Issuer)
	fmt.Printf("Serial Number: %s\n", certInfo.SerialNumber)
	fmt.Printf("Valid From: %s\n", certInfo.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Valid To: %s\n", certInfo.NotAfter.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Version: %d\n", certInfo.Version)
	fmt.Printf("Is CA: %t\n", certInfo.IsCA)
	fmt.Printf("Public Key Algorithm: %s\n", certInfo.PublicKeyAlgorithm)
	if certInfo.KeySize > 0 {
		fmt.Printf("Key Size: %d bits\n", certInfo.KeySize)
	}
	fmt.Printf("Signature Algorithm: %s\n", certInfo.SignatureAlgorithm)

	if len(certInfo.DNSNames) > 0 {
		fmt.Printf("DNS Names: %s\n", strings.Join(certInfo.DNSNames, ", "))
	}

	if len(certInfo.IPAddresses) > 0 {
		fmt.Printf("IP Addresses: %s\n", strings.Join(certInfo.IPAddresses, ", "))
	}

	if len(certInfo.KeyUsage) > 0 {
		fmt.Printf("Key Usage: %s\n", strings.Join(certInfo.KeyUsage, ", "))
	}

	if len(certInfo.ExtKeyUsage) > 0 {
		fmt.Printf("Extended Key Usage: %s\n", strings.Join(certInfo.ExtKeyUsage, ", "))
	}

	fmt.Printf("\nFingerprints:\n")
	fmt.Printf("=============\n")
	for hashType, fingerprint := range certInfo.Fingerprints {
		fmt.Printf("%-20s: %s\n", strings.ToUpper(hashType), fingerprint)
	}
}

func displaySSLInfo(sslInfo *pkg.SSLInfo, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(sslInfo, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Printf("SSL/TLS Connection Information:\n")
	fmt.Printf("===============================\n")
	fmt.Printf("TLS Version: %s\n", sslInfo.TLSVersion)
	fmt.Printf("Cipher Suite: %s\n", sslInfo.CipherSuite)
	fmt.Printf("HTTP/2 Support: %s\n", boolIcon(sslInfo.SupportsHTTP2))
	fmt.Printf("OCSP Stapling: %s\n", boolIcon(sslInfo.HasOCSPStaple))
	fmt.Printf("Handshake Time: %v\n", sslInfo.HandshakeTime)
	fmt.Printf("Connected At: %s\n", sslInfo.ConnectedAt.Format("2006-01-02 15:04:05 UTC"))

	fmt.Printf("\nCertificate Chain (%d certificates):\n", sslInfo.PeerCerts.ChainLength)
	fmt.Printf("=====================================\n")

	for i, cert := range sslInfo.PeerCerts.Certificates {
		fmt.Printf("\nCertificate %d:\n", i+1)
		fmt.Printf("--------------\n")
		displayCertInfo(&cert, "text")
		if i < len(sslInfo.PeerCerts.Certificates)-1 {
			fmt.Println("\n" + strings.Repeat("-", 50))
		}
	}
}

func displayFingerprints(fingerprints map[string]string, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(fingerprints, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Certificate Fingerprints:\n")
	fmt.Printf("========================\n")
	for hashType, fingerprint := range fingerprints {
		fmt.Printf("%-20s: %s\n", strings.ToUpper(hashType), fingerprint)
	}
}

func displayBatchResults(results []pkg.BatchResult, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Batch Certificate Analysis Results:\n")
	fmt.Printf("===================================\n")

	successCount := 0
	errorCount := 0

	for i, result := range results {
		fmt.Printf("\n[%d/%d] Target: %s\n", i+1, len(results), result.Target)
		fmt.Printf("%s\n", strings.Repeat("-", 50))

		if result.Error != nil {
			fmt.Printf("❌ Error: %v\n", result.Error)
			errorCount++
		} else {
			fmt.Printf("✅ Success\n")
			successCount++

			if result.SSLInfo != nil {
				fmt.Printf("TLS Version: %s\n", result.SSLInfo.TLSVersion)
				fmt.Printf("Cipher Suite: %s\n", result.SSLInfo.CipherSuite)
				if len(result.SSLInfo.PeerCerts.Certificates) > 0 {
					cert := result.SSLInfo.PeerCerts.Certificates[0]
					fmt.Printf("Subject: %s\n", cert.Subject)
					fmt.Printf("Issuer: %s\n", cert.Issuer)
					fmt.Printf("Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))
					if cert.KeySize > 0 {
						fmt.Printf("Key Size: %d bits\n", cert.KeySize)
					}

					if len(cert.DNSNames) > 0 {
						fmt.Printf("DNS Names: %s\n", strings.Join(cert.DNSNames[:minInt(3, len(cert.DNSNames))], ", "))
						if len(cert.DNSNames) > 3 {
							fmt.Printf("... and %d more\n", len(cert.DNSNames)-3)
						}
					}
				}
			} else if result.CertInfo != nil {
				fmt.Printf("Subject: %s\n", result.CertInfo.Subject)
				fmt.Printf("Issuer: %s\n", result.CertInfo.Issuer)
				fmt.Printf("Valid Until: %s\n", result.CertInfo.NotAfter.Format("2006-01-02 15:04:05 UTC"))
				if result.CertInfo.KeySize > 0 {
					fmt.Printf("Key Size: %d bits\n", result.CertInfo.KeySize)
				}
			}
		}
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 50))
	fmt.Printf("Summary: %d successful, %d failed, %d total\n", successCount, errorCount, len(results))
}

func displaySecurityAnalysis(analysis *pkg.SecurityAnalysis, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(analysis, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Printf("\nSecurity Analysis Report\n")
	fmt.Printf("========================\n")
	fmt.Printf("Target: %s\n", analysis.Target)
	fmt.Printf("Overall Security Score: %d/100\n", analysis.OverallScore)

	var levelIcon string
	switch analysis.SecurityLevel {
	case "Good":
		levelIcon = "✅"
	case "Medium":
		levelIcon = "⚠️"
	case "High":
		levelIcon = "🚨"
	case "Critical":
		levelIcon = "💀"
	default:
		levelIcon = "❓"
	}
	fmt.Printf("Security Level: %s %s\n", levelIcon, analysis.SecurityLevel)

	// 证书检查结果
	fmt.Printf("\nCertificate Analysis:\n")
	fmt.Printf("=====================\n")
	cert := analysis.CertificateCheck

	if cert.IsExpired {
		fmt.Printf("❌ Certificate Status: EXPIRED\n")
	} else if cert.IsExpiringSoon {
		fmt.Printf("⚠️  Certificate Status: Expiring Soon (%d days)\n", cert.DaysUntilExpiry)
	} else {
		fmt.Printf("✅ Certificate Status: Valid (%d days remaining)\n", cert.DaysUntilExpiry)
	}

	fmt.Printf("Signature Algorithm: %s", cert.SignatureAlg)
	if cert.WeakSignature {
		fmt.Printf(" ⚠️  (Weak)")
	}
	fmt.Printf("\n")

	if cert.KeySize > 0 {
		fmt.Printf("Key Size: %d bits\n", cert.KeySize)
	}

	if cert.IsSelfSigned {
		fmt.Printf("⚠️  Self-signed certificate detected\n")
	}

	if cert.WildcardCert {
		fmt.Printf("🔸 Wildcard certificate\n")
	}

	if cert.HasSAN {
		fmt.Printf("✅ Subject Alternative Names: %d domains\n", cert.SANCount)
	} else {
		fmt.Printf("⚠️  No Subject Alternative Names\n")
	}

	// TLS检查结果
	fmt.Printf("\nTLS Connection Analysis:\n")
	fmt.Printf("========================\n")
	tls := analysis.TLSCheck

	fmt.Printf("TLS Version: %s", tls.Version)
	if tls.IsSecureVersion {
		fmt.Printf(" ✅")
	} else {
		fmt.Printf(" ❌ (Insecure)")
	}
	fmt.Printf("\n")

	fmt.Printf("Cipher Suite: %s", tls.CipherSuite)
	if tls.IsSecureCipherSuite {
		fmt.Printf(" ✅")
	} else {
		fmt.Printf(" ❌ (Weak)")
	}
	fmt.Printf("\n")

	fmt.Printf("HTTP/2 Support: %s\n", boolIcon(tls.SupportsHTTP2))
	fmt.Printf("OCSP Stapling: %s\n", boolIcon(tls.HasOCSPStaple))

	if tls.HSTS != nil {
		fmt.Printf("HSTS: %s\n", boolIcon(tls.HSTS.Enabled))
		if tls.HSTS.Enabled {
			fmt.Printf("HSTS Max-Age: %d seconds (%.1f days)\n", tls.HSTS.MaxAge, float64(tls.HSTS.MaxAge)/86400.0)
			fmt.Printf("HSTS IncludeSubDomains: %s\n", boolIcon(tls.HSTS.IncludeSubDomains))
			fmt.Printf("HSTS Preload: %s\n", boolIcon(tls.HSTS.Preload))
		}
	}

	// 过期检查
	fmt.Printf("\nExpiration Check:\n")
	fmt.Printf("=================\n")
	exp := analysis.ExpirationCheck

	var statusIcon string
	switch exp.Status {
	case "Good":
		statusIcon = "✅"
	case "Warning":
		statusIcon = "⚠️"
	case "Critical":
		statusIcon = "🚨"
	case "Expired":
		statusIcon = "❌"
	}
	fmt.Printf("%s %s\n", statusIcon, exp.Message)
	fmt.Printf("Expiration Date: %s\n", exp.ExpirationDate)

	// 安全问题
	if len(analysis.Issues) > 0 {
		fmt.Printf("\nSecurity Issues Found:\n")
		fmt.Printf("======================\n")
		for i, issue := range analysis.Issues {
			var severityIcon string
			switch issue.Severity {
			case "Critical":
				severityIcon = "💀"
			case "High":
				severityIcon = "🚨"
			case "Medium":
				severityIcon = "⚠️"
			case "Low":
				severityIcon = "🔸"
			}

			fmt.Printf("%d. %s [%s] %s\n", i+1, severityIcon, issue.Severity, issue.Type)
			fmt.Printf("   Description: %s\n", issue.Description)
			fmt.Printf("   Impact: %s\n", issue.Impact)
			if i < len(analysis.Issues)-1 {
				fmt.Println()
			}
		}
	} else {
		fmt.Printf("\n✅ No major security issues detected!\n")
	}

	// 安全建议
	fmt.Printf("\nSecurity Recommendations:\n")
	fmt.Printf("==========================\n")
	for i, rec := range analysis.Recommendations {
		fmt.Printf("%d. %s\n", i+1, rec)
	}
}

func displayGenerationResult(result *pkg.GenerationResult, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Printf("\nCertificate Generation Complete!\n")
	fmt.Printf("=================================\n")
	fmt.Printf("✅ %s\n", result.Message)
	fmt.Printf("\nGenerated Files:\n")
	fmt.Printf("Certificate: %s\n", result.CertificatePath)
	fmt.Printf("Private Key: %s\n", result.PrivateKeyPath)

	fmt.Printf("\nCertificate Fingerprints:\n")
	fmt.Printf("=========================\n")
	for hashType, fingerprint := range result.Fingerprints {
		fmt.Printf("%-20s: %s\n", strings.ToUpper(hashType), fingerprint)
	}

	fmt.Printf("\nNext Steps:\n")
	fmt.Printf("===========\n")
	fmt.Printf("1. Verify the certificate: cert-hacker parse %s\n", result.CertificatePath)
	fmt.Printf("2. Check fingerprints: cert-hacker fingerprint %s\n", result.CertificatePath)
	fmt.Printf("3. Use in your application or server configuration\n")
	fmt.Printf("\n⚠️  Note: This is a self-signed certificate for testing purposes only.\n")
}

// --- Helper Functions ---

// isFileTarget checks if a target string looks like a file path
func isFileTarget(target string) bool {
	fileExts := []string{".pem", ".crt", ".cer", ".der", ".p7b", ".p7c"}
	for _, ext := range fileExts {
		if strings.HasSuffix(strings.ToLower(target), ext) {
			return true
		}
	}
	return false
}

// boolIcon returns a checkmark or X icon for boolean values
func boolIcon(val bool) string {
	if val {
		return "✅ Yes"
	}
	return "❌ No"
}

// minInt returns the smaller of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseIPAddresses parses comma-separated IP address strings into net.IP slice
func parseIPAddresses(ipStr string) []net.IP {
	if ipStr == "" {
		return nil
	}
	var ips []net.IP
	for _, s := range strings.Split(ipStr, ",") {
		s = strings.TrimSpace(s)
		ip := net.ParseIP(s)
		if ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}
