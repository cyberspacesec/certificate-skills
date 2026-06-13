package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/cyberspacesec/certificate-skills/internal/display"
	"github.com/cyberspacesec/certificate-skills/pkg"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", display.Error(err.Error()))
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "cert-skills",
	Short: "Certificate security toolkit for cyberspace mapping",
	Long: `cert-skills is a comprehensive certificate security toolkit for
cyberspace mapping and security assessment. It provides certificate
downloading, parsing, analysis, generation, vulnerability scanning,
and cyberspace mapping capabilities.

Designed for security researchers, system administrators, and
penetration testers who need to work with SSL/TLS certificates.`,
	Version:      version,
	SilenceUsage: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Show banner unless output is JSON
		outputFormat, _ := cmd.Flags().GetString("output")
		if outputFormat != "json" {
			display.Banner()
		}
	},
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

	// scan-ciphers 命令参数
	scanCiphersCmd.Flags().String("tls-version", "", "TLS version to scan (1.0, 1.1, 1.2, 1.3)")

	// check-hsts 命令
	rootCmd.AddCommand(checkHSTSCmd)
	rootCmd.AddCommand(checkWildcardCmd)
	rootCmd.AddCommand(getTrustedDomainsCmd)
	rootCmd.AddCommand(checkCAACmd)
	rootCmd.AddCommand(checkSCTCmd)
	rootCmd.AddCommand(verifyHostnameCmd)
	rootCmd.AddCommand(scanCertSecurityCmd)
	rootCmd.AddCommand(ctEnumerateCmd)
	rootCmd.AddCommand(searchCTByFingerprintCmd)
	rootCmd.AddCommand(checkDistrustedCACmd)
	rootCmd.AddCommand(checkOCSPMustStapleCmd)
	rootCmd.AddCommand(checkKeyUsageComplianceCmd)
	rootCmd.AddCommand(checkSerialEntropyCmd)
	rootCmd.AddCommand(checkPolicyAnalysisCmd)
	rootCmd.AddCommand(checkNameConstraintsCmd)
	rootCmd.AddCommand(checkBundleCompletenessCmd)
	rootCmd.AddCommand(checkPFSCmd)
	rootCmd.AddCommand(detectEVCmd)
	rootCmd.AddCommand(verifyChainCmd)
	rootCmd.AddCommand(checkSessionResumptionCmd)
	rootCmd.AddCommand(expiryMonitorCmd)

	// expiry-monitor command parameters
	expiryMonitorCmd.Flags().StringP("targets", "t", "", "Comma-separated list of domains or files to monitor")

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
	rootCmd.AddCommand(jarmCmd)
	rootCmd.AddCommand(ja3Cmd)
	rootCmd.AddCommand(scanVulnsCmd)
	rootCmd.AddCommand(searchCTCmd)
	rootCmd.AddCommand(checkRevocationCmd)
}

// --- Command Definitions ---

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

var generateCmd = &cobra.Command{
	Use:   "generate [options]",
	Short: "Generate self-signed certificates",
	Long: `Generate self-signed certificates for testing and development purposes.

Examples:
  cert-skills generate --common-name localhost
  cert-skills generate --common-name example.com --dns-names www.example.com,api.example.com
  cert-skills generate --common-name myserver --validity-days 730 --key-size 4096
  cert-skills generate --common-name ca-root --is-ca --validity-days 3650
  cert-skills generate --common-name example.com --key-type ecdsa
  cert-skills generate --common-name example.com --key-type ed25519`,
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
  cert-skills generate-csr --common-name example.com
  cert-skills generate-csr --common-name example.com --key-type ecdsa
  cert-skills generate-csr --common-name example.com --organization "My Org" --country US`,
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

// --- Display Functions ---

func displayCertInfo(certInfo *pkg.CertInfo, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(certInfo, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", display.Error(fmt.Sprintf("marshaling JSON: %v", err)))
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println(display.SectionHeader("Certificate Information"))
	fmt.Println(display.BulletKeyValue("Subject", certInfo.Subject))
	fmt.Println(display.BulletKeyValue("Issuer", certInfo.Issuer))
	fmt.Println(display.BulletKeyValue("Serial", certInfo.SerialNumber))
	fmt.Println(display.BulletKeyValue("Valid From", certInfo.NotBefore.Format("2006-01-02 15:04:05 UTC")))
	fmt.Println(display.BulletKeyValue("Valid To", certInfo.NotAfter.Format("2006-01-02 15:04:05 UTC")))
	fmt.Println(display.BulletKeyValue("Version", fmt.Sprintf("%d", certInfo.Version)))
	fmt.Println(display.BulletKeyValue("Is CA", display.BoolIcon(certInfo.IsCA)))
	fmt.Println(display.BulletKeyValue("Key Algorithm", certInfo.PublicKeyAlgorithm))
	if certInfo.KeySize > 0 {
		fmt.Println(display.BulletKeyValue("Key Size", fmt.Sprintf("%d bits", certInfo.KeySize)))
	}
	fmt.Println(display.BulletKeyValue("Signature", certInfo.SignatureAlgorithm))

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
		fmt.Println(display.BulletKeyValue("Ext Key Usage", strings.Join(certInfo.ExtKeyUsage, ", ")))
	}

	fmt.Println(display.SectionHeader("Fingerprints"))
	for hashType, fingerprint := range certInfo.Fingerprints {
		fmt.Println(display.BulletKeyValue(strings.ToUpper(hashType), fingerprint))
	}
}

func displaySSLInfo(sslInfo *pkg.SSLInfo, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(sslInfo, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", display.Error(fmt.Sprintf("marshaling JSON: %v", err)))
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println(display.SectionHeader("SSL/TLS Connection Information"))
	fmt.Println(display.BulletKeyValue("TLS Version", sslInfo.TLSVersion))
	fmt.Println(display.BulletKeyValue("Cipher Suite", sslInfo.CipherSuite))
	fmt.Println(display.BulletKeyValue("HTTP/2", display.BoolIcon(sslInfo.SupportsHTTP2)))
	fmt.Println(display.BulletKeyValue("OCSP Stapling", display.BoolIcon(sslInfo.HasOCSPStaple)))
	fmt.Println(display.BulletKeyValue("Handshake Time", sslInfo.HandshakeTime.String()))
	fmt.Println(display.BulletKeyValue("Connected At", sslInfo.ConnectedAt.Format("2006-01-02 15:04:05 UTC")))

	fmt.Println(display.SectionHeader(fmt.Sprintf("Certificate Chain (%d)", sslInfo.PeerCerts.ChainLength)))

	for i, cert := range sslInfo.PeerCerts.Certificates {
		if i > 0 {
			fmt.Println(display.ThinSeparator())
		}
		fmt.Println(display.Subtitle(fmt.Sprintf("Certificate %d", i+1)))
		displayCertInfo(&cert, "text")
	}
}

func displayFingerprints(fingerprints map[string]string, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(fingerprints, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", display.Error(fmt.Sprintf("marshaling JSON: %v", err)))
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println(display.SectionHeader("Certificate Fingerprints"))
	for hashType, fingerprint := range fingerprints {
		fmt.Println(display.BulletKeyValue(strings.ToUpper(hashType), fingerprint))
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
					fmt.Println(display.BulletKeyValue("Issuer", cert.Issuer))
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
			fmt.Fprintf(os.Stderr, "%s\n", display.Error(fmt.Sprintf("marshaling JSON: %v", err)))
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println(display.SectionHeader("Security Analysis Report"))
	fmt.Println(display.BulletKeyValue("Target", analysis.Target))
	fmt.Println(display.BulletKeyValue("Score", display.ScoreStyle(analysis.OverallScore)))
	fmt.Println(display.BulletKeyValue("Security Level", display.SeverityStyle(analysis.SecurityLevel)))

	// Certificate Analysis
	fmt.Println(display.SectionHeader("Certificate Analysis"))
	cert := analysis.CertificateCheck

	if cert.IsExpired {
		fmt.Printf("  %s\n", display.Error("EXPIRED"))
	} else if cert.IsExpiringSoon {
		fmt.Printf("  %s\n", display.Warning(fmt.Sprintf("Expiring Soon (%d days)", cert.DaysUntilExpiry)))
	} else {
		fmt.Printf("  %s\n", display.Success(fmt.Sprintf("Valid (%d days remaining)", cert.DaysUntilExpiry)))
	}

	sigDetail := cert.SignatureAlg
	if cert.WeakSignature {
		sigDetail += " " + display.Warning("(Weak)")
	}
	fmt.Println(display.BulletKeyValue("Signature", sigDetail))

	if cert.KeySize > 0 {
		fmt.Println(display.BulletKeyValue("Key Size", fmt.Sprintf("%d bits", cert.KeySize)))
	}

	if cert.IsSelfSigned {
		fmt.Printf("  %s\n", display.Warning("Self-signed certificate detected"))
	}

	if cert.WildcardCert {
		fmt.Printf("  %s\n", display.Info("Wildcard certificate"))
	}

	if cert.HasSAN {
		fmt.Println(display.BulletKeyValue("SANs", fmt.Sprintf("%d domains", cert.SANCount)))
	} else {
		fmt.Printf("  %s\n", display.Warning("No Subject Alternative Names"))
	}

	// TLS Connection Analysis
	fmt.Println(display.SectionHeader("TLS Connection Analysis"))
	tls := analysis.TLSCheck

	tlsDetail := tls.Version
	if tls.IsSecureVersion {
		tlsDetail += " " + display.Success("✓")
	} else {
		tlsDetail += " " + display.Error("(Insecure)")
	}
	fmt.Println(display.BulletKeyValue("TLS Version", tlsDetail))

	cipherDetail := tls.CipherSuite
	if tls.IsSecureCipherSuite {
		cipherDetail += " " + display.Success("✓")
	} else {
		cipherDetail += " " + display.Error("(Weak)")
	}
	fmt.Println(display.BulletKeyValue("Cipher Suite", cipherDetail))
	fmt.Println(display.BulletKeyValue("HTTP/2", display.BoolIcon(tls.SupportsHTTP2)))
	fmt.Println(display.BulletKeyValue("OCSP Stapling", display.BoolIcon(tls.HasOCSPStaple)))

	if tls.HSTS != nil {
		fmt.Println(display.BulletKeyValue("HSTS", display.BoolIcon(tls.HSTS.Enabled)))
		if tls.HSTS.Enabled {
			fmt.Println(display.BulletKeyValue("HSTS Max-Age", fmt.Sprintf("%d seconds (%.1f days)", tls.HSTS.MaxAge, float64(tls.HSTS.MaxAge)/86400.0)))
			fmt.Println(display.BulletKeyValue("IncludeSubDomains", display.BoolIcon(tls.HSTS.IncludeSubDomains)))
			fmt.Println(display.BulletKeyValue("Preload", display.BoolIcon(tls.HSTS.Preload)))
		}
	}

	// Expiration
	fmt.Println(display.SectionHeader("Expiration Check"))
	exp := analysis.ExpirationCheck
	fmt.Printf("  %s %s\n", display.StatusIcon(exp.Status), display.Value(exp.Message))
	fmt.Println(display.BulletKeyValue("Expiration Date", exp.ExpirationDate))

	// Security Issues
	if len(analysis.Issues) > 0 {
		fmt.Println(display.SectionHeader("Security Issues"))
		for i, issue := range analysis.Issues {
			fmt.Printf("  %s ", display.Dim(fmt.Sprintf("%d.", i+1)))
			fmt.Printf("%s ", display.SeverityStyle(issue.Severity))
			fmt.Printf("%s\n", display.Value(issue.Type))
			fmt.Printf("     %s\n", display.Dim(issue.Description))
			fmt.Printf("     %s\n", display.Label("Impact: "+issue.Impact))
		}
	} else {
		fmt.Printf("\n  %s\n", display.Success("No major security issues detected!"))
	}

	// Recommendations
	if len(analysis.Recommendations) > 0 {
		fmt.Println(display.SectionHeader("Recommendations"))
		for i, rec := range analysis.Recommendations {
			fmt.Printf("  %s %s\n", display.Dim(fmt.Sprintf("%d.", i+1)), display.Value(rec))
		}
	}
}

func displayGenerationResult(result *pkg.GenerationResult, format string) {
	if format == "json" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", display.Error(fmt.Sprintf("marshaling JSON: %v", err)))
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println(display.SectionHeader("Certificate Generation Complete"))
	fmt.Printf("  %s\n", display.Success(result.Message))
	fmt.Println(display.SectionHeader("Generated Files"))
	fmt.Println(display.BulletKeyValue("Certificate", result.CertificatePath))
	fmt.Println(display.BulletKeyValue("Private Key", result.PrivateKeyPath))

	fmt.Println(display.SectionHeader("Fingerprints"))
	for hashType, fingerprint := range result.Fingerprints {
		fmt.Println(display.BulletKeyValue(strings.ToUpper(hashType), fingerprint))
	}

	fmt.Println(display.SectionHeader("Next Steps"))
	fmt.Printf("  %s %s\n", display.Dim("1."), display.Value(fmt.Sprintf("cert-skills parse %s", result.CertificatePath)))
	fmt.Printf("  %s %s\n", display.Dim("2."), display.Value(fmt.Sprintf("cert-skills fingerprint %s", result.CertificatePath)))
	fmt.Printf("  %s %s\n", display.Dim("3."), display.Value("Use in your application or server configuration"))
	fmt.Printf("\n  %s\n", display.Warning("Note: This is a self-signed certificate for testing purposes only."))
}

// --- New Command Definitions ---

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

// --- Helper Functions ---

// isFileTarget checks if a target string looks like a file path
func isFileTarget(target string) bool {
	return pkg.IsFileTarget(target)
}

// boolIcon returns a checkmark or X icon for boolean values
func boolIcon(val bool) string {
	return display.BoolIcon(val)
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
