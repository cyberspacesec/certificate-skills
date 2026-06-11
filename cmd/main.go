package main

import (
	"encoding/json"
	"fmt"
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
	
	// 为各个命令添加特定参数
	downloadCmd.Flags().StringP("output", "o", "", "Output file name")
	
	// generate命令参数
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
	
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(parseCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(fingerprintCmd)
}

// infoCmd displays certificate information
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
			// 单个目标处理
			target := targets[0]
			
			// 判断是域名还是文件
			if strings.Contains(target, ".pem") || strings.Contains(target, ".crt") || strings.Contains(target, ".cer") {
				// 从文件获取证书
				certInfo, err := pkg.GetCertFromFile(target)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading certificate file: %v\n", err)
					os.Exit(1)
				}
				
				displayCertInfo(certInfo, outputFormat)
			} else {
				// 从域名获取证书
				sslInfo, err := pkg.GetCertFromDomain(target)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error getting certificate from domain: %v\n", err)
					os.Exit(1)
				}
				
				displaySSLInfo(sslInfo, outputFormat)
			}
		} else {
			// 批量处理多个目标
			results := make([]pkg.BatchResult, 0, len(targets))
			
			for _, target := range targets {
				result := pkg.BatchResult{
					Target: target,
				}
				
				// 判断是域名还是文件
				if strings.Contains(target, ".pem") || strings.Contains(target, ".crt") || strings.Contains(target, ".cer") {
					// 从文件获取证书
					certInfo, err := pkg.GetCertFromFile(target)
					result.CertInfo = certInfo
					result.Error = err
				} else {
					// 从域名获取证书
					sslInfo, err := pkg.GetCertFromDomain(target)
					result.SSLInfo = sslInfo
					result.Error = err
				}
				
				results = append(results, result)
			}
			
			// 显示批量结果
			displayBatchResults(results, outputFormat)
		}
	},
}

// downloadCmd downloads certificates
var downloadCmd = &cobra.Command{
	Use:   "download [domain:port]",
	Short: "Download certificate from a domain",
	Long:  `Download SSL/TLS certificate chain from a remote domain and save to PEM files.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.DownloadCertsFromDomain(domain, "")
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

// parseCmd parses certificate files
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

// generateCmd generates certificates
var generateCmd = &cobra.Command{
	Use:   "generate [options]",
	Short: "Generate self-signed certificates",
	Long: `Generate self-signed certificates for testing and development purposes.

Examples:
  cert-hacker generate --common-name localhost
  cert-hacker generate --common-name example.com --dns-names www.example.com,api.example.com
  cert-hacker generate --common-name myserver --validity-days 730 --key-size 4096
  cert-hacker generate --common-name ca-root --is-ca --validity-days 3650`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取命令行参数
		commonName, _ := cmd.Flags().GetString("common-name")
		organization, _ := cmd.Flags().GetString("organization")
		country, _ := cmd.Flags().GetString("country")
		province, _ := cmd.Flags().GetString("province")
		locality, _ := cmd.Flags().GetString("locality")
		dnsNamesStr, _ := cmd.Flags().GetString("dns-names")
		validityDays, _ := cmd.Flags().GetInt("validity-days")
		keySize, _ := cmd.Flags().GetInt("key-size")
		isCA, _ := cmd.Flags().GetBool("is-ca")
			keyType, _ := cmd.Flags().GetString("key-type")
		outputCert, _ := cmd.Flags().GetString("output-cert")
		outputKey, _ := cmd.Flags().GetString("output-key")
		outputFormat, _ := cmd.Flags().GetString("output")

		// 验证必需参数
		if commonName == "" {
			fmt.Fprintf(os.Stderr, "Error: --common-name is required\n")
			os.Exit(1)
		}

		// 解析DNS名称
		var dnsNames []string
		if dnsNamesStr != "" {
			dnsNames = strings.Split(dnsNamesStr, ",")
			for i, name := range dnsNames {
				dnsNames[i] = strings.TrimSpace(name)
			}
		}

		// 创建证书生成请求
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

		// 生成证书
		result, err := pkg.GenerateSelfSignedCert(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating certificate: %v\n", err)
			os.Exit(1)
		}

		// 验证生成的文件
		if err := pkg.ValidateCertificateFiles(result.CertificatePath, result.PrivateKeyPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Certificate validation failed: %v\n", err)
		}

		// 显示结果
		displayGenerationResult(result, outputFormat)
	},
}

// analyzeCmd analyzes SSL/TLS connections
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

// fingerprintCmd generates certificate fingerprints
var fingerprintCmd = &cobra.Command{
	Use:   "fingerprint [certificate file or domain:port]",
	Short: "Generate certificate fingerprints",
	Long:  `Generate various types of certificate fingerprints including SHA-1, SHA-256, and public key fingerprints for SSL pinning.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		outputFormat, _ := cmd.Flags().GetString("output")
		
		var fingerprints map[string]string
		
		// 判断是域名还是文件
		if strings.Contains(target, ".pem") || strings.Contains(target, ".crt") || strings.Contains(target, ".cer") {
			// 从文件获取证书
			certInfo, err := pkg.GetCertFromFile(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading certificate file: %v\n", err)
				os.Exit(1)
			}
			fingerprints = certInfo.Fingerprints
		} else {
			// 从域名获取证书
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

// 显示函数

// displayCertInfo 显示证书信息
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
	
	// 文本格式显示
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

// displaySSLInfo 显示SSL连接信息
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
	
	// 文本格式显示
	fmt.Printf("SSL/TLS Connection Information:\n")
	fmt.Printf("===============================\n")
	fmt.Printf("TLS Version: %s\n", sslInfo.TLSVersion)
	fmt.Printf("Cipher Suite: %s\n", sslInfo.CipherSuite)
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

// displayFingerprints 显示证书指纹
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
	
	// 文本格式显示
	fmt.Printf("Certificate Fingerprints:\n")
	fmt.Printf("========================\n")
	for hashType, fingerprint := range fingerprints {
		fmt.Printf("%-20s: %s\n", strings.ToUpper(hashType), fingerprint)
	}
}

// displayBatchResults 显示批量处理结果
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
	
	// 文本格式显示
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
				// 显示关键SSL信息
				fmt.Printf("TLS Version: %s\n", result.SSLInfo.TLSVersion)
				fmt.Printf("Cipher Suite: %s\n", result.SSLInfo.CipherSuite)
				if len(result.SSLInfo.PeerCerts.Certificates) > 0 {
					cert := result.SSLInfo.PeerCerts.Certificates[0]
					fmt.Printf("Subject: %s\n", cert.Subject)
					fmt.Printf("Issuer: %s\n", cert.Issuer)
					fmt.Printf("Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))
					
					if len(cert.DNSNames) > 0 {
						fmt.Printf("DNS Names: %s\n", strings.Join(cert.DNSNames[:min(3, len(cert.DNSNames))], ", "))
						if len(cert.DNSNames) > 3 {
							fmt.Printf("... and %d more\n", len(cert.DNSNames)-3)
						}
					}
				}
			} else if result.CertInfo != nil {
				// 显示证书文件信息
				fmt.Printf("Subject: %s\n", result.CertInfo.Subject)
				fmt.Printf("Issuer: %s\n", result.CertInfo.Issuer)
				fmt.Printf("Valid Until: %s\n", result.CertInfo.NotAfter.Format("2006-01-02 15:04:05 UTC"))
			}
		}
	}
	
	// 显示统计信息
	fmt.Printf("\n%s\n", strings.Repeat("=", 50))
	fmt.Printf("Summary: %d successful, %d failed, %d total\n", successCount, errorCount, len(results))
}

// displaySecurityAnalysis 显示安全分析结果
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

	// 文本格式显示
	fmt.Printf("\nSecurity Analysis Report\n")
	fmt.Printf("========================\n")
	fmt.Printf("Target: %s\n", analysis.Target)
	fmt.Printf("Overall Security Score: %d/100\n", analysis.OverallScore)
	
	// 根据安全等级显示不同的符号
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

	// 显示证书检查结果
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

	// 显示TLS检查结果
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

	// 显示过期检查
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

	// 显示安全问题
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

	// 显示安全建议
	fmt.Printf("\nSecurity Recommendations:\n")
	fmt.Printf("==========================\n")
	for i, rec := range analysis.Recommendations {
		fmt.Printf("%d. %s\n", i+1, rec)
	}
}

// displayGenerationResult 显示证书生成结果
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

	// 文本格式显示
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

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
