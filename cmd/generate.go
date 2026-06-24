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
	// generate command parameters
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

	// generate-csr command parameters
	generateCSRCmd.Flags().StringP("common-name", "n", "", "Common name (CN) for the CSR (required)")
	generateCSRCmd.Flags().StringP("organization", "", "", "Organization name")
	generateCSRCmd.Flags().StringP("country", "", "", "Country code (2 letters)")
	generateCSRCmd.Flags().StringP("province", "", "", "Province or state")
	generateCSRCmd.Flags().StringP("locality", "", "", "Locality or city")
	generateCSRCmd.Flags().StringP("dns-names", "", "", "Comma-separated list of DNS names")
	generateCSRCmd.Flags().IntP("key-size", "", 2048, "Key size (RSA: 2048/4096, ECDSA: 256/384/521)")
	generateCSRCmd.Flags().StringP("key-type", "", "rsa", "Key type (rsa, ecdsa, ed25519)")

	// sign-cert command parameters
	signCertCmd.Flags().StringP("common-name", "n", "", "Common name (CN) for the certificate")
	signCertCmd.Flags().StringP("organization", "", "", "Organization name")
	signCertCmd.Flags().StringP("country", "", "", "Country code (2 letters)")
	signCertCmd.Flags().StringP("province", "", "", "Province or state")
	signCertCmd.Flags().StringP("locality", "", "", "Locality or city")
	signCertCmd.Flags().StringP("dns-names", "", "", "Comma-separated list of DNS names")
	signCertCmd.Flags().IntP("validity-days", "", 365, "Certificate validity period in days")
	signCertCmd.Flags().IntP("key-size", "", 2048, "Key size (RSA: 2048/4096, ECDSA: 256/384/521)")
	signCertCmd.Flags().StringP("key-type", "", "rsa", "Key type (rsa, ecdsa, ed25519)")
	signCertCmd.Flags().StringP("key-usage", "", "server", "Key usage (server, client, both)")
	signCertCmd.Flags().StringP("ca-cert", "", "", "CA certificate file path (required)")
	signCertCmd.Flags().StringP("ca-key", "", "", "CA private key file path (required)")
	signCertCmd.Flags().StringP("output-cert", "", "", "Output certificate file path")
	signCertCmd.Flags().StringP("output-key", "", "", "Output private key file path")

	// generate-intermediate-ca command parameters
	generateIntermediateCACmd.Flags().StringP("common-name", "n", "", "Common name (CN) for the intermediate CA")
	generateIntermediateCACmd.Flags().StringP("organization", "", "", "Organization name")
	generateIntermediateCACmd.Flags().StringP("country", "", "", "Country code (2 letters)")
	generateIntermediateCACmd.Flags().StringP("province", "", "", "Province or state")
	generateIntermediateCACmd.Flags().StringP("locality", "", "", "Locality or city")
	generateIntermediateCACmd.Flags().IntP("validity-days", "", 1825, "Certificate validity period in days")
	generateIntermediateCACmd.Flags().IntP("key-size", "", 4096, "Key size (RSA: 4096 default, ECDSA: 384)")
	generateIntermediateCACmd.Flags().StringP("key-type", "", "rsa", "Key type (rsa, ecdsa, ed25519)")
	generateIntermediateCACmd.Flags().IntP("path-len", "", 0, "Path length constraint (-1 = unlimited)")
	generateIntermediateCACmd.Flags().StringP("parent-cert", "", "", "Parent CA certificate file path (required)")
	generateIntermediateCACmd.Flags().StringP("parent-key", "", "", "Parent CA private key file path (required)")
	generateIntermediateCACmd.Flags().StringP("output-cert", "", "", "Output certificate file path")
	generateIntermediateCACmd.Flags().StringP("output-key", "", "", "Output private key file path")

	// clone-cert command parameters
	cloneCertCmd.Flags().StringP("source", "", "", "Source certificate file path (required)")
	cloneCertCmd.Flags().IntP("key-size", "", 2048, "New key size")
	cloneCertCmd.Flags().StringP("key-type", "", "rsa", "New key type (rsa, ecdsa, ed25519)")
	cloneCertCmd.Flags().IntP("validity-days", "", 365, "Certificate validity period in days")
	cloneCertCmd.Flags().BoolP("modify-subject", "", false, "Modify subject information")
	cloneCertCmd.Flags().StringP("new-cn", "", "", "New common name (requires --modify-subject)")
	cloneCertCmd.Flags().StringP("new-org", "", "", "New organization (requires --modify-subject)")
	cloneCertCmd.Flags().StringP("ca-cert", "", "", "CA certificate file path for CA-signed clone")
	cloneCertCmd.Flags().StringP("ca-key", "", "", "CA private key file path for CA-signed clone")
	cloneCertCmd.Flags().StringP("output-cert", "", "", "Output certificate file path")
	cloneCertCmd.Flags().StringP("output-key", "", "", "Output private key file path")

	// domain-variants command parameters
	domainVariantsCmd.Flags().StringP("domain", "d", "", "Base domain name (required)")
	domainVariantsCmd.Flags().StringP("types", "t", "homoglyph,subdomain,tld,hyphenation", "Variant types (comma-separated: homoglyph,subdomain,tld,hyphenation,insertion)")
	domainVariantsCmd.Flags().IntP("key-size", "", 2048, "Key size")
	domainVariantsCmd.Flags().StringP("key-type", "", "rsa", "Key type (rsa, ecdsa, ed25519)")
	domainVariantsCmd.Flags().IntP("validity-days", "", 365, "Certificate validity period in days")
	domainVariantsCmd.Flags().StringP("output-dir", "", ".", "Output directory")
	domainVariantsCmd.Flags().StringP("organization", "", "", "Organization name")
	domainVariantsCmd.Flags().StringP("ca-cert", "", "", "CA certificate file path for CA-signed variants")
	domainVariantsCmd.Flags().StringP("ca-key", "", "", "CA private key file path for CA-signed variants")

	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(generateCSRCmd)
	rootCmd.AddCommand(signCertCmd)
	rootCmd.AddCommand(generateIntermediateCACmd)
	rootCmd.AddCommand(cloneCertCmd)
	rootCmd.AddCommand(domainVariantsCmd)
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

var signCertCmd = &cobra.Command{
	Use:   "sign-cert",
	Short: "Sign a certificate using a CA",
	Long: `Sign a terminal/leaf certificate using a CA certificate and private key.
Supports server, client, and dual-purpose certificates with RSA, ECDSA, or Ed25519 keys.

Examples:
  cert-skills sign-cert --ca-cert ca.pem --ca-key ca-key.pem --common-name app.example.com
  cert-skills sign-cert --ca-cert ca.pem --ca-key ca-key.pem -n app.example.com --key-type ecdsa --key-usage both`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("output")
		caCertPath, _ := cmd.Flags().GetString("ca-cert")
		caKeyPath, _ := cmd.Flags().GetString("ca-key")

		if caCertPath == "" || caKeyPath == "" {
			fmt.Fprintf(os.Stderr, "Error: --ca-cert and --ca-key are required\n")
			os.Exit(1)
		}

		dnsNamesStr, _ := cmd.Flags().GetString("dns-names")
		var dnsNames []string
		if dnsNamesStr != "" {
			dnsNames = strings.Split(dnsNamesStr, ",")
			for i, d := range dnsNames {
				dnsNames[i] = strings.TrimSpace(d)
			}
		}

		req := pkg.SignCertRequest{
			CommonName:     mustGetString(cmd, "common-name"),
			Organization:   mustGetString(cmd, "organization"),
			Country:        mustGetString(cmd, "country"),
			Province:       mustGetString(cmd, "province"),
			Locality:       mustGetString(cmd, "locality"),
			DNSNames:       dnsNames,
			ValidityDays:   mustGetInt(cmd, "validity-days"),
			KeySize:        mustGetInt(cmd, "key-size"),
			KeyType:        mustGetString(cmd, "key-type"),
			KeyUsage:       mustGetString(cmd, "key-usage"),
			CACertPath:     caCertPath,
			CAKeyPath:      caKeyPath,
			OutputCertPath: mustGetString(cmd, "output-cert"),
			OutputKeyPath:  mustGetString(cmd, "output-key"),
		}

		result, err := pkg.SignCertificate(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error signing certificate: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Signed Successfully"))
		fmt.Println(display.BulletKeyValue("Certificate Path", result.CertificatePath))
		fmt.Println(display.BulletKeyValue("Private Key Path", result.PrivateKeyPath))
		fmt.Println(display.BulletKeyValue("CA Subject", result.CASubject))
		fmt.Println(display.BulletKeyValue("Issued Subject", result.IssuedSubject))
		fmt.Println(display.BulletKeyValue("Serial Number", result.SerialNumber))
		fmt.Println(display.BulletKeyValue("Not Before", result.NotBefore.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("Not After", result.NotAfter.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("SHA-256", result.Fingerprints["sha256"]))
	},
}

var generateIntermediateCACmd = &cobra.Command{
	Use:   "generate-intermediate-ca",
	Short: "Generate an intermediate CA certificate",
	Long: `Generate an intermediate CA certificate signed by a parent CA.
The intermediate CA can be used to sign end-entity certificates, creating a multi-tier PKI hierarchy.

Examples:
  cert-skills generate-intermediate-ca --parent-cert root-ca.pem --parent-key root-ca-key.pem -n "My Intermediate CA"
  cert-skills generate-intermediate-ca --parent-cert root-ca.pem --parent-key root-ca-key.pem -n "Sub CA" --key-type ecdsa`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("output")
		parentCertPath, _ := cmd.Flags().GetString("parent-cert")
		parentKeyPath, _ := cmd.Flags().GetString("parent-key")

		if parentCertPath == "" || parentKeyPath == "" {
			fmt.Fprintf(os.Stderr, "Error: --parent-cert and --parent-key are required\n")
			os.Exit(1)
		}

		req := pkg.IntermediateCARequest{
			CommonName:        mustGetString(cmd, "common-name"),
			Organization:      mustGetString(cmd, "organization"),
			Country:           mustGetString(cmd, "country"),
			Province:          mustGetString(cmd, "province"),
			Locality:          mustGetString(cmd, "locality"),
			ValidityDays:      mustGetInt(cmd, "validity-days"),
			KeySize:           mustGetInt(cmd, "key-size"),
			KeyType:           mustGetString(cmd, "key-type"),
			PathLenConstraint: mustGetInt(cmd, "path-len"),
			ParentCertPath:    parentCertPath,
			ParentKeyPath:     parentKeyPath,
			OutputCertPath:    mustGetString(cmd, "output-cert"),
			OutputKeyPath:     mustGetString(cmd, "output-key"),
		}

		result, err := pkg.GenerateIntermediateCA(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating intermediate CA: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Intermediate CA Generated Successfully"))
		fmt.Println(display.BulletKeyValue("Certificate Path", result.CertificatePath))
		fmt.Println(display.BulletKeyValue("Private Key Path", result.PrivateKeyPath))
		fmt.Println(display.BulletKeyValue("Parent CA", result.CASubject))
		fmt.Println(display.BulletKeyValue("Intermediate CA Subject", result.IssuedSubject))
		fmt.Println(display.BulletKeyValue("Serial Number", result.SerialNumber))
		fmt.Println(display.BulletKeyValue("Not Before", result.NotBefore.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("Not After", result.NotAfter.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("SHA-256", result.Fingerprints["sha256"]))
	},
}

var cloneCertCmd = &cobra.Command{
	Use:   "clone-cert",
	Short: "Clone a certificate",
	Long: `Clone an existing certificate, copying its subject information and extensions
but generating a new key pair and serial number. Useful for security testing and research.

WARNING: This tool is for authorized security testing only. Cloned certificates
will have different fingerprints and will not be trusted by standard PKI.

Examples:
  cert-skills clone-cert --source cert.pem
  cert-skills clone-cert --source cert.pem --modify-subject --new-cn test.example.com
  cert-skills clone-cert --source cert.pem --ca-cert ca.pem --ca-key ca-key.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("output")
		sourcePath, _ := cmd.Flags().GetString("source")

		if sourcePath == "" {
			fmt.Fprintf(os.Stderr, "Error: --source is required\n")
			os.Exit(1)
		}

		req := pkg.CloneCertRequest{
			SourceCertPath:  sourcePath,
			KeySize:         mustGetInt(cmd, "key-size"),
			KeyType:         mustGetString(cmd, "key-type"),
			ValidityDays:    mustGetInt(cmd, "validity-days"),
			ModifySubject:   mustGetBool(cmd, "modify-subject"),
			NewCommonName:   mustGetString(cmd, "new-cn"),
			NewOrganization: mustGetString(cmd, "new-org"),
			OutputCertPath:  mustGetString(cmd, "output-cert"),
			OutputKeyPath:   mustGetString(cmd, "output-key"),
		}

		caCertPath, _ := cmd.Flags().GetString("ca-cert")
		caKeyPath, _ := cmd.Flags().GetString("ca-key")
		if caCertPath != "" && caKeyPath != "" {
			req.CACertPath = caCertPath
			req.CAKeyPath = caKeyPath
		}

		result, err := pkg.CloneCertificate(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error cloning certificate: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Cloned Successfully"))
		fmt.Println(display.BulletKeyValue("Certificate Path", result.CertificatePath))
		fmt.Println(display.BulletKeyValue("Private Key Path", result.PrivateKeyPath))
		fmt.Println(display.BulletKeyValue("Original Subject", result.OriginalSubject))
		fmt.Println(display.BulletKeyValue("Cloned Subject", result.ClonedSubject))
		fmt.Println(display.BulletKeyValue("Key Algorithm", result.KeyAlgorithm))
		fmt.Println(display.BulletKeyValue("Serial Number", result.SerialNumber))
		fmt.Println(display.BulletKeyValue("Not Before", result.NotBefore.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("Not After", result.NotAfter.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("SHA-256", result.Fingerprints["sha256"]))
	},
}

var domainVariantsCmd = &cobra.Command{
	Use:   "domain-variants",
	Short: "Generate domain variant certificates",
	Long: `Generate certificates for domain variants (homoglyphs, subdomains, TLD changes, etc.)
Useful for detecting phishing domains and typosquatting in security research.

WARNING: This tool is for authorized security testing only.

Examples:
  cert-skills domain-variants --domain example.com
  cert-skills domain-variants --domain example.com --types homoglyph,tld
  cert-skills domain-variants --domain example.com --ca-cert ca.pem --ca-key ca-key.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("output")
		domain, _ := cmd.Flags().GetString("domain")

		if domain == "" {
			fmt.Fprintf(os.Stderr, "Error: --domain is required\n")
			os.Exit(1)
		}

		typesStr, _ := cmd.Flags().GetString("types")
		var variantTypes []string
		if typesStr != "" {
			variantTypes = strings.Split(typesStr, ",")
			for i, t := range variantTypes {
				variantTypes[i] = strings.TrimSpace(t)
			}
		}

		req := pkg.DomainVariantRequest{
			BaseDomain:   domain,
			VariantTypes: variantTypes,
			KeySize:      mustGetInt(cmd, "key-size"),
			KeyType:      mustGetString(cmd, "key-type"),
			ValidityDays: mustGetInt(cmd, "validity-days"),
			OutputDir:    mustGetString(cmd, "output-dir"),
			Organization: mustGetString(cmd, "organization"),
		}

		caCertPath, _ := cmd.Flags().GetString("ca-cert")
		caKeyPath, _ := cmd.Flags().GetString("ca-key")
		if caCertPath != "" && caKeyPath != "" {
			req.CACertPath = caCertPath
			req.CAKeyPath = caKeyPath
		}

		result, err := pkg.GenerateDomainVariants(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating domain variants: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" || outputFormat == "csv" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Domain Variant Certificates"))
		fmt.Println(display.BulletKeyValue("Base Domain", result.BaseDomain))
		fmt.Println(display.BulletKeyValue("Total Variants", fmt.Sprintf("%d", result.TotalCount)))
		fmt.Println()

		for i, v := range result.Variants {
			certInfo := ""
			if v.CertPath != "" {
				certInfo = fmt.Sprintf(" (cert: %s)", v.CertPath)
			}
			fmt.Printf("  [%d] %s [%s]%s\n", i+1, v.Domain, v.VariantType, certInfo)
		}
	},
}
