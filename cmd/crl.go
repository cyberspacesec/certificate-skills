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
	// generate-crl command parameters
	generateCRLCmd.Flags().StringP("ca-cert", "", "", "CA certificate file path (required)")
	generateCRLCmd.Flags().StringP("ca-key", "", "", "CA private key file path (required)")
	generateCRLCmd.Flags().StringP("serials", "s", "", "Comma-separated list of revoked serial numbers")
	generateCRLCmd.Flags().StringP("reasons", "", "", "Comma-separated list of revocation reasons (one per serial)")
	generateCRLCmd.Flags().IntP("next-update", "", 30, "Next update period in days")
	generateCRLCmd.Flags().IntP("number", "", 1, "CRL number")
	generateCRLCmd.Flags().StringP("crl-output", "", "crl.pem", "Output CRL file path")

	rootCmd.AddCommand(generateCRLCmd)
	rootCmd.AddCommand(parseCRLCmd)
}

var generateCRLCmd = &cobra.Command{
	Use:   "generate-crl",
	Short: "Generate a Certificate Revocation List (CRL)",
	Long: `Generate a CRL signed by a CA, listing revoked certificates by serial number.
Supports RFC 5280 revocation reason codes.

Examples:
  cert-skills generate-crl --ca-cert ca.pem --ca-key ca-key.pem --serials 123456,789012
  cert-skills generate-crl --ca-cert ca.pem --ca-key ca-key.pem --serials 123456 --reasons key-compromise`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("output")
		caCertPath, _ := cmd.Flags().GetString("ca-cert")
		caKeyPath, _ := cmd.Flags().GetString("ca-key")

		if caCertPath == "" || caKeyPath == "" {
			fmt.Fprintf(os.Stderr, "Error: --ca-cert and --ca-key are required\n")
			os.Exit(1)
		}

		serialsStr, _ := cmd.Flags().GetString("serials")
		reasonsStr, _ := cmd.Flags().GetString("reasons")
		nextUpdate, _ := cmd.Flags().GetInt("next-update")
		number, _ := cmd.Flags().GetInt("number")
		outputPath, _ := cmd.Flags().GetString("crl-output")

		var revokedCerts []pkg.RevokedEntry
		if serialsStr != "" {
			serials := strings.Split(serialsStr, ",")
			var reasons []string
			if reasonsStr != "" {
				reasons = strings.Split(reasonsStr, ",")
			}

			for i, s := range serials {
				s = strings.TrimSpace(s)
				entry := pkg.RevokedEntry{SerialNumber: s}
				if i < len(reasons) {
					entry.Reason = strings.TrimSpace(reasons[i])
				}
				revokedCerts = append(revokedCerts, entry)
			}
		}

		req := pkg.CRLGenerateRequest{
			CACertPath:   caCertPath,
			CAKeyPath:    caKeyPath,
			RevokedCerts: revokedCerts,
			NextUpdate:   nextUpdate,
			Number:       int64(number),
			OutputPath:   outputPath,
		}

		result, err := pkg.GenerateCRL(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating CRL: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("CRL Generated Successfully"))
		fmt.Println(display.BulletKeyValue("CRL Path", result.CRLPath))
		fmt.Println(display.BulletKeyValue("CRL Number", fmt.Sprintf("%d", result.CRLNumber)))
		fmt.Println(display.BulletKeyValue("Issuer", result.Issuer))
		fmt.Println(display.BulletKeyValue("This Update", result.ThisUpdate.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("Next Update", result.NextUpdate.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("Revoked Certificates", fmt.Sprintf("%d", result.RevokedCount)))
	},
}

var parseCRLCmd = &cobra.Command{
	Use:   "parse-crl [crl-file]",
	Short: "Parse a CRL file",
	Long:  `Parse and display the contents of a Certificate Revocation List (CRL) file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("output")
		crlPath := args[0]

		result, err := pkg.ParseCRL(crlPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing CRL: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(display.SectionHeader("Certificate Revocation List"))
		fmt.Println(display.BulletKeyValue("Issuer", result.Issuer))
		fmt.Println(display.BulletKeyValue("This Update", result.ThisUpdate.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("Next Update", result.NextUpdate.Format("2006-01-02 15:04:05 UTC")))
		fmt.Println(display.BulletKeyValue("CRL Number", result.Number))
		fmt.Println(display.BulletKeyValue("Signature Algorithm", result.SignatureAlgo))
		fmt.Println(display.BulletKeyValue("Revoked Certificates", fmt.Sprintf("%d", result.RevokedCount)))

		if len(result.RevokedCerts) > 0 {
			fmt.Println()
			for _, rc := range result.RevokedCerts {
				fmt.Printf("  Serial: %s | Revoked: %s | Reason: %s (%d)\n",
					rc.SerialNumber,
					rc.RevocationTime.Format("2006-01-02"),
					rc.Reason,
					rc.ReasonCode)
			}
		}
	},
}
