package main

import (
	"fmt"
	"os"

	"github.com/cyberspacesec/certificate-skills/internal/display"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

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

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", display.Error(err.Error()))
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("output", "o", "text", "Output format (text, json, csv)")
}
