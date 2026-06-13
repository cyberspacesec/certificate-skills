package main

import (
	"fmt"
	"os"

	"github.com/cyberspacesec/certificate-skills/internal/mcpserver"
	"github.com/spf13/cobra"
)

var (
	transport string
	addr      string
	baseURL   string
	version   = "dev"
	commit    = "none"
	date      = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "cert-skills-mcp",
	Short: "MCP server for certificate security analysis",
	Long: `Certificate Skills MCP Server — Model Context Protocol server
exposing SSL/TLS certificate analysis tools.

Supports three transport modes:
  - stdio (default): JSON-RPC over stdin/stdout, for Claude Code subprocess mode
  - sse: HTTP server with Server-Sent Events (legacy MCP transport)
  - http: HTTP server with Streamable HTTP transport (modern MCP transport)`,
	Version: version,
	RunE: func(cmd *cobra.Command, args []string) error {
		return mcpserver.Run(transport, addr, baseURL)
	},
}

func init() {
	rootCmd.Flags().StringVarP(&transport, "transport", "t", "stdio",
		"Transport mode: stdio, sse, http")
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":8080",
		"Listen address for SSE/HTTP transports (e.g., :8080, 0.0.0.0:3000)")
	rootCmd.Flags().StringVarP(&baseURL, "base-url", "b", "",
		"Base URL for SSE transport when behind a reverse proxy (e.g., https://example.com)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
