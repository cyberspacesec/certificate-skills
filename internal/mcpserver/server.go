package mcpserver

import (
	"fmt"
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"
)

const (
	ServerName    = "certificate-hacker-mcp"
	ServerVersion = "1.0.0"
)

// NewServer creates and configures the MCP server with all certificate tools.
func NewServer() *server.MCPServer {
	s := server.NewMCPServer(
		ServerName,
		ServerVersion,
		server.WithToolCapabilities(false),
		server.WithRecovery(),
		server.WithInstructions(
			"Certificate security toolkit MCP server. Provides tools for retrieving SSL/TLS "+
				"certificate information from domains, parsing local certificate files, performing "+
				"comprehensive security analysis with scoring (0-100), generating self-signed certificates "+
				"and CSRs, generating fingerprints (MD5/SHA1/SHA256/public-key), and validating "+
				"certificate/key pairs.\n\n"+
				"Common workflows:\n"+
				"- Check a website cert: use cert_info with domain name\n"+
				"- Security audit: use cert_analyze_security for a scored report\n"+
				"- SSL pinning: use cert_info, then extract public_key_sha256 from fingerprints\n"+
				"- Generate test cert: use cert_generate with common_name",
		),
	)

	s.AddTools(Tools()...)
	return s
}

// Run starts the MCP server with the specified transport.
//
// Supported transports:
//   - "stdio": JSON-RPC over stdin/stdout (default, for MCP client subprocess mode)
//   - "sse": HTTP server with Server-Sent Events (legacy MCP HTTP transport)
//   - "http": HTTP server with Streamable HTTP transport (modern MCP HTTP transport)
func Run(transport, addr, baseURL string) error {
	mcpServer := NewServer()

	// Use stderr for all log output to avoid corrupting the stdio JSON-RPC stream.
	// The MCP stdio protocol uses stdout exclusively for protocol messages.
	logger := log.New(os.Stderr, "[cert-skills-mcp] ", log.LstdFlags|log.Lmsgprefix)

	switch transport {
	case "stdio":
		logger.Printf("Starting in stdio mode")
		return server.ServeStdio(mcpServer)

	case "sse":
		opts := []server.SSEOption{
			server.WithKeepAlive(true),
			server.WithKeepAliveInterval(30e9), // 30 seconds
		}
		if baseURL != "" {
			opts = append(opts, server.WithBaseURL(baseURL))
		}
		sseServer := server.NewSSEServer(mcpServer, opts...)
		logger.Printf("SSE server listening on %s", addr)
		logger.Printf("  SSE endpoint:     http://%s/sse", addr)
		logger.Printf("  Message endpoint: http://%s/message", addr)
		return sseServer.Start(addr)

	case "http":
		httpServer := server.NewStreamableHTTPServer(mcpServer)
		logger.Printf("Streamable HTTP server listening on %s", addr)
		logger.Printf("  Endpoint: http://%s/mcp", addr)
		return httpServer.Start(addr)

	default:
		return fmt.Errorf("unknown transport: %q (use stdio, sse, or http)", transport)
	}
}
