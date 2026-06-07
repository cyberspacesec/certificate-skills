package mcpserver

import (
	"fmt"

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
			"Certificate security toolkit MCP server. Provides tools for retrieving SSL/TLS " +
				"certificate information from domains, parsing local certificate files, performing " +
				"comprehensive security analysis with scoring, generating self-signed certificates " +
				"and CSRs, generating fingerprints, and validating certificate/key pairs.",
		),
	)

	s.AddTools(Tools()...)
	return s
}

// Run starts the MCP server with the specified transport.
//
// Supported transports:
//   - "stdio": JSON-RPC over stdin/stdout (default, for Claude Code subprocess mode)
//   - "sse": HTTP server with Server-Sent Events (legacy MCP HTTP transport)
//   - "http": HTTP server with Streamable HTTP transport (modern MCP HTTP transport)
func Run(transport, addr, baseURL string) error {
	mcpServer := NewServer()

	switch transport {
	case "stdio":
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
		fmt.Printf("SSE MCP server listening on %s\n", addr)
		fmt.Printf("  SSE endpoint:   http://%s/sse\n", addr)
		fmt.Printf("  Message endpoint: http://%s/message\n", addr)
		return sseServer.Start(addr)

	case "http":
		httpServer := server.NewStreamableHTTPServer(mcpServer)
		fmt.Printf("Streamable HTTP MCP server listening on %s\n", addr)
		fmt.Printf("  Endpoint: http://%s/mcp\n", addr)
		return httpServer.Start(addr)

	default:
		return fmt.Errorf("unknown transport: %q (use stdio, sse, or http)", transport)
	}
}
