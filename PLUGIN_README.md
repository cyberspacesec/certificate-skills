# Certificate Hacker — Claude Code Plugin & MCP Server

🔒 A Claude Code plugin and MCP server providing SSL/TLS certificate security analysis capabilities.

## What This Plugin Provides

This plugin adds 4 specialized skills to Claude Code:

| Skill | Description | Trigger Examples |
|-------|-------------|------------------|
| `certificate-info` | Retrieve and display certificate information | "check SSL cert for google.com", "parse certificate.pem" |
| `certificate-fingerprint` | Generate certificate fingerprints for SSL pinning | "get SHA-256 fingerprint", "SSL pinning hash" |
| `certificate-analysis` | Comprehensive security analysis with scoring | "analyze TLS security of example.com" |
| `certificate-generator` | Generate self-signed and CA certificates | "create a test certificate for localhost" |

## Installation

### Option 1: Install from Marketplace

```bash
# Add this plugin's marketplace
/plugin marketplace add cyberspacesec/certificate-hacker

# Install the plugin
/plugin install certificate-hacker@certificate-hacker

# Enable the plugin
/plugin enable certificate-hacker@certificate-hacker
```

### Option 2: Install from Local Directory

```bash
# Clone the repository
git clone https://github.com/cyberspacesec/certificate-hacker.git
cd certificate-hacker

# Build the cert-hacker binary
bash scripts/install.sh

# Test with Claude Code
claude --plugin-dir .
```

### Option 3: Add to Project Settings

Add to your project's `.claude/settings.json`:

```json
{
  "enabledPlugins": {
    "certificate-hacker@certificate-hacker": true
  },
  "extraKnownMarketplaces": {
    "certificate-hacker": {
      "source": {
        "source": "git",
        "url": "https://github.com/cyberspacesec/certificate-hacker.git"
      }
    }
  }
}
```

## Prerequisites

- **Go 1.23+** (for building the binary from source)
- **OR** download pre-built binaries from [GitHub Releases](https://github.com/cyberspacesec/certificate-hacker/releases)

## Usage Examples

After installation, simply ask Claude in natural language:

```text
# Check a website's certificate
"Check the SSL certificate for google.com"

# Security analysis
"Analyze the TLS security of my-website.com"

# Generate a test certificate
"Generate a self-signed certificate for localhost"

# Get fingerprints for SSL pinning
"Get the public key fingerprint of api.example.com for SSL pinning"
```

## MCP Server

Certificate Hacker also provides an **MCP (Model Context Protocol) server** that exposes certificate tools to any MCP-compatible AI client (Claude Code, Cursor, Windsurf, etc.).

### Quick Start (stdio mode)

Add to your project's `.mcp.json` or global MCP config:

```json
{
  "mcpServers": {
    "certificate-hacker": {
      "command": "go",
      "args": ["run", "cmd/mcp/main.go"]
    }
  }
}
```

**Using a pre-built binary** (recommended for faster startup, no Go required at runtime):

```json
{
  "mcpServers": {
    "certificate-hacker": {
      "command": "/path/to/cert-hacker-mcp",
      "args": ["-t", "stdio"]
    }
  }
}
```

### Transport Modes

| Mode | Flag | Use Case |
|------|------|----------|
| **stdio** | `-t stdio` (default) | MCP client subprocess — the primary mode for `.mcp.json` |
| **SSE** | `-t sse -a :8080` | Legacy HTTP transport with Server-Sent Events |
| **HTTP** | `-t http -a :8080` | Modern Streamable HTTP transport |

### MCP Tools (9 tools)

| Tool | Description |
|------|-------------|
| `cert_info` | Retrieve SSL/TLS certificate from a domain |
| `cert_parse` | Parse a certificate from a local PEM/DER file |
| `cert_analyze_security` | Comprehensive security analysis with 0-100 scoring |
| `cert_fingerprint_domain` | Generate fingerprints by connecting to a domain |
| `cert_fingerprint_file` | Generate fingerprints from a local certificate file |
| `cert_generate` | Generate a self-signed certificate and private key |
| `cert_generate_csr` | Generate a Certificate Signing Request (CSR) |
| `cert_validate_files` | Validate that cert and key files are a matching pair |
| `cert_validate_fingerprint` | Validate a fingerprint string format against a hash algorithm |

### Build MCP Binary

```bash
# Build just the MCP server
make build-mcp

# Build both CLI and MCP server
make build-all-binaries

# Or use the install script (builds both)
bash scripts/install.sh
```

## Plugin Structure

```
certificate-hacker/
├── .claude-plugin/
│   └── plugin.json              # Plugin manifest
├── skills/
│   ├── certificate-info/        # Certificate retrieval and parsing
│   ├── certificate-fingerprint/ # Fingerprint generation
│   ├── certificate-analysis/    # Security analysis and scoring
│   └── certificate-generator/   # Certificate generation
├── cmd/
│   ├── main.go                  # CLI entry point
│   └── mcp/main.go              # MCP server entry point
├── internal/
│   └── mcpserver/               # MCP server implementation
│       ├── server.go            # Server init and transport selection
│       ├── tools.go             # MCP tool definitions
│       └── handlers.go          # Tool handlers wrapping pkg/
├── pkg/                         # Go library packages (core logic)
├── scripts/                     # Build and install scripts
└── bin/                         # Compiled binaries (after build)
```

## Security Disclaimer

⚠️ This tool is intended for **legitimate security research and testing** only. Users are responsible for ensuring compliance with applicable laws and regulations.

## License

MIT License — see [LICENSE](LICENSE) for details.
