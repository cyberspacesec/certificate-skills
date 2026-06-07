# Certificate Hacker — Claude Code Plugin

🔒 A Claude Code plugin providing SSL/TLS certificate security analysis capabilities.

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
├── cmd/                         # Go CLI source code
├── pkg/                         # Go library packages
├── scripts/                     # Build and install scripts
└── bin/                         # Compiled binary (after build)
```

## Security Disclaimer

⚠️ This tool is intended for **legitimate security research and testing** only. Users are responsible for ensuring compliance with applicable laws and regulations.

## License

MIT License — see [LICENSE](LICENSE) for details.
