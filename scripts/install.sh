#!/usr/bin/env bash
# scripts/install.sh
# Build and install cert-hacker binary for the current platform

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
BINARY_NAME="cert-hacker"

echo "=== Certificate Hacker Plugin Installer ==="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed. Please install Go 1.23+ from https://golang.org/dl/"
    echo "Alternatively, download pre-built binaries from the GitHub releases page."
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "Detected Go version: $GO_VERSION"

# Create bin directory
mkdir -p "$BIN_DIR"

# Build the binary
echo "Building cert-hacker..."
cd "$PROJECT_ROOT"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-ldflags \"-X main.version=plugin-1.0.0 -X main.commit=$COMMIT -X main.date=$DATE\""
eval "go build $LDFLAGS -o $BIN_DIR/$BINARY_NAME cmd/main.go"

if [ $? -eq 0 ]; then
    echo ""
    echo "SUCCESS: cert-hacker built successfully!"
    echo "Binary location: $BIN_DIR/$BINARY_NAME"
    echo ""
    echo "Verify installation:"
    echo "  $BIN_DIR/$BINARY_NAME --version"
else
    echo "ERROR: Build failed. Please check the error messages above."
    exit 1
fi
