#!/usr/bin/env bash
# scripts/build-all-platforms.sh
# Cross-platform build for cert-hacker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
BINARY_NAME="cert-hacker"
VERSION="${1:-plugin-1.0.0}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-ldflags \"-X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE\""

mkdir -p "$BIN_DIR"

echo "=== Building cert-hacker for all platforms ==="
echo "Version: $VERSION"
echo ""

PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$PLATFORM"
    OUTPUT="$BIN_DIR/${BINARY_NAME}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi

    echo -n "Building for $GOOS/$GOARCH... "
    cd "$PROJECT_ROOT"
    GOOS=$GOOS GOARCH=$GOARCH eval "go build $LDFLAGS -o $OUTPUT cmd/main.go" && echo "OK" || echo "FAILED"
done

echo ""
echo "Build complete. Binaries in: $BIN_DIR/"
ls -lh "$BIN_DIR/"
