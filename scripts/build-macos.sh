#!/bin/bash
# Build script for macOS (ARM64)

set -e

echo "==================================="
echo "USB Writer by Kognit Labs - macOS Build"
echo "==================================="

# Check dependencies
echo "Checking dependencies..."

if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo not found. Install from https://rustup.rs"
    exit 1
fi

if ! command -v npm &> /dev/null; then
    echo "Error: Node.js/npm not found. Install from https://nodejs.org"
    exit 1
fi

# Determine target architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    TARGET="aarch64-apple-darwin"
else
    TARGET="x86_64-apple-darwin"
fi

echo "Building for: $TARGET"

# Build frontend
echo ""
echo "Building frontend..."
cd ui
npm install
npm run build
cd ..

# Build Rust backend
echo ""
echo "Building Rust backend..."
cd src-tauri
cargo build --release --target $TARGET

echo ""
echo "Build complete!"
echo "Binary location: src-tauri/target/$TARGET/release/kognit-usb-writer"
echo ""
echo "To create .dmg package, run:"
echo "  cargo tauri build --target $TARGET"
