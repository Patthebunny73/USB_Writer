#!/bin/bash
# Build script for Linux

set -e

echo "==================================="
echo "USB Writer by Kognit Labs - Linux Build"
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

# Check for required system libraries
MISSING_DEPS=""
if ! pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
    MISSING_DEPS="$MISSING_DEPS libwebkit2gtk-4.1-dev"
fi

if [ -n "$MISSING_DEPS" ]; then
    echo "Missing dependencies:$MISSING_DEPS"
    echo "Install with: sudo apt install$MISSING_DEPS"
    exit 1
fi

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
cargo build --release

echo ""
echo "Build complete!"
echo "Binary location: src-tauri/target/release/kognit-usb-writer"
echo ""
echo "To create distributable packages, run:"
echo "  cargo tauri build"
