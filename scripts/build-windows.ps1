# Build script for Windows (PowerShell)

Write-Host "===================================" -ForegroundColor Cyan
Write-Host "USB Writer by Kognit Labs - Windows Build" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan

# Check dependencies
Write-Host "`nChecking dependencies..." -ForegroundColor Yellow

$hasRust = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $hasRust) {
    Write-Host "Error: Rust/Cargo not found. Install from https://rustup.rs" -ForegroundColor Red
    exit 1
}

$hasNode = Get-Command npm -ErrorAction SilentlyContinue
if (-not $hasNode) {
    Write-Host "Error: Node.js/npm not found. Install from https://nodejs.org" -ForegroundColor Red
    exit 1
}

# Build frontend
Write-Host "`nBuilding frontend..." -ForegroundColor Yellow
Set-Location ui
npm install
npm run build
Set-Location ..

# Build Rust backend
Write-Host "`nBuilding Rust backend..." -ForegroundColor Yellow
Set-Location src-tauri
cargo build --release --target x86_64-pc-windows-msvc

Write-Host "`nBuild complete!" -ForegroundColor Green
Write-Host "Binary location: src-tauri\target\x86_64-pc-windows-msvc\release\kognit-usb-writer.exe"
Write-Host "`nTo create installer, run:" -ForegroundColor Yellow
Write-Host "  cargo tauri build --target x86_64-pc-windows-msvc"
