# Kognit USB Writer

A professional, cross-platform bootable USB creator with support for Windows 11, Linux distributions, and other bootable ISOs.

## Table of Contents

- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [User Guide](#user-guide)
  - [Step 1: Select ISO File](#step-1-select-iso-file)
  - [Step 2: Select USB Drive](#step-2-select-usb-drive)
  - [Step 3: Write to USB](#step-3-write-to-usb)
- [Write Modes](#write-modes)
- [Troubleshooting](#troubleshooting)
- [Building from Source](#building-from-source)
- [License](#license)

## Features

- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Windows 11 Ready**: Full support for Windows 11 ISOs with automatic large file handling
- **Linux Support**: Create bootable USB drives from any Linux distribution ISO
- **Smart Detection**: Automatically detects ISO type and recommends the best write mode
- **Modern Interface**: Clean, intuitive dark-themed wizard interface
- **Real-time Progress**: Live progress tracking with speed and time estimates
- **Safe Operation**: Confirmation dialogs and clear warnings before writing

## System Requirements

### Minimum Requirements

| Platform | Version | Architecture |
|----------|---------|--------------|
| Linux | Ubuntu 22.04+ | x86_64 |
| macOS | 11.0 (Big Sur)+ | ARM64 / Intel |
| Windows | 10/11 | x86_64 |

### USB Drive Requirements

- Minimum 8GB capacity for Windows ISOs
- Minimum 8GB capacity for most Linux ISOs
- USB 3.0 recommended for faster write speeds

### Linux Dependencies

The following packages are required on Linux:

```bash
sudo apt install parted ntfs-3g udisks2
```

Optional (for faster operations):
```bash
sudo apt install p7zip-full wimtools
```

## Installation

### Pre-built Packages

Download the latest release for your platform:

- **Linux**: `.deb` package or `.AppImage`
- **macOS**: `.dmg` disk image
- **Windows**: `.msi` installer or `.exe`

### Installing on Linux (Debian/Ubuntu)

```bash
sudo dpkg -i kognit-usb-writer_1.0.0_amd64.deb
sudo apt-get install -f  # Install any missing dependencies
```

---

## User Guide

### Step 1: Select ISO File

Launch Kognit USB Writer and you'll see the ISO selection screen.

<!-- Screenshot: ISO Selection Screen -->
<!-- Add screenshot showing the initial screen with drag-and-drop zone -->

**To select an ISO file:**

1. **Drag and Drop**: Drag an ISO file directly onto the application window
2. **Browse**: Click the "Browse" button to open a file dialog

Once selected, the application will analyze the ISO and display:
- ISO file name and size
- Detected operating system (Windows 11, Ubuntu, etc.)
- Recommended write mode
- Boot compatibility (UEFI/BIOS)

<!-- Screenshot: ISO Information Display -->
<!-- Add screenshot showing detected ISO information -->

Click **"Next"** to proceed to USB drive selection.

### Step 2: Select USB Drive

The application will scan for available USB drives.

<!-- Screenshot: USB Drive Selection -->
<!-- Add screenshot showing the USB drive list -->

**Selecting a drive:**

1. Review the list of detected USB drives
2. Verify the drive name and size match your intended target
3. Click on the drive to select it
4. Click **"Refresh"** if your drive doesn't appear

**Important warnings:**
- All data on the selected drive will be permanently erased
- Double-check you've selected the correct drive
- The minimum required size is displayed based on your ISO

<!-- Screenshot: Drive Selected -->
<!-- Add screenshot showing a selected drive with warning message -->

Click **"Next"** to proceed to the write confirmation.

### Step 3: Write to USB

Review your selections before writing.

<!-- Screenshot: Write Confirmation -->
<!-- Add screenshot showing the confirmation screen with all details -->

**The confirmation screen shows:**
- Selected ISO file
- Target USB drive
- Write mode that will be used
- Partition scheme (GPT/MBR)

**To start writing:**

1. Review all settings
2. Click **"Write to USB"**
3. Confirm the warning dialog

<!-- Screenshot: Progress Screen -->
<!-- Add screenshot showing the write progress -->

**During the write process:**
- Current operation stage is displayed
- Progress bar shows overall completion
- Write speed (MB/s) is shown in real-time
- Estimated time remaining updates continuously

**Write stages:**
1. Preparing
2. Unmounting existing partitions
3. Creating partition table
4. Formatting partitions
5. Copying files
6. Splitting large files (if needed)
7. Finalizing

<!-- Screenshot: Write Complete -->
<!-- Add screenshot showing successful completion -->

When complete, safely eject your USB drive. It's now ready to boot!

---

## Write Modes

Kognit USB Writer automatically selects the best mode based on your ISO:

### Windows Dual Partition (Windows ISOs)

Creates a dual-partition layout optimized for Windows 11:
- **Partition 1**: 1GB FAT32 for UEFI boot files
- **Partition 2**: NTFS for Windows installation files

This handles Windows 11's large install.wim files that exceed FAT32's 4GB limit.

### DD Image (Linux Hybrid ISOs)

Direct byte-by-byte copy for hybrid ISO images. This is the fastest method and works with most modern Linux distributions including:
- Ubuntu, Linux Mint, Pop!_OS
- Fedora, CentOS, RHEL
- Debian, Kali Linux
- Arch Linux, Manjaro
- And many more

### ISO Extract (Legacy ISOs)

Extracts ISO contents to a FAT32 filesystem. Used for older ISOs that aren't hybrid bootable.

---

## Troubleshooting

### USB drive not detected

1. Ensure the drive is properly connected
2. Click the "Refresh" button
3. Try a different USB port
4. Check if the drive appears in your system's disk utility

### Write fails with permission error

- **Linux**: The application will prompt for sudo/admin password
- **Windows**: Right-click and "Run as Administrator"
- **macOS**: Enter your password when prompted

### Write appears stuck at "Finalizing"

This is normal. The system is syncing data to the USB drive. This can take several minutes for large ISOs. Do not remove the USB drive.

### Windows USB doesn't boot

1. Ensure your computer's BIOS/UEFI is set to boot from USB
2. For UEFI systems, disable Secure Boot temporarily
3. Try recreating the USB with "GPT" partition scheme

### Linux USB doesn't boot

1. Verify your computer supports UEFI boot (for GPT) or Legacy/CSM (for MBR)
2. Check boot order in BIOS/UEFI settings
3. Try the DD Image write mode if available

---

## Building from Source

### Prerequisites

1. **Rust** (1.70+): https://rustup.rs
2. **Node.js** (18+): https://nodejs.org

### Linux Build Dependencies

```bash
sudo apt install libwebkit2gtk-4.1-dev libappindicator3-dev \
    librsvg2-dev patchelf libssl-dev libayatana-appindicator3-dev
```

### Build Commands

```bash
# Clone the repository
git clone https://github.com/Patthebunny73/USB_Writer.git
cd USB_Writer

# Build using the provided script
./scripts/build-linux.sh

# Or build manually
cd ui && npm install && npm run build && cd ..
cd src-tauri && cargo tauri build
```

### Development Mode

```bash
# Start the development server
cd ui && npm run dev &
cd src-tauri && cargo tauri dev
```

---

## License

MIT License - Copyright (c) 2024 Kognit Labs

---

## Support

For issues and feature requests, please visit:
https://github.com/Patthebunny73/USB_Writer/issues

---

**Made with care by Kognit Labs**
