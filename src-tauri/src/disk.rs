// Cross-platform disk detection and information

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDrive {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub size_formatted: String,
    pub vendor: String,
    pub model: String,
    pub is_removable: bool,
    pub mount_points: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IsoType {
    Windows,      // Windows installer ISO (needs special partition layout)
    LinuxHybrid,  // Linux hybrid ISO (can use dd direct write)
    LinuxLegacy,  // Non-hybrid Linux ISO (needs extraction)
    Unknown,      // Unknown ISO type
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WriteMode {
    WindowsDual,     // GPT with FAT32 boot + NTFS data (for Windows 11)
    DDImage,         // Direct byte-by-byte copy (for hybrid ISOs)
    ISOExtract,      // Extract ISO contents to FAT32 (for UEFI-only)
    Ventoy,          // Ventoy-style multi-boot (future)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PartitionScheme {
    GPT,  // Modern UEFI systems
    MBR,  // Legacy BIOS systems
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TargetSystem {
    UEFI,         // UEFI only (GPT required)
    BIOS,         // Legacy BIOS only (MBR)
    UEFIAndBIOS,  // Dual-boot compatible
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsoInfo {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub size_formatted: String,
    pub is_valid: bool,
    pub iso_type: IsoType,
    pub is_hybrid: bool,
    pub is_windows_iso: bool,
    pub windows_version: Option<String>,
    pub linux_distro: Option<String>,
    pub architecture: Option<String>,
    pub recommended_mode: WriteMode,
    pub supported_modes: Vec<WriteMode>,
    pub has_efi: bool,
    pub has_bios: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub platform: String,
    pub is_admin: bool,
    pub available_space: u64,
}

/// Detect USB drives based on the current platform
pub fn detect_usb_drives() -> Vec<UsbDrive> {
    #[cfg(target_os = "linux")]
    {
        detect_usb_drives_linux()
    }
    #[cfg(target_os = "macos")]
    {
        detect_usb_drives_macos()
    }
    #[cfg(target_os = "windows")]
    {
        detect_usb_drives_windows()
    }
}

#[cfg(target_os = "linux")]
fn detect_usb_drives_linux() -> Vec<UsbDrive> {
    let mut drives = Vec::new();

    // Use lsblk to get block device information
    let output = Command::new("lsblk")
        .args([
            "-J",
            "-o",
            "NAME,SIZE,TYPE,MOUNTPOINT,VENDOR,MODEL,RM,TRAN,HOTPLUG",
        ])
        .output();

    if let Ok(output) = output {
        if let Ok(json_str) = String::from_utf8(output.stdout) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                if let Some(blockdevices) = json["blockdevices"].as_array() {
                    for device in blockdevices {
                        let device_type = device["type"].as_str().unwrap_or("");
                        let transport = device["tran"].as_str().unwrap_or("");
                        let removable = device["rm"].as_bool().unwrap_or(false)
                            || device["rm"].as_str() == Some("1");
                        let hotplug = device["hotplug"].as_bool().unwrap_or(false)
                            || device["hotplug"].as_str() == Some("1");

                        // Only include USB removable drives (disks, not partitions)
                        if device_type == "disk" && (transport == "usb" || (removable && hotplug)) {
                            let name = device["name"].as_str().unwrap_or("").to_string();
                            let path = format!("/dev/{}", name);

                            // Parse size
                            let size_str = device["size"].as_str().unwrap_or("0");
                            let size = parse_size_string(size_str);

                            let vendor = device["vendor"]
                                .as_str()
                                .unwrap_or("")
                                .trim()
                                .to_string();
                            let model =
                                device["model"].as_str().unwrap_or("").trim().to_string();

                            // Get mount points from children (partitions)
                            let mut mount_points = Vec::new();
                            if let Some(children) = device["children"].as_array() {
                                for child in children {
                                    if let Some(mp) = child["mountpoint"].as_str() {
                                        if !mp.is_empty() {
                                            mount_points.push(mp.to_string());
                                        }
                                    }
                                }
                            }

                            let display_name = if !vendor.is_empty() || !model.is_empty() {
                                format!("{} {}", vendor, model).trim().to_string()
                            } else {
                                format!("USB Drive ({})", name)
                            };

                            drives.push(UsbDrive {
                                path,
                                name: display_name,
                                size,
                                size_formatted: format_size(size),
                                vendor,
                                model,
                                is_removable: removable,
                                mount_points,
                            });
                        }
                    }
                }
            }
        }
    }

    drives
}

#[cfg(target_os = "macos")]
fn detect_usb_drives_macos() -> Vec<UsbDrive> {
    let mut drives = Vec::new();

    // Use diskutil to get disk information
    let output = Command::new("diskutil").args(["list", "-plist"]).output();

    if let Ok(output) = output {
        // Parse plist output - simplified approach using diskutil info for each disk
        let list_output = Command::new("diskutil")
            .args(["list", "external"])
            .output();

        if let Ok(list_output) = list_output {
            if let Ok(list_str) = String::from_utf8(list_output.stdout) {
                // Parse the disk identifiers
                for line in list_str.lines() {
                    if line.starts_with("/dev/disk") {
                        let disk_id = line.split_whitespace().next().unwrap_or("");
                        if !disk_id.is_empty() {
                            if let Some(drive) = get_macos_disk_info(disk_id) {
                                drives.push(drive);
                            }
                        }
                    }
                }
            }
        }
    }

    drives
}

#[cfg(target_os = "macos")]
fn get_macos_disk_info(disk_path: &str) -> Option<UsbDrive> {
    let output = Command::new("diskutil")
        .args(["info", "-plist", disk_path])
        .output()
        .ok()?;

    let plist_str = String::from_utf8(output.stdout).ok()?;

    // Simple plist parsing for key fields
    let is_removable = plist_str.contains("<key>Removable</key>\n\t<true/>");
    let is_external = plist_str.contains("<key>Internal</key>\n\t<false/>");

    if !is_removable && !is_external {
        return None;
    }

    // Extract size
    let size = extract_plist_integer(&plist_str, "TotalSize").unwrap_or(0);

    // Extract name/model
    let media_name = extract_plist_string(&plist_str, "MediaName").unwrap_or_default();
    let volume_name = extract_plist_string(&plist_str, "VolumeName").unwrap_or_default();

    let name = if !media_name.is_empty() {
        media_name
    } else if !volume_name.is_empty() {
        volume_name
    } else {
        format!("External Drive ({})", disk_path)
    };

    // Get mount point
    let mount_point = extract_plist_string(&plist_str, "MountPoint");
    let mount_points = mount_point.map(|mp| vec![mp]).unwrap_or_default();

    Some(UsbDrive {
        path: disk_path.to_string(),
        name,
        size,
        size_formatted: format_size(size),
        vendor: String::new(),
        model: extract_plist_string(&plist_str, "MediaName").unwrap_or_default(),
        is_removable,
        mount_points,
    })
}

#[cfg(target_os = "macos")]
fn extract_plist_string(plist: &str, key: &str) -> Option<String> {
    let key_tag = format!("<key>{}</key>", key);
    let key_pos = plist.find(&key_tag)?;
    let after_key = &plist[key_pos + key_tag.len()..];
    let string_start = after_key.find("<string>")? + 8;
    let string_end = after_key.find("</string>")?;
    Some(after_key[string_start..string_end].to_string())
}

#[cfg(target_os = "macos")]
fn extract_plist_integer(plist: &str, key: &str) -> Option<u64> {
    let key_tag = format!("<key>{}</key>", key);
    let key_pos = plist.find(&key_tag)?;
    let after_key = &plist[key_pos + key_tag.len()..];
    let int_start = after_key.find("<integer>")? + 9;
    let int_end = after_key.find("</integer>")?;
    after_key[int_start..int_end].parse().ok()
}

#[cfg(target_os = "windows")]
fn detect_usb_drives_windows() -> Vec<UsbDrive> {
    let mut drives = Vec::new();

    // Use PowerShell to get USB drive information
    let ps_script = r#"
        Get-Disk | Where-Object { $_.BusType -eq 'USB' } | ForEach-Object {
            $disk = $_
            $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
            $mountPoints = @()
            foreach ($p in $partitions) {
                if ($p.DriveLetter) {
                    $mountPoints += "$($p.DriveLetter):"
                }
            }
            [PSCustomObject]@{
                Path = "\\.\PhysicalDrive$($disk.Number)"
                Number = $disk.Number
                FriendlyName = $disk.FriendlyName
                Size = $disk.Size
                Model = $disk.Model
                MountPoints = $mountPoints -join ','
            }
        } | ConvertTo-Json -Compress
    "#;

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_script])
        .output();

    if let Ok(output) = output {
        if let Ok(json_str) = String::from_utf8(output.stdout) {
            // Handle both single object and array cases
            let json_str = json_str.trim();
            if json_str.starts_with('[') {
                if let Ok(disks) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
                    for disk in disks {
                        if let Some(drive) = parse_windows_disk(&disk) {
                            drives.push(drive);
                        }
                    }
                }
            } else if json_str.starts_with('{') {
                if let Ok(disk) = serde_json::from_str::<serde_json::Value>(json_str) {
                    if let Some(drive) = parse_windows_disk(&disk) {
                        drives.push(drive);
                    }
                }
            }
        }
    }

    drives
}

#[cfg(target_os = "windows")]
fn parse_windows_disk(disk: &serde_json::Value) -> Option<UsbDrive> {
    let path = disk["Path"].as_str()?.to_string();
    let name = disk["FriendlyName"].as_str().unwrap_or("USB Drive").to_string();
    let size = disk["Size"].as_u64().unwrap_or(0);
    let model = disk["Model"].as_str().unwrap_or("").to_string();
    let mount_points_str = disk["MountPoints"].as_str().unwrap_or("");
    let mount_points: Vec<String> = mount_points_str
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Some(UsbDrive {
        path,
        name,
        size,
        size_formatted: format_size(size),
        vendor: String::new(),
        model,
        is_removable: true,
        mount_points,
    })
}

/// Parse size strings like "32G", "500M", "1T"
fn parse_size_string(size_str: &str) -> u64 {
    let size_str = size_str.trim().to_uppercase();

    // Try to extract number and unit
    let mut num_str = String::new();
    let mut unit = String::new();

    for c in size_str.chars() {
        if c.is_ascii_digit() || c == '.' {
            num_str.push(c);
        } else {
            unit.push(c);
        }
    }

    let num: f64 = num_str.parse().unwrap_or(0.0);

    let multiplier: u64 = match unit.trim() {
        "B" | "" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024 * 1024,
        "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
        "T" | "TB" | "TIB" => 1024 * 1024 * 1024 * 1024,
        _ => 1,
    };

    (num * multiplier as f64) as u64
}

/// Format size in human-readable format
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Get ISO file information with comprehensive detection
pub fn get_iso_info(path: &str) -> std::io::Result<IsoInfo> {
    use std::fs;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::Path;

    let path = Path::new(path);
    let metadata = fs::metadata(path)?;

    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Unknown")
        .to_string();

    let size = metadata.len();

    let mut file = fs::File::open(path)?;

    // Check ISO 9660 identifier at offset 32769 (sector 16, byte 1)
    let mut buffer = [0u8; 32774];
    file.read_exact(&mut buffer)?;
    let is_valid = &buffer[32769..32774] == b"CD001";

    if !is_valid {
        return Ok(IsoInfo {
            path: path.to_string_lossy().to_string(),
            name,
            size,
            size_formatted: format_size(size),
            is_valid: false,
            iso_type: IsoType::Unknown,
            is_hybrid: false,
            is_windows_iso: false,
            windows_version: None,
            linux_distro: None,
            architecture: None,
            recommended_mode: WriteMode::ISOExtract,
            supported_modes: vec![WriteMode::ISOExtract],
            has_efi: false,
            has_bios: false,
        });
    }

    // Check for hybrid ISO (isohybrid) - look for MBR signature at offset 510-511
    file.seek(SeekFrom::Start(0))?;
    let mut mbr_buffer = [0u8; 512];
    file.read_exact(&mut mbr_buffer)?;

    // Hybrid ISO has MBR boot signature (0x55, 0xAA) and valid partition table
    let has_mbr_signature = mbr_buffer[510] == 0x55 && mbr_buffer[511] == 0xAA;

    // Check for valid partition table entries (at offsets 446, 462, 478, 494)
    let has_partition_table = mbr_buffer[446..450].iter().any(|&b| b != 0) ||
                              mbr_buffer[462..466].iter().any(|&b| b != 0);

    let is_hybrid = has_mbr_signature && has_partition_table;

    // Check for El Torito boot record (indicates bootable CD)
    file.seek(SeekFrom::Start(0x8801))?; // Sector 17
    let mut boot_buffer = [0u8; 32];
    let has_el_torito = if file.read_exact(&mut boot_buffer).is_ok() {
        &boot_buffer[0..23] == b"\x00CD001\x01EL TORITO SPECIFICATION"
            || boot_buffer.windows(7).any(|w| w == b"EL TORI")
    } else {
        false
    };

    // Detect OS type from filename and content patterns
    let name_lower = name.to_lowercase();

    // Windows detection
    let is_windows = name_lower.contains("windows")
        || name_lower.contains("win10")
        || name_lower.contains("win11")
        || name_lower.contains("win_")
        || name_lower.starts_with("en_windows")
        || name_lower.starts_with("en-us_windows");

    let windows_version = if is_windows {
        if name_lower.contains("11") || name_lower.contains("win11") {
            Some("Windows 11".to_string())
        } else if name_lower.contains("10") || name_lower.contains("win10") {
            Some("Windows 10".to_string())
        } else if name_lower.contains("server") {
            Some("Windows Server".to_string())
        } else {
            Some("Windows".to_string())
        }
    } else {
        None
    };

    // Linux distro detection
    let linux_distro = detect_linux_distro(&name_lower);

    // Architecture detection
    let architecture = detect_architecture(&name_lower);

    // Determine ISO type
    let iso_type = if is_windows {
        IsoType::Windows
    } else if linux_distro.is_some() {
        if is_hybrid {
            IsoType::LinuxHybrid
        } else {
            IsoType::LinuxLegacy
        }
    } else if is_hybrid {
        IsoType::LinuxHybrid  // Assume hybrid ISOs are bootable Linux-like
    } else {
        IsoType::Unknown
    };

    // Determine EFI/BIOS support based on ISO type and structure
    let has_efi = is_windows || is_hybrid || has_el_torito;
    let has_bios = is_hybrid || has_el_torito;

    // Determine recommended and supported write modes
    let (recommended_mode, supported_modes) = match iso_type {
        IsoType::Windows => (
            WriteMode::WindowsDual,
            vec![WriteMode::WindowsDual, WriteMode::ISOExtract],
        ),
        IsoType::LinuxHybrid => (
            WriteMode::DDImage,
            vec![WriteMode::DDImage, WriteMode::ISOExtract],
        ),
        IsoType::LinuxLegacy => (
            WriteMode::ISOExtract,
            vec![WriteMode::ISOExtract],
        ),
        IsoType::Unknown => (
            WriteMode::ISOExtract,
            vec![WriteMode::ISOExtract, WriteMode::DDImage],
        ),
    };

    Ok(IsoInfo {
        path: path.to_string_lossy().to_string(),
        name,
        size,
        size_formatted: format_size(size),
        is_valid,
        iso_type,
        is_hybrid,
        is_windows_iso: is_windows,
        windows_version,
        linux_distro,
        architecture,
        recommended_mode,
        supported_modes,
        has_efi,
        has_bios,
    })
}

/// Detect Linux distribution from ISO filename
fn detect_linux_distro(name: &str) -> Option<String> {
    let distros = [
        ("ubuntu", "Ubuntu"),
        ("debian", "Debian"),
        ("fedora", "Fedora"),
        ("centos", "CentOS"),
        ("rhel", "Red Hat Enterprise Linux"),
        ("rocky", "Rocky Linux"),
        ("alma", "AlmaLinux"),
        ("arch", "Arch Linux"),
        ("manjaro", "Manjaro"),
        ("mint", "Linux Mint"),
        ("pop", "Pop!_OS"),
        ("elementary", "elementary OS"),
        ("zorin", "Zorin OS"),
        ("opensuse", "openSUSE"),
        ("suse", "SUSE"),
        ("kali", "Kali Linux"),
        ("parrot", "Parrot OS"),
        ("tails", "Tails"),
        ("qubes", "Qubes OS"),
        ("nixos", "NixOS"),
        ("void", "Void Linux"),
        ("gentoo", "Gentoo"),
        ("slackware", "Slackware"),
        ("mx", "MX Linux"),
        ("antix", "antiX"),
        ("puppy", "Puppy Linux"),
        ("solus", "Solus"),
        ("endeavour", "EndeavourOS"),
        ("garuda", "Garuda Linux"),
        ("artix", "Artix Linux"),
        ("kubuntu", "Kubuntu"),
        ("xubuntu", "Xubuntu"),
        ("lubuntu", "Lubuntu"),
        ("freebsd", "FreeBSD"),
        ("openbsd", "OpenBSD"),
        ("netbsd", "NetBSD"),
        ("proxmox", "Proxmox VE"),
        ("truenas", "TrueNAS"),
        ("openmediavault", "OpenMediaVault"),
        ("clonezilla", "Clonezilla"),
        ("gparted", "GParted Live"),
        ("systemrescue", "SystemRescue"),
        ("hiren", "Hiren's Boot CD"),
    ];

    for (pattern, distro_name) in distros {
        if name.contains(pattern) {
            return Some(distro_name.to_string());
        }
    }
    None
}

/// Detect architecture from ISO filename
fn detect_architecture(name: &str) -> Option<String> {
    if name.contains("amd64") || name.contains("x86_64") || name.contains("x64") || name.contains("64bit") {
        Some("x86_64".to_string())
    } else if name.contains("i386") || name.contains("i686") || name.contains("x86") || name.contains("32bit") {
        Some("x86".to_string())
    } else if name.contains("arm64") || name.contains("aarch64") {
        Some("ARM64".to_string())
    } else if name.contains("armhf") || name.contains("armv7") {
        Some("ARM".to_string())
    } else {
        // Default assumption for modern ISOs
        Some("x86_64".to_string())
    }
}


/// Get system information
pub fn get_system_info() -> SystemInfo {
    let platform = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
    .to_string();

    let is_admin = check_admin_privileges();

    SystemInfo {
        platform,
        is_admin,
        available_space: 0,
    }
}

/// Check if running with admin/root privileges
fn check_admin_privileges() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // Check if running as admin on Windows
        let output = std::process::Command::new("net")
            .args(["session"])
            .output();

        matches!(output, Ok(o) if o.status.success())
    }
}
