// USB Writer - Core writing logic for bootable USB creation
// Supports: Windows (dual partition), Linux (DD/extraction), and more

use crate::disk::{format_size, UsbDrive, WriteMode, PartitionScheme, TargetSystem};
use crate::error::{Result, WriterError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::io::Write as IoWrite;

/// Create a file with world-writable permissions (0o666) for pkexec scripts
#[cfg(unix)]
fn create_world_writable_file(path: &str, content: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Create and write the file
    std::fs::write(path, content)?;
    // Explicitly set permissions to 666 (world-writable) - this bypasses umask
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(())
}

/// Progress information for the write operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteProgress {
    pub stage: WriteStage,
    pub stage_name: String,
    pub stage_progress: f64,
    pub overall_progress: f64,
    pub bytes_written: u64,
    pub total_bytes: u64,
    pub speed: String,
    pub eta: String,
    pub current_file: Option<String>,
    pub is_complete: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WriteStage {
    Preparing,
    Unmounting,
    Partitioning,
    Formatting,
    Copying,
    SplittingInstallWim,
    Finalizing,
    Complete,
    Error,
}

impl WriteStage {
    pub fn name(&self) -> &'static str {
        match self {
            WriteStage::Preparing => "Preparing",
            WriteStage::Unmounting => "Unmounting drive",
            WriteStage::Partitioning => "Creating partitions",
            WriteStage::Formatting => "Formatting drive",
            WriteStage::Copying => "Copying files",
            WriteStage::SplittingInstallWim => "Splitting install.wim",
            WriteStage::Finalizing => "Finalizing",
            WriteStage::Complete => "Complete",
            WriteStage::Error => "Error",
        }
    }

    pub fn weight(&self) -> f64 {
        // Weight for overall progress calculation
        match self {
            WriteStage::Preparing => 0.02,
            WriteStage::Unmounting => 0.03,
            WriteStage::Partitioning => 0.05,
            WriteStage::Formatting => 0.05,
            WriteStage::Copying => 0.75,
            WriteStage::SplittingInstallWim => 0.05,
            WriteStage::Finalizing => 0.05,
            WriteStage::Complete => 0.0,
            WriteStage::Error => 0.0,
        }
    }
}

/// Writer state that can be shared between threads
pub struct WriterState {
    pub stage: std::sync::Mutex<WriteStage>,
    pub stage_progress: AtomicU64,
    pub bytes_written: AtomicU64,
    pub total_bytes: AtomicU64,
    pub current_file: std::sync::Mutex<Option<String>>,
    pub error: std::sync::Mutex<Option<String>>,
    pub cancelled: AtomicBool,
    pub start_time: std::sync::Mutex<Option<std::time::Instant>>,
}

impl WriterState {
    pub fn new() -> Self {
        Self {
            stage: std::sync::Mutex::new(WriteStage::Preparing),
            stage_progress: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            current_file: std::sync::Mutex::new(None),
            error: std::sync::Mutex::new(None),
            cancelled: AtomicBool::new(false),
            start_time: std::sync::Mutex::new(None),
        }
    }

    pub fn get_progress(&self) -> WriteProgress {
        let stage = self.stage.lock().unwrap().clone();
        let stage_progress = f64::from_bits(self.stage_progress.load(Ordering::Relaxed));
        let bytes_written = self.bytes_written.load(Ordering::Relaxed);
        let total_bytes = self.total_bytes.load(Ordering::Relaxed);
        let current_file = self.current_file.lock().unwrap().clone();
        let error = self.error.lock().unwrap().clone();
        let start_time = self.start_time.lock().unwrap();

        // Calculate overall progress
        let stages = [
            WriteStage::Preparing,
            WriteStage::Unmounting,
            WriteStage::Partitioning,
            WriteStage::Formatting,
            WriteStage::Copying,
            WriteStage::SplittingInstallWim,
            WriteStage::Finalizing,
        ];

        let mut overall_progress = 0.0;
        for s in &stages {
            if *s == stage {
                overall_progress += s.weight() * stage_progress;
                break;
            }
            overall_progress += s.weight();
        }

        if stage == WriteStage::Complete {
            overall_progress = 1.0;
        }

        // Calculate speed and ETA
        let (speed, eta) = if let Some(start) = *start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 && bytes_written > 0 {
                let speed_bps = bytes_written as f64 / elapsed;
                let remaining_bytes = total_bytes.saturating_sub(bytes_written);
                let eta_secs = if speed_bps > 0.0 {
                    remaining_bytes as f64 / speed_bps
                } else {
                    0.0
                };

                let speed_str = format!("{}/s", format_size(speed_bps as u64));
                let eta_str = format_duration(eta_secs as u64);
                (speed_str, eta_str)
            } else {
                ("--".to_string(), "--".to_string())
            }
        } else {
            ("--".to_string(), "--".to_string())
        };

        WriteProgress {
            stage: stage.clone(),
            stage_name: stage.name().to_string(),
            stage_progress,
            overall_progress,
            bytes_written,
            total_bytes,
            speed,
            eta,
            current_file,
            is_complete: stage == WriteStage::Complete,
            error,
        }
    }

    pub fn set_stage(&self, stage: WriteStage) {
        *self.stage.lock().unwrap() = stage;
        self.stage_progress.store(0.0f64.to_bits(), Ordering::Relaxed);
    }

    pub fn set_stage_progress(&self, progress: f64) {
        self.stage_progress
            .store(progress.to_bits(), Ordering::Relaxed);
    }

    pub fn set_error(&self, error: String) {
        *self.error.lock().unwrap() = Some(error);
        *self.stage.lock().unwrap() = WriteStage::Error;
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Main USB writing function - dispatches to appropriate write mode
pub async fn write_usb(
    iso_path: &str,
    drive: &UsbDrive,
    mode: WriteMode,
    scheme: PartitionScheme,
    target: TargetSystem,
    state: Arc<WriterState>,
) -> Result<()> {
    tracing::info!("Starting USB write: {} -> {} (mode: {:?}, scheme: {:?}, target: {:?})",
        iso_path, drive.path, mode, scheme, target);

    // Initialize
    *state.start_time.lock().unwrap() = Some(std::time::Instant::now());

    // Validate inputs
    if !Path::new(iso_path).exists() {
        return Err(WriterError::IsoNotFound(iso_path.to_string()));
    }

    let iso_size = std::fs::metadata(iso_path)?.len();
    state.total_bytes.store(iso_size, Ordering::Relaxed);

    // Check minimum drive size based on mode
    let min_size = match mode {
        WriteMode::WindowsDual => 8 * 1024 * 1024 * 1024,  // 8GB for Windows
        WriteMode::DDImage => iso_size + (100 * 1024 * 1024),  // ISO size + 100MB buffer
        WriteMode::ISOExtract => iso_size + (500 * 1024 * 1024),  // ISO size + 500MB for filesystem overhead
        WriteMode::Ventoy => 4 * 1024 * 1024 * 1024,  // 4GB minimum for Ventoy
    };

    if drive.size < min_size {
        return Err(WriterError::DriveTooSmall {
            required: min_size as f64 / 1024.0 / 1024.0 / 1024.0,
            available: drive.size as f64 / 1024.0 / 1024.0 / 1024.0,
        });
    }

    // Platform-specific write based on mode
    #[cfg(target_os = "linux")]
    {
        match mode {
            WriteMode::DDImage => write_usb_dd_linux(iso_path, drive, state).await,
            WriteMode::ISOExtract => write_usb_extract_linux(iso_path, drive, scheme, target, state).await,
            WriteMode::WindowsDual => write_usb_windows_linux(iso_path, drive, state).await,
            WriteMode::Ventoy => Err(WriterError::UnsupportedMode("Ventoy mode not yet implemented".to_string())),
        }
    }

    #[cfg(target_os = "macos")]
    {
        match mode {
            WriteMode::DDImage => write_usb_dd_macos(iso_path, drive, state).await,
            WriteMode::WindowsDual => write_usb_macos(iso_path, drive, state).await,
            _ => write_usb_macos(iso_path, drive, state).await,
        }
    }

    #[cfg(target_os = "windows")]
    {
        match mode {
            WriteMode::WindowsDual => write_usb_windows(iso_path, drive, state).await,
            _ => write_usb_windows(iso_path, drive, state).await,
        }
    }
}

/// DD mode - Direct byte-by-byte copy (fastest for hybrid ISOs like Linux distros)
#[cfg(target_os = "linux")]
async fn write_usb_dd_linux(
    iso_path: &str,
    drive: &UsbDrive,
    state: Arc<WriterState>,
) -> Result<()> {
    use std::fs;
    use std::io::Write as IoWrite;

    let drive_path = &drive.path;
    let session_id = uuid::Uuid::new_v4();
    let progress_file = format!("/tmp/kognit_progress_{}", session_id);
    let script_file = format!("/tmp/kognit_dd_{}.sh", session_id);
    let error_file = format!("/tmp/kognit_error_{}", session_id);

    let iso_size = std::fs::metadata(iso_path)?.len();

    // DD mode script - fastest method for hybrid ISOs
    // Simple and robust - no error traps that could interfere with progress updates
    let write_script = format!(r#"#!/bin/bash

PROGRESS_FILE="{progress_file}"
ERROR_FILE="{error_file}"
DRIVE="{drive_path}"
ISO_PATH="{iso_path}"
ISO_SIZE={iso_size}
ISO_SIZE_MB=$((ISO_SIZE / 1024 / 1024))

# Stage 1: Unmount
echo "unmounting|0|Unmounting drive..." > "$PROGRESS_FILE"
umount -f "$DRIVE"* 2>/dev/null
sync
sleep 1
echo "unmounting|100|Drive unmounted" > "$PROGRESS_FILE"

# Stage 2: DD Write with progress monitoring
echo "copying|0|Starting direct image write..." > "$PROGRESS_FILE"
START_TIME=$(date +%s)

# Run dd in background and capture stderr for status
dd if="$ISO_PATH" of="$DRIVE" bs=4M conv=fsync status=progress 2>&1 &
DD_PID=$!

# Monitor progress by checking /proc fdinfo for bytes read
sleep 2
while kill -0 $DD_PID 2>/dev/null; do
    WRITTEN=0

    # Check all file descriptors for position (dd uses fd 0 for input, fd 1 for output typically)
    for fd in 0 1 3 4; do
        if [ -r "/proc/$DD_PID/fdinfo/$fd" ] 2>/dev/null; then
            POS=$(cat "/proc/$DD_PID/fdinfo/$fd" 2>/dev/null | grep "^pos:" | awk '{{print $2}}')
            if [ -n "$POS" ] && [ "$POS" -gt "$WRITTEN" ] 2>/dev/null; then
                WRITTEN=$POS
            fi
        fi
    done

    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))

    if [ "$WRITTEN" -gt 0 ] && [ "$ISO_SIZE" -gt 0 ]; then
        [ "$WRITTEN" -gt "$ISO_SIZE" ] && WRITTEN=$ISO_SIZE
        PCT=$((WRITTEN * 100 / ISO_SIZE))
        WRITTEN_MB=$((WRITTEN / 1024 / 1024))

        if [ "$ELAPSED" -gt 0 ]; then
            SPEED_MBS=$((WRITTEN_MB / ELAPSED))
            REMAINING_MB=$((ISO_SIZE_MB - WRITTEN_MB))
            if [ "$SPEED_MBS" -gt 0 ]; then
                ETA_SECS=$((REMAINING_MB / SPEED_MBS))
                ETA_MIN=$((ETA_SECS / 60))
                ETA_SEC=$((ETA_SECS % 60))
                echo "copying|$PCT|${{WRITTEN_MB}}/${{ISO_SIZE_MB}} MB @ ${{SPEED_MBS}} MB/s (~${{ETA_MIN}}m ${{ETA_SEC}}s)" > "$PROGRESS_FILE"
            else
                echo "copying|$PCT|${{WRITTEN_MB}}/${{ISO_SIZE_MB}} MB" > "$PROGRESS_FILE"
            fi
        fi
    else
        echo "copying|0|Writing to USB... (${{ELAPSED}}s elapsed)" > "$PROGRESS_FILE"
    fi
    sleep 1
done

# Check dd exit status
wait $DD_PID
DD_STATUS=$?

if [ $DD_STATUS -ne 0 ]; then
    echo "DD write failed with status $DD_STATUS" > "$ERROR_FILE"
    echo "error|0|DD write failed" > "$PROGRESS_FILE"
    exit 1
fi

echo "copying|100|Image write complete" > "$PROGRESS_FILE"

# Stage 3: Sync and finalize
echo "finalizing|0|Syncing data to USB..." > "$PROGRESS_FILE"
sync
sleep 2
echo "finalizing|50|Refreshing partition table..." > "$PROGRESS_FILE"
partprobe "$DRIVE" 2>/dev/null
echo "finalizing|100|Finalization complete" > "$PROGRESS_FILE"

echo "complete|100|Bootable USB created successfully (DD mode)" > "$PROGRESS_FILE"
"#);

    // Write and execute script
    tracing::info!("Creating DD write script at {}", script_file);
    {
        let mut file = fs::File::create(&script_file)
            .map_err(|e| WriterError::CommandFailed(format!("Failed to create script: {}", e)))?;
        file.write_all(write_script.as_bytes())
            .map_err(|e| WriterError::CommandFailed(format!("Failed to write script: {}", e)))?;
    }

    let _ = Command::new("chmod").args(["+x", &script_file]).output();

    create_world_writable_file(&progress_file, "preparing|0|Preparing...")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create progress file: {}", e)))?;

    create_world_writable_file(&error_file, "")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create error file: {}", e)))?;

    state.set_stage(WriteStage::Preparing);

    let mut child = Command::new("pkexec")
        .args(["bash", &script_file])
        .spawn()
        .map_err(|e| WriterError::CommandFailed(format!("Failed to start DD process: {}", e)))?;

    // Monitor progress
    loop {
        if state.is_cancelled() {
            let _ = child.kill();
            let _ = fs::remove_file(&script_file);
            let _ = fs::remove_file(&progress_file);
            let _ = fs::remove_file(&error_file);
            return Err(WriterError::Cancelled);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    let error_msg = fs::read_to_string(&error_file)
                        .unwrap_or_else(|_| "Unknown error during DD write".to_string());
                    let _ = fs::remove_file(&script_file);
                    let _ = fs::remove_file(&progress_file);
                    let _ = fs::remove_file(&error_file);
                    return Err(WriterError::WriteFailed(error_msg.trim().to_string()));
                }
                break;
            }
            Ok(None) => {}
            Err(e) => {
                let _ = fs::remove_file(&script_file);
                let _ = fs::remove_file(&progress_file);
                let _ = fs::remove_file(&error_file);
                return Err(WriterError::CommandFailed(format!("Process error: {}", e)));
            }
        }

        if let Ok(progress_content) = fs::read_to_string(&progress_file) {
            let parts: Vec<&str> = progress_content.trim().split('|').collect();
            if parts.len() >= 3 {
                let stage_name = parts[0];
                let progress: f64 = parts[1].parse().unwrap_or(0.0) / 100.0;
                let message = parts[2];

                match stage_name {
                    "unmounting" => {
                        state.set_stage(WriteStage::Unmounting);
                        state.set_stage_progress(progress);
                    }
                    "copying" => {
                        state.set_stage(WriteStage::Copying);
                        state.set_stage_progress(progress);
                        *state.current_file.lock().unwrap() = Some(message.to_string());
                    }
                    "finalizing" => {
                        state.set_stage(WriteStage::Finalizing);
                        state.set_stage_progress(progress);
                    }
                    "complete" => {
                        state.set_stage(WriteStage::Complete);
                        state.set_stage_progress(1.0);
                    }
                    _ => {}
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    let _ = fs::remove_file(&script_file);
    let _ = fs::remove_file(&progress_file);
    let _ = fs::remove_file(&error_file);

    state.set_stage(WriteStage::Complete);
    tracing::info!("DD write completed successfully");
    Ok(())
}

/// ISO Extract mode - Extracts ISO contents to a formatted USB (for UEFI-only boot)
#[cfg(target_os = "linux")]
async fn write_usb_extract_linux(
    iso_path: &str,
    drive: &UsbDrive,
    scheme: PartitionScheme,
    _target: TargetSystem,
    state: Arc<WriterState>,
) -> Result<()> {
    use std::fs;
    use std::io::Write as IoWrite;

    let drive_path = &drive.path;
    let session_id = uuid::Uuid::new_v4();
    let mount_point = format!("/tmp/kognit_usb_{}", session_id);
    let progress_file = format!("/tmp/kognit_progress_{}", session_id);
    let script_file = format!("/tmp/kognit_extract_{}.sh", session_id);
    let error_file = format!("/tmp/kognit_error_{}", session_id);

    let part1 = if drive_path.contains("nvme") || drive_path.contains("mmcblk") {
        format!("{}p1", drive_path)
    } else {
        format!("{}1", drive_path)
    };

    let iso_mount = format!("{}_iso", mount_point);
    let usb_mount = format!("{}_usb", mount_point);

    let partition_type = match scheme {
        PartitionScheme::GPT => "gpt",
        PartitionScheme::MBR => "msdos",
    };

    // ISO Extract script - creates a simple FAT32 USB with ISO contents
    let write_script = format!(r#"#!/bin/bash

PROGRESS_FILE="{progress_file}"
ERROR_FILE="{error_file}"
DRIVE="{drive_path}"
PART1="{part1}"
ISO_PATH="{iso_path}"
ISO_MOUNT="{iso_mount}"
USB_MOUNT="{usb_mount}"
PARTITION_TYPE="{partition_type}"

# Ensure progress and error files are writable (we're running as root via pkexec)
chmod 666 "$PROGRESS_FILE" 2>/dev/null || true
chmod 666 "$ERROR_FILE" 2>/dev/null || true

update_progress() {{
    echo "$1|$2|$3" > "$PROGRESS_FILE" 2>/dev/null || true
}}

handle_error() {{
    local msg="${{1:-Unknown error}}"
    echo "$msg" > "$ERROR_FILE" 2>/dev/null || true
    update_progress "error" "0" "$msg"
    umount -f "$ISO_MOUNT" 2>/dev/null || true
    umount -f "$USB_MOUNT" 2>/dev/null || true
    rmdir "$ISO_MOUNT" "$USB_MOUNT" 2>/dev/null || true
    exit 1
}}

# Trap errors - capture the line number and command
trap 'handle_error "Script error at line $LINENO: $BASH_COMMAND"' ERR
trap 'handle_error "Script interrupted"' INT TERM

set -E

# Stage 1: Unmount
update_progress "unmounting" "0" "Unmounting drive..."
umount -f "$DRIVE"* 2>/dev/null || true
sync
sleep 1
update_progress "unmounting" "100" "Drive unmounted"

# Stage 2: Partitioning
update_progress "partitioning" "0" "Creating partition table..."
parted -s "$DRIVE" mklabel $PARTITION_TYPE || handle_error "Failed to create partition table"
update_progress "partitioning" "50" "Creating partition..."

if [ "$PARTITION_TYPE" = "gpt" ]; then
    parted -s "$DRIVE" mkpart primary fat32 1MiB 100% || handle_error "Failed to create partition"
    parted -s "$DRIVE" set 1 boot on || handle_error "Failed to set boot flag"
    parted -s "$DRIVE" set 1 esp on 2>/dev/null || true
else
    parted -s "$DRIVE" mkpart primary fat32 1MiB 100% || handle_error "Failed to create partition"
    parted -s "$DRIVE" set 1 boot on || handle_error "Failed to set boot flag"
fi

partprobe "$DRIVE"
sleep 2
update_progress "partitioning" "100" "Partitioning complete"

# Stage 3: Formatting
update_progress "formatting" "0" "Formatting FAT32..."
mkfs.fat -F 32 -n BOOTUSB "$PART1" || handle_error "Failed to format partition"
update_progress "formatting" "100" "Formatting complete"

# Stage 4: Mount and extract
update_progress "copying" "0" "Mounting partitions..."
mkdir -p "$ISO_MOUNT" "$USB_MOUNT"
mount -o loop,ro "$ISO_PATH" "$ISO_MOUNT" || handle_error "Failed to mount ISO"
mount "$PART1" "$USB_MOUNT" || handle_error "Failed to mount USB"

# Count files for progress
TOTAL_FILES=$(find "$ISO_MOUNT" -type f | wc -l)
COPIED_FILES=0

update_progress "copying" "5" "Copying files (0/$TOTAL_FILES)..."

# Use 7z if available for faster extraction, otherwise rsync
if command -v 7z &> /dev/null; then
    update_progress "copying" "10" "Extracting with 7z (fast mode)..."
    umount "$ISO_MOUNT" 2>/dev/null || true
    7z x "$ISO_PATH" -o"$USB_MOUNT" -y -bsp1 2>&1 | \
    while IFS= read -r line; do
        if echo "$line" | grep -q "%"; then
            PCT=$(echo "$line" | grep -oP '\d+(?=%)' | tail -1)
            if [ -n "$PCT" ]; then
                SCALED=$((10 + PCT * 85 / 100))
                update_progress "copying" "$SCALED" "Extracting: $PCT%"
            fi
        fi
    done
else
    # Fallback: rsync with progress
    rsync -a --info=progress2 --no-inc-recursive "$ISO_MOUNT/" "$USB_MOUNT/" 2>&1 | \
    while IFS= read -r line; do
        if echo "$line" | grep -qP '\d+%'; then
            PCT=$(echo "$line" | grep -oP '\d+(?=%)' | tail -1)
            if [ -n "$PCT" ]; then
                SCALED=$((10 + PCT * 85 / 100))
                update_progress "copying" "$SCALED" "Copying: $PCT%"
            fi
        fi
    done
    umount "$ISO_MOUNT" 2>/dev/null || true
fi

update_progress "copying" "100" "File extraction complete"

# Stage 5: Make bootable (install syslinux if needed for MBR)
if [ "$PARTITION_TYPE" = "msdos" ]; then
    update_progress "finalizing" "0" "Installing bootloader..."
    if command -v syslinux &> /dev/null; then
        syslinux --install "$PART1" 2>/dev/null || true
        dd bs=440 count=1 conv=notrunc if=/usr/lib/syslinux/mbr/mbr.bin of="$DRIVE" 2>/dev/null || \
        dd bs=440 count=1 conv=notrunc if=/usr/lib/syslinux/bios/mbr.bin of="$DRIVE" 2>/dev/null || \
        dd bs=440 count=1 conv=notrunc if=/usr/share/syslinux/mbr.bin of="$DRIVE" 2>/dev/null || true
    fi
fi

update_progress "finalizing" "50" "Syncing data..."
sync
umount "$USB_MOUNT" 2>/dev/null || true
rmdir "$ISO_MOUNT" "$USB_MOUNT" 2>/dev/null || true
update_progress "finalizing" "100" "Finalization complete"

update_progress "complete" "100" "Bootable USB created successfully (Extract mode)"
"#);

    // Write and execute script
    tracing::info!("Creating extract write script at {}", script_file);
    {
        let mut file = fs::File::create(&script_file)
            .map_err(|e| WriterError::CommandFailed(format!("Failed to create script: {}", e)))?;
        file.write_all(write_script.as_bytes())
            .map_err(|e| WriterError::CommandFailed(format!("Failed to write script: {}", e)))?;
    }

    let _ = Command::new("chmod").args(["+x", &script_file]).output();

    create_world_writable_file(&progress_file, "preparing|0|Preparing...")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create progress file: {}", e)))?;

    create_world_writable_file(&error_file, "")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create error file: {}", e)))?;

    state.set_stage(WriteStage::Preparing);

    let mut child = Command::new("pkexec")
        .args(["bash", &script_file])
        .spawn()
        .map_err(|e| WriterError::CommandFailed(format!("Failed to start extract process: {}", e)))?;

    // Monitor progress
    loop {
        if state.is_cancelled() {
            let _ = child.kill();
            let _ = fs::remove_file(&script_file);
            let _ = fs::remove_file(&progress_file);
            let _ = fs::remove_file(&error_file);
            return Err(WriterError::Cancelled);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    let error_msg = fs::read_to_string(&error_file)
                        .unwrap_or_else(|_| "Unknown error during extraction".to_string());
                    let _ = fs::remove_file(&script_file);
                    let _ = fs::remove_file(&progress_file);
                    let _ = fs::remove_file(&error_file);
                    return Err(WriterError::WriteFailed(error_msg.trim().to_string()));
                }
                break;
            }
            Ok(None) => {}
            Err(e) => {
                let _ = fs::remove_file(&script_file);
                let _ = fs::remove_file(&progress_file);
                let _ = fs::remove_file(&error_file);
                return Err(WriterError::CommandFailed(format!("Process error: {}", e)));
            }
        }

        if let Ok(progress_content) = fs::read_to_string(&progress_file) {
            let parts: Vec<&str> = progress_content.trim().split('|').collect();
            if parts.len() >= 3 {
                let stage_name = parts[0];
                let progress: f64 = parts[1].parse().unwrap_or(0.0) / 100.0;
                let message = parts[2];

                match stage_name {
                    "unmounting" => {
                        state.set_stage(WriteStage::Unmounting);
                        state.set_stage_progress(progress);
                    }
                    "partitioning" => {
                        state.set_stage(WriteStage::Partitioning);
                        state.set_stage_progress(progress);
                    }
                    "formatting" => {
                        state.set_stage(WriteStage::Formatting);
                        state.set_stage_progress(progress);
                    }
                    "copying" => {
                        state.set_stage(WriteStage::Copying);
                        state.set_stage_progress(progress);
                        *state.current_file.lock().unwrap() = Some(message.to_string());
                    }
                    "finalizing" => {
                        state.set_stage(WriteStage::Finalizing);
                        state.set_stage_progress(progress);
                    }
                    "complete" => {
                        state.set_stage(WriteStage::Complete);
                        state.set_stage_progress(1.0);
                    }
                    _ => {}
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    let _ = fs::remove_file(&script_file);
    let _ = fs::remove_file(&progress_file);
    let _ = fs::remove_file(&error_file);

    state.set_stage(WriteStage::Complete);
    tracing::info!("Extract write completed successfully");
    Ok(())
}

/// Windows dual-partition mode (FAT32 boot + NTFS data)
#[cfg(target_os = "linux")]
async fn write_usb_windows_linux(
    iso_path: &str,
    drive: &UsbDrive,
    state: Arc<WriterState>,
) -> Result<()> {
    use std::fs;
    use std::io::Write as IoWrite;

    let drive_path = &drive.path;
    let session_id = uuid::Uuid::new_v4();
    let mount_point = format!("/tmp/kognit_usb_{}", session_id);
    let progress_file = format!("/tmp/kognit_progress_{}", session_id);
    let script_file = format!("/tmp/kognit_write_{}.sh", session_id);
    let error_file = format!("/tmp/kognit_error_{}", session_id);

    // Determine partition naming (sda1 vs nvme0n1p1)
    let part1 = if drive_path.contains("nvme") || drive_path.contains("mmcblk") {
        format!("{}p1", drive_path)
    } else {
        format!("{}1", drive_path)
    };

    let part2 = if drive_path.contains("nvme") || drive_path.contains("mmcblk") {
        format!("{}p2", drive_path)
    } else {
        format!("{}2", drive_path)
    };

    let iso_mount = format!("{}_iso", mount_point);
    let boot_mount = format!("{}_boot", mount_point);
    let data_mount = format!("{}_data", mount_point);

    // Create the comprehensive write script that runs with a single pkexec call
    let write_script = format!(r#"#!/bin/bash

PROGRESS_FILE="{progress_file}"
ERROR_FILE="{error_file}"
DRIVE="{drive_path}"
PART1="{part1}"
PART2="{part2}"
ISO_PATH="{iso_path}"
ISO_MOUNT="{iso_mount}"
BOOT_MOUNT="{boot_mount}"
DATA_MOUNT="{data_mount}"

# Ensure progress and error files are writable (we're running as root via pkexec)
chmod 666 "$PROGRESS_FILE" 2>/dev/null || true
chmod 666 "$ERROR_FILE" 2>/dev/null || true
# Also try to take ownership in case chmod doesn't work
chown $(stat -c '%U:%G' /tmp) "$PROGRESS_FILE" "$ERROR_FILE" 2>/dev/null || true

# Function to update progress
update_progress() {{
    echo "$1|$2|$3" > "$PROGRESS_FILE" 2>/dev/null || true
}}

# Function to handle errors
handle_error() {{
    local msg="${{1:-Unknown error}}"
    echo "$msg" > "$ERROR_FILE" 2>/dev/null || true
    update_progress "error" "0" "$msg"
    # Cleanup on error
    umount -f "$ISO_MOUNT" 2>/dev/null || true
    umount -f "$BOOT_MOUNT" 2>/dev/null || true
    umount -f "$DATA_MOUNT" 2>/dev/null || true
    rmdir "$ISO_MOUNT" "$BOOT_MOUNT" "$DATA_MOUNT" 2>/dev/null || true
    exit 1
}}

# Trap errors - capture the line number and command
trap 'handle_error "Script error at line $LINENO: $BASH_COMMAND"' ERR
trap 'handle_error "Script interrupted"' INT TERM

# Enable error trapping
set -E

# Stage 1: Unmount
update_progress "unmounting" "0" "Unmounting drive..."
umount -f "$DRIVE" 2>/dev/null || true
for i in $(seq 1 10); do
    umount -f "${{DRIVE}}$i" 2>/dev/null || true
    umount -f "${{DRIVE}}p$i" 2>/dev/null || true
done
sync
sleep 1
update_progress "unmounting" "100" "Drive unmounted"

# Stage 2: Partitioning
update_progress "partitioning" "0" "Creating partition table..."
parted -s "$DRIVE" mklabel gpt || handle_error "Failed to create partition table"
update_progress "partitioning" "25" "Creating boot partition..."
parted -s "$DRIVE" mkpart primary fat32 1MiB 1024MiB || handle_error "Failed to create boot partition"
update_progress "partitioning" "50" "Creating data partition..."
parted -s "$DRIVE" mkpart primary ntfs 1024MiB 100% || handle_error "Failed to create data partition"
update_progress "partitioning" "75" "Setting boot flags..."
parted -s "$DRIVE" set 1 boot on || handle_error "Failed to set boot flag"
parted -s "$DRIVE" set 1 esp on || handle_error "Failed to set ESP flag"
partprobe "$DRIVE"
sleep 2
update_progress "partitioning" "100" "Partitioning complete"

# Stage 3: Formatting
update_progress "formatting" "0" "Formatting FAT32 boot partition..."
mkfs.fat -F 32 -n BOOT "$PART1" || handle_error "Failed to format FAT32 partition"
update_progress "formatting" "50" "Formatting NTFS data partition..."
mkfs.ntfs -f -L USBWRITER "$PART2" || handle_error "Failed to format NTFS partition"
update_progress "formatting" "100" "Formatting complete"

# Stage 4: Mount partitions and extract ISO
update_progress "copying" "0" "Preparing partitions..."
mkdir -p "$ISO_MOUNT" "$BOOT_MOUNT" "$DATA_MOUNT"
mount "$PART1" "$BOOT_MOUNT" || handle_error "Failed to mount boot partition"
mount "$PART2" "$DATA_MOUNT" || handle_error "Failed to mount data partition"

update_progress "copying" "1" "Checking extraction method..."

# CORRECT Windows 11 file layout:
# - FAT32 (BOOT_MOUNT): All files EXCEPT sources/install.wim (or install.esd if >4GB)
# - NTFS (DATA_MOUNT): Complete copy of sources folder (for install.wim which is >4GB)
#
# Performance optimization: Use 7z for direct extraction (fastest method, used by windows2usb)
# Fallback to mount+rsync if 7z is not available

USE_7Z=false
if command -v 7z &> /dev/null; then
    USE_7Z=true
fi

if [ "$USE_7Z" = true ]; then
    update_progress "copying" "2" "Extracting ISO with 7z (fastest method)..."

    # Extract everything EXCEPT sources folder to FAT32 boot partition
    update_progress "copying" "5" "Extracting boot files to FAT32..."
    7z x "$ISO_PATH" -o"$BOOT_MOUNT" -x'!sources' -y -bsp1 2>&1 | \
    while IFS= read -r line; do
        if echo "$line" | grep -q "%"; then
            PCT=$(echo "$line" | grep -oP '\d+(?=%)' | tail -1)
            if [ -n "$PCT" ]; then
                SCALED=$((5 + PCT / 10))
                update_progress "copying" "$SCALED" "Extracting boot files: $PCT%"
            fi
        fi
    done

    update_progress "copying" "15" "Extracting sources (except install.wim) to FAT32..."

    # Extract sources folder EXCEPT install.wim/install.esd to FAT32
    7z x "$ISO_PATH" -o"$BOOT_MOUNT" 'sources/*' -x'!sources/install.wim' -x'!sources/install.esd' -y -bsp1 2>&1 | \
    while IFS= read -r line; do
        if echo "$line" | grep -q "%"; then
            PCT=$(echo "$line" | grep -oP '\d+(?=%)' | tail -1)
            if [ -n "$PCT" ]; then
                SCALED=$((15 + PCT / 10))
                update_progress "copying" "$SCALED" "Extracting sources: $PCT%"
            fi
        fi
    done

    update_progress "copying" "25" "Extracting complete sources to NTFS (including install.wim)..."

    # Extract entire sources folder to NTFS (this includes the large install.wim)
    7z x "$ISO_PATH" -o"$DATA_MOUNT" 'sources/*' -y -bsp1 2>&1 | \
    while IFS= read -r line; do
        if echo "$line" | grep -q "%"; then
            PCT=$(echo "$line" | grep -oP '\d+(?=%)' | tail -1)
            if [ -n "$PCT" ]; then
                SCALED=$((25 + (PCT * 65 / 100)))
                update_progress "copying" "$SCALED" "Extracting install files: $PCT%"
            fi
        fi
    done

else
    # Fallback: Mount ISO and use rsync/dd
    update_progress "copying" "2" "Mounting ISO..."
    mount -o loop,ro "$ISO_PATH" "$ISO_MOUNT" || handle_error "Failed to mount ISO"

    update_progress "copying" "5" "Copying boot files to FAT32..."

    # Copy everything EXCEPT sources folder to FAT32 using rsync
    rsync -a --info=progress2 --no-inc-recursive \
        --exclude='sources' \
        "$ISO_MOUNT/" "$BOOT_MOUNT/" 2>/dev/null || true

    update_progress "copying" "15" "Copying sources structure to FAT32..."

    # Create sources folder on FAT32
    mkdir -p "$BOOT_MOUNT/sources"

    # Copy sources files EXCEPT install.wim/install.esd to FAT32
    rsync -a --no-inc-recursive \
        --exclude='install.wim' \
        --exclude='install.esd' \
        "$ISO_MOUNT/sources/" "$BOOT_MOUNT/sources/" 2>/dev/null || true

    update_progress "copying" "25" "Copying install files to NTFS..."

    # For the NTFS partition, copy entire sources folder
    mkdir -p "$DATA_MOUNT/sources"

    # Copy small files first
    rsync -a --no-inc-recursive \
        --exclude='install.wim' \
        --exclude='install.esd' \
        "$ISO_MOUNT/sources/" "$DATA_MOUNT/sources/" 2>/dev/null &
    RSYNC_PID=$!

    # Copy install.wim using dd with 4MB block size for maximum throughput
    INSTALL_FILE=""
    if [ -f "$ISO_MOUNT/sources/install.wim" ]; then
        INSTALL_FILE="$ISO_MOUNT/sources/install.wim"
        INSTALL_DEST="$DATA_MOUNT/sources/install.wim"
    elif [ -f "$ISO_MOUNT/sources/install.esd" ]; then
        INSTALL_FILE="$ISO_MOUNT/sources/install.esd"
        INSTALL_DEST="$DATA_MOUNT/sources/install.esd"
    fi

    if [ -n "$INSTALL_FILE" ]; then
        update_progress "copying" "30" "Copying install.wim..."
        INSTALL_SIZE=$(stat -c%s "$INSTALL_FILE" 2>/dev/null || echo "0")
        INSTALL_SIZE_MB=$((INSTALL_SIZE / 1024 / 1024))
        START_TIME=$(date +%s)

        # Start dd in background and monitor progress by checking destination file size
        dd if="$INSTALL_FILE" of="$INSTALL_DEST" bs=4M conv=fsync 2>/dev/null &
        DD_PID=$!

        # Monitor progress while dd is running
        while kill -0 $DD_PID 2>/dev/null; do
            if [ -f "$INSTALL_DEST" ]; then
                COPIED=$(stat -c%s "$INSTALL_DEST" 2>/dev/null || echo "0")
                if [ "$INSTALL_SIZE" -gt 0 ] && [ "$COPIED" -gt 0 ]; then
                    PCT=$((30 + (COPIED * 60 / INSTALL_SIZE)))
                    COPIED_MB=$((COPIED / 1024 / 1024))

                    # Calculate speed
                    NOW=$(date +%s)
                    ELAPSED=$((NOW - START_TIME))
                    if [ "$ELAPSED" -gt 0 ]; then
                        SPEED_MBS=$((COPIED_MB / ELAPSED))
                        REMAINING_MB=$((INSTALL_SIZE_MB - COPIED_MB))
                        if [ "$SPEED_MBS" -gt 0 ]; then
                            ETA_SECS=$((REMAINING_MB / SPEED_MBS))
                            ETA_MIN=$((ETA_SECS / 60))
                            ETA_SEC=$((ETA_SECS % 60))
                            update_progress "copying" "$PCT" "install.wim: ${{COPIED_MB}}/${{INSTALL_SIZE_MB}} MB @ ${{SPEED_MBS}} MB/s (~${{ETA_MIN}}m ${{ETA_SEC}}s)"
                        else
                            update_progress "copying" "$PCT" "install.wim: ${{COPIED_MB}}/${{INSTALL_SIZE_MB}} MB"
                        fi
                    else
                        update_progress "copying" "$PCT" "install.wim: ${{COPIED_MB}}/${{INSTALL_SIZE_MB}} MB"
                    fi
                fi
            fi
            sleep 1
        done

        # Wait for dd to complete and check status
        wait $DD_PID || handle_error "Failed to copy install.wim"
    fi

    wait $RSYNC_PID 2>/dev/null || true
    umount "$ISO_MOUNT" 2>/dev/null || true
fi

update_progress "copying" "92" "Verifying file structure..."

# Verify critical files exist
if [ ! -f "$BOOT_MOUNT/bootmgr" ] && [ ! -f "$BOOT_MOUNT/bootmgr.efi" ]; then
    if [ ! -f "$BOOT_MOUNT/BOOTMGR" ]; then
        # Try to extract bootmgr if missing
        if [ "$USE_7Z" = true ]; then
            7z x "$ISO_PATH" -o"$BOOT_MOUNT" 'bootmgr*' 'BOOTMGR*' -y 2>/dev/null || true
        fi
    fi
fi

# Ensure boot.wim exists on FAT32 (critical for setup to start)
if [ ! -f "$BOOT_MOUNT/sources/boot.wim" ]; then
    update_progress "copying" "95" "Extracting boot.wim..."
    if [ "$USE_7Z" = true ]; then
        7z x "$ISO_PATH" -o"$BOOT_MOUNT" 'sources/boot.wim' -y 2>/dev/null || true
    fi
fi

update_progress "copying" "100" "File copy complete"

# Note: We don't split install.wim anymore because it stays on NTFS
# where large files are supported

# Stage 5: Finalize
update_progress "finalizing" "0" "Syncing data..."
sync
update_progress "finalizing" "50" "Unmounting filesystems..."
umount "$ISO_MOUNT" 2>/dev/null || true
umount "$BOOT_MOUNT" 2>/dev/null || true
umount "$DATA_MOUNT" 2>/dev/null || true
rmdir "$ISO_MOUNT" "$BOOT_MOUNT" "$DATA_MOUNT" 2>/dev/null || true
sync
update_progress "finalizing" "100" "Finalizing complete"

# Mark as complete
update_progress "complete" "100" "USB write completed successfully"
"#);

    // Write the script to a temp file
    tracing::info!("Creating write script at {}", script_file);
    {
        let mut file = fs::File::create(&script_file)
            .map_err(|e| WriterError::CommandFailed(format!("Failed to create script: {}", e)))?;
        file.write_all(write_script.as_bytes())
            .map_err(|e| WriterError::CommandFailed(format!("Failed to write script: {}", e)))?;
    }

    // Make script executable
    let _ = Command::new("chmod")
        .args(["+x", &script_file])
        .output();

    // Initialize progress file with world-writable permissions
    // This allows the root script to write to it
    fs::write(&progress_file, "preparing|0|Preparing...")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create progress file: {}", e)))?;
    let _ = Command::new("chmod")
        .args(["666", &progress_file])
        .output();

    // Pre-create error file with world-writable permissions
    fs::write(&error_file, "")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create error file: {}", e)))?;
    let _ = Command::new("chmod")
        .args(["666", &error_file])
        .output();

    // Start the script with pkexec (single password prompt!)
    tracing::info!("Executing write script with pkexec (single password prompt)");
    state.set_stage(WriteStage::Preparing);

    let mut child = Command::new("pkexec")
        .args(["bash", &script_file])
        .spawn()
        .map_err(|e| WriterError::CommandFailed(format!("Failed to start write process: {}", e)))?;

    // Monitor progress by reading the progress file
    loop {
        // Check if cancelled
        if state.is_cancelled() {
            let _ = child.kill();
            // Cleanup
            let _ = fs::remove_file(&script_file);
            let _ = fs::remove_file(&progress_file);
            let _ = fs::remove_file(&error_file);
            return Err(WriterError::Cancelled);
        }

        // Check if process finished
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process finished
                if !status.success() {
                    // Check error file
                    let error_msg = fs::read_to_string(&error_file)
                        .unwrap_or_else(|_| "Unknown error during write process".to_string());

                    // Cleanup
                    let _ = fs::remove_file(&script_file);
                    let _ = fs::remove_file(&progress_file);
                    let _ = fs::remove_file(&error_file);

                    return Err(WriterError::WriteFailed(error_msg.trim().to_string()));
                }
                break;
            }
            Ok(None) => {
                // Process still running, check progress
            }
            Err(e) => {
                let _ = fs::remove_file(&script_file);
                let _ = fs::remove_file(&progress_file);
                let _ = fs::remove_file(&error_file);
                return Err(WriterError::CommandFailed(format!("Process error: {}", e)));
            }
        }

        // Read progress file
        if let Ok(progress_content) = fs::read_to_string(&progress_file) {
            let parts: Vec<&str> = progress_content.trim().split('|').collect();
            if parts.len() >= 3 {
                let stage_name = parts[0];
                let progress: f64 = parts[1].parse().unwrap_or(0.0) / 100.0;
                let message = parts[2];

                // Update state based on stage
                match stage_name {
                    "unmounting" => {
                        state.set_stage(WriteStage::Unmounting);
                        state.set_stage_progress(progress);
                    }
                    "partitioning" => {
                        state.set_stage(WriteStage::Partitioning);
                        state.set_stage_progress(progress);
                    }
                    "formatting" => {
                        state.set_stage(WriteStage::Formatting);
                        state.set_stage_progress(progress);
                    }
                    "copying" => {
                        state.set_stage(WriteStage::Copying);
                        state.set_stage_progress(progress);
                        // Parse message format: "install.wim: 6136/6408 MB @ 245 MB/s (~0m 1s)"
                        // Set current file as just the filename
                        if let Some(filename) = message.split(':').next() {
                            *state.current_file.lock().unwrap() = Some(filename.trim().to_string());
                        }
                        // Parse bytes for speed/ETA calculation
                        // Look for pattern like "1234/5678 MB"
                        if let Some(mb_part) = message.split(" MB").next() {
                            if let Some(bytes_part) = mb_part.split(": ").nth(1) {
                                let parts: Vec<&str> = bytes_part.split('/').collect();
                                if parts.len() == 2 {
                                    if let (Ok(written), Ok(total)) = (
                                        parts[0].trim().parse::<u64>(),
                                        parts[1].trim().parse::<u64>()
                                    ) {
                                        // Convert MB to bytes
                                        state.bytes_written.store(written * 1024 * 1024, Ordering::Relaxed);
                                        state.total_bytes.store(total * 1024 * 1024, Ordering::Relaxed);
                                        // Set start time if not already set
                                        if state.start_time.lock().unwrap().is_none() {
                                            *state.start_time.lock().unwrap() = Some(std::time::Instant::now());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "splitting" => {
                        state.set_stage(WriteStage::SplittingInstallWim);
                        state.set_stage_progress(progress);
                    }
                    "finalizing" => {
                        state.set_stage(WriteStage::Finalizing);
                        state.set_stage_progress(progress);
                    }
                    "complete" => {
                        state.set_stage(WriteStage::Complete);
                        state.set_stage_progress(1.0);
                    }
                    _ => {}
                }

                tracing::debug!("Progress: {} - {}% - {}", stage_name, progress * 100.0, message);
            }
        }

        // Small delay before next check
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Cleanup temp files
    let _ = fs::remove_file(&script_file);
    let _ = fs::remove_file(&progress_file);
    let _ = fs::remove_file(&error_file);

    state.set_stage(WriteStage::Complete);
    tracing::info!("USB write completed successfully");
    Ok(())
}

/// DD mode for macOS - Direct byte-by-byte copy (fastest for hybrid ISOs)
#[cfg(target_os = "macos")]
async fn write_usb_dd_macos(
    iso_path: &str,
    drive: &UsbDrive,
    state: Arc<WriterState>,
) -> Result<()> {
    use std::fs;
    use std::io::Write as IoWrite;

    let drive_path = &drive.path;
    // Convert disk identifier for raw device (e.g., /dev/disk2 -> /dev/rdisk2)
    let raw_drive = drive_path.replace("/dev/disk", "/dev/rdisk");

    let session_id = uuid::Uuid::new_v4();
    let progress_file = format!("/tmp/kognit_progress_{}", session_id);
    let script_file = format!("/tmp/kognit_dd_{}.sh", session_id);
    let error_file = format!("/tmp/kognit_error_{}", session_id);

    let iso_size = std::fs::metadata(iso_path)?.len();

    // DD mode script for macOS
    let write_script = format!(r#"#!/bin/bash
set -e

PROGRESS_FILE="{progress_file}"
ERROR_FILE="{error_file}"
DRIVE="{drive_path}"
RAW_DRIVE="{raw_drive}"
ISO_PATH="{iso_path}"
ISO_SIZE={iso_size}

update_progress() {{
    echo "$1|$2|$3" > "$PROGRESS_FILE"
}}

handle_error() {{
    echo "$1" > "$ERROR_FILE"
    exit 1
}}

trap 'handle_error "Script interrupted"' INT TERM

# Stage 1: Unmount
update_progress "unmounting" "0" "Unmounting drive..."
diskutil unmountDisk "$DRIVE" 2>/dev/null || true
sleep 1
update_progress "unmounting" "100" "Drive unmounted"

# Stage 2: DD Write
update_progress "copying" "0" "Starting direct image write..."

# Use dd with raw device for maximum speed
# macOS dd doesn't have status=progress, but we can use pv if available, otherwise estimate
if command -v pv &> /dev/null; then
    pv -n "$ISO_PATH" 2>&1 | dd of="$RAW_DRIVE" bs=4m 2>/dev/null | \
    while IFS= read -r pct; do
        update_progress "copying" "$pct" "Writing: $pct%"
    done
else
    # Fallback: Use dd without progress, update periodically
    dd if="$ISO_PATH" of="$RAW_DRIVE" bs=4m &
    DD_PID=$!

    while kill -0 $DD_PID 2>/dev/null; do
        # Estimate progress based on file size written
        WRITTEN=$(ls -l "$RAW_DRIVE" 2>/dev/null | awk '{{print $5}}' || echo "0")
        if [ "$ISO_SIZE" -gt 0 ] && [ "$WRITTEN" -gt 0 ]; then
            PCT=$((WRITTEN * 100 / ISO_SIZE))
            update_progress "copying" "$PCT" "Writing..."
        fi
        sleep 2
    done

    wait $DD_PID || handle_error "DD write failed"
fi

update_progress "copying" "100" "Image write complete"

# Stage 3: Sync and finalize
update_progress "finalizing" "0" "Syncing data..."
sync
sleep 2
update_progress "finalizing" "50" "Ejecting drive..."
diskutil eject "$DRIVE" 2>/dev/null || true
update_progress "finalizing" "100" "Finalization complete"

update_progress "complete" "100" "Bootable USB created successfully (DD mode)"
"#);

    // Write and execute script
    tracing::info!("Creating DD write script at {}", script_file);
    {
        let mut file = fs::File::create(&script_file)
            .map_err(|e| WriterError::CommandFailed(format!("Failed to create script: {}", e)))?;
        file.write_all(write_script.as_bytes())
            .map_err(|e| WriterError::CommandFailed(format!("Failed to write script: {}", e)))?;
    }

    let _ = Command::new("chmod").args(["+x", &script_file]).output();

    create_world_writable_file(&progress_file, "preparing|0|Preparing...")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create progress file: {}", e)))?;

    create_world_writable_file(&error_file, "")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create error file: {}", e)))?;

    state.set_stage(WriteStage::Preparing);

    // Use osascript to prompt for admin privileges
    let osascript_command = format!(
        "do shell script \"bash '{}'\" with administrator privileges",
        script_file
    );

    let mut child = Command::new("osascript")
        .args(["-e", &osascript_command])
        .spawn()
        .map_err(|e| WriterError::CommandFailed(format!("Failed to start DD process: {}", e)))?;

    // Monitor progress
    loop {
        if state.is_cancelled() {
            let _ = child.kill();
            let _ = fs::remove_file(&script_file);
            let _ = fs::remove_file(&progress_file);
            let _ = fs::remove_file(&error_file);
            return Err(WriterError::Cancelled);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    let error_msg = fs::read_to_string(&error_file)
                        .unwrap_or_else(|_| "Unknown error during DD write".to_string());
                    let _ = fs::remove_file(&script_file);
                    let _ = fs::remove_file(&progress_file);
                    let _ = fs::remove_file(&error_file);
                    return Err(WriterError::WriteFailed(error_msg.trim().to_string()));
                }
                break;
            }
            Ok(None) => {}
            Err(e) => {
                let _ = fs::remove_file(&script_file);
                let _ = fs::remove_file(&progress_file);
                let _ = fs::remove_file(&error_file);
                return Err(WriterError::CommandFailed(format!("Process error: {}", e)));
            }
        }

        if let Ok(progress_content) = fs::read_to_string(&progress_file) {
            let parts: Vec<&str> = progress_content.trim().split('|').collect();
            if parts.len() >= 3 {
                let stage_name = parts[0];
                let progress: f64 = parts[1].parse().unwrap_or(0.0) / 100.0;
                let message = parts[2];

                match stage_name {
                    "unmounting" => {
                        state.set_stage(WriteStage::Unmounting);
                        state.set_stage_progress(progress);
                    }
                    "copying" => {
                        state.set_stage(WriteStage::Copying);
                        state.set_stage_progress(progress);
                        *state.current_file.lock().unwrap() = Some(message.to_string());
                    }
                    "finalizing" => {
                        state.set_stage(WriteStage::Finalizing);
                        state.set_stage_progress(progress);
                    }
                    "complete" => {
                        state.set_stage(WriteStage::Complete);
                        state.set_stage_progress(1.0);
                    }
                    _ => {}
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    let _ = fs::remove_file(&script_file);
    let _ = fs::remove_file(&progress_file);
    let _ = fs::remove_file(&error_file);

    state.set_stage(WriteStage::Complete);
    tracing::info!("DD write completed successfully on macOS");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn write_usb_macos(
    iso_path: &str,
    drive: &UsbDrive,
    state: Arc<WriterState>,
) -> Result<()> {
    use std::fs;
    use std::io::Write as IoWrite;

    let drive_path = &drive.path;
    let session_id = uuid::Uuid::new_v4();
    let progress_file = format!("/tmp/kognit_progress_{}", session_id);
    let script_file = format!("/tmp/kognit_write_{}.sh", session_id);
    let error_file = format!("/tmp/kognit_error_{}", session_id);
    let iso_mount = format!("/tmp/kognit_iso_{}", session_id);

    // Create the comprehensive write script that runs with a single sudo call via osascript
    let write_script = format!(r#"#!/bin/bash
set -e

PROGRESS_FILE="{progress_file}"
ERROR_FILE="{error_file}"
DRIVE="{drive_path}"
ISO_PATH="{iso_path}"
ISO_MOUNT="{iso_mount}"

# Function to update progress
update_progress() {{
    echo "$1|$2|$3" > "$PROGRESS_FILE"
}}

# Function to handle errors
handle_error() {{
    echo "$1" > "$ERROR_FILE"
    hdiutil detach "$ISO_MOUNT" 2>/dev/null || true
    rmdir "$ISO_MOUNT" 2>/dev/null || true
    exit 1
}}

trap 'handle_error "Script interrupted"' INT TERM

# Stage 1: Unmount
update_progress "unmounting" "0" "Unmounting drive..."
diskutil unmountDisk "$DRIVE" 2>/dev/null || true
sleep 1
update_progress "unmounting" "100" "Drive unmounted"

# Stage 2: Partitioning and Formatting (diskutil does both)
update_progress "partitioning" "0" "Creating partition table..."
diskutil partitionDisk "$DRIVE" GPT MS-DOS BOOT 1GB ExFAT USBWRITER R || handle_error "Failed to partition disk"
update_progress "partitioning" "100" "Partitioning complete"

# Stage 3: Formatting (already done by partitionDisk)
update_progress "formatting" "100" "Formatting complete"

# Stage 4: Mount and copy
update_progress "copying" "0" "Mounting ISO..."
mkdir -p "$ISO_MOUNT"
hdiutil attach -mountpoint "$ISO_MOUNT" "$ISO_PATH" || handle_error "Failed to mount ISO"

BOOT_MOUNT="/Volumes/BOOT"
DATA_MOUNT="/Volumes/USBWRITER"

# Count total files for progress
TOTAL_FILES=$(find "$ISO_MOUNT" -type f | wc -l | tr -d ' ')
COPIED_FILES=0

update_progress "copying" "1" "Copying files (0/$TOTAL_FILES)..."

# CORRECT Windows 11 file layout:
# - FAT32 (BOOT_MOUNT): All files EXCEPT sources/install.wim
# - NTFS-like (DATA_MOUNT): Complete copy of sources folder

update_progress "copying" "2" "Copying boot files to FAT32 partition..."

# First, copy everything EXCEPT the sources folder to FAT32
find "$ISO_MOUNT" -maxdepth 1 -mindepth 1 ! -name "sources" | while read -r item; do
    cp -rf "$item" "$BOOT_MOUNT/" 2>/dev/null || true
done

update_progress "copying" "15" "Creating sources structure..."

# Create sources folder on FAT32 and copy boot.wim
mkdir -p "$BOOT_MOUNT/sources"

# Copy everything from sources EXCEPT install.wim and install.esd to FAT32
find "$ISO_MOUNT/sources" -maxdepth 1 -mindepth 1 -type f ! -name "install.wim" ! -name "install.esd" | while read -r src_file; do
    cp -f "$src_file" "$BOOT_MOUNT/sources/" 2>/dev/null || true
done

# Copy any subdirectories in sources to FAT32
find "$ISO_MOUNT/sources" -maxdepth 1 -mindepth 1 -type d | while read -r src_dir; do
    cp -rf "$src_dir" "$BOOT_MOUNT/sources/" 2>/dev/null || true
done

update_progress "copying" "30" "Copying complete sources to data partition..."

# Copy the ENTIRE sources folder to data partition (including install.wim)
cp -rf "$ISO_MOUNT/sources" "$DATA_MOUNT/" 2>/dev/null || true

update_progress "copying" "100" "File copy complete"

# Stage 5: Finalize
update_progress "finalizing" "0" "Syncing data..."
sync
hdiutil detach "$ISO_MOUNT" 2>/dev/null || true
rmdir "$ISO_MOUNT" 2>/dev/null || true
diskutil eject "$DRIVE" 2>/dev/null || true
update_progress "finalizing" "100" "Finalizing complete"

# Mark as complete
update_progress "complete" "100" "USB write completed successfully"
"#);

    // Write the script to a temp file
    tracing::info!("Creating write script at {}", script_file);
    {
        let mut file = fs::File::create(&script_file)
            .map_err(|e| WriterError::CommandFailed(format!("Failed to create script: {}", e)))?;
        file.write_all(write_script.as_bytes())
            .map_err(|e| WriterError::CommandFailed(format!("Failed to write script: {}", e)))?;
    }

    // Make script executable
    let _ = Command::new("chmod")
        .args(["+x", &script_file])
        .output();

    // Initialize progress file with world-writable permissions
    fs::write(&progress_file, "preparing|0|Preparing...")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create progress file: {}", e)))?;
    let _ = Command::new("chmod")
        .args(["666", &progress_file])
        .output();

    // Pre-create error file with world-writable permissions
    fs::write(&error_file, "")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create error file: {}", e)))?;
    let _ = Command::new("chmod")
        .args(["666", &error_file])
        .output();

    // Start the script with osascript to get single admin password prompt
    tracing::info!("Executing write script with sudo via osascript (single password prompt)");
    state.set_stage(WriteStage::Preparing);

    // Use osascript to prompt for admin privileges once
    let osascript_command = format!(
        "do shell script \"bash '{}'\" with administrator privileges",
        script_file
    );

    let mut child = Command::new("osascript")
        .args(["-e", &osascript_command])
        .spawn()
        .map_err(|e| WriterError::CommandFailed(format!("Failed to start write process: {}", e)))?;

    // Monitor progress by reading the progress file
    loop {
        // Check if cancelled
        if state.is_cancelled() {
            let _ = child.kill();
            let _ = fs::remove_file(&script_file);
            let _ = fs::remove_file(&progress_file);
            let _ = fs::remove_file(&error_file);
            return Err(WriterError::Cancelled);
        }

        // Check if process finished
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    let error_msg = fs::read_to_string(&error_file)
                        .unwrap_or_else(|_| "Unknown error during write process".to_string());
                    let _ = fs::remove_file(&script_file);
                    let _ = fs::remove_file(&progress_file);
                    let _ = fs::remove_file(&error_file);
                    return Err(WriterError::WriteFailed(error_msg.trim().to_string()));
                }
                break;
            }
            Ok(None) => {}
            Err(e) => {
                let _ = fs::remove_file(&script_file);
                let _ = fs::remove_file(&progress_file);
                let _ = fs::remove_file(&error_file);
                return Err(WriterError::CommandFailed(format!("Process error: {}", e)));
            }
        }

        // Read progress file and update state
        if let Ok(progress_content) = fs::read_to_string(&progress_file) {
            let parts: Vec<&str> = progress_content.trim().split('|').collect();
            if parts.len() >= 3 {
                let stage_name = parts[0];
                let progress: f64 = parts[1].parse().unwrap_or(0.0) / 100.0;
                let message = parts[2];

                match stage_name {
                    "unmounting" => {
                        state.set_stage(WriteStage::Unmounting);
                        state.set_stage_progress(progress);
                    }
                    "partitioning" => {
                        state.set_stage(WriteStage::Partitioning);
                        state.set_stage_progress(progress);
                    }
                    "formatting" => {
                        state.set_stage(WriteStage::Formatting);
                        state.set_stage_progress(progress);
                    }
                    "copying" => {
                        state.set_stage(WriteStage::Copying);
                        state.set_stage_progress(progress);
                        if let Some(file_part) = message.split(": ").nth(1) {
                            *state.current_file.lock().unwrap() = Some(file_part.to_string());
                        }
                    }
                    "finalizing" => {
                        state.set_stage(WriteStage::Finalizing);
                        state.set_stage_progress(progress);
                    }
                    "complete" => {
                        state.set_stage(WriteStage::Complete);
                        state.set_stage_progress(1.0);
                    }
                    _ => {}
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Cleanup temp files
    let _ = fs::remove_file(&script_file);
    let _ = fs::remove_file(&progress_file);
    let _ = fs::remove_file(&error_file);

    state.set_stage(WriteStage::Complete);
    tracing::info!("USB write completed successfully");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn write_usb_windows(
    iso_path: &str,
    drive: &UsbDrive,
    state: Arc<WriterState>,
) -> Result<()> {
    use std::fs;
    use std::io::Write as IoWrite;

    // Extract disk number from path (\\.\PhysicalDrive0 -> 0)
    let disk_num = drive
        .path
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();

    let session_id = uuid::Uuid::new_v4();
    let progress_file = format!("{}\\kognit_progress_{}.txt", std::env::temp_dir().display(), session_id);
    let script_file = format!("{}\\kognit_write_{}.ps1", std::env::temp_dir().display(), session_id);
    let error_file = format!("{}\\kognit_error_{}.txt", std::env::temp_dir().display(), session_id);

    // Create a comprehensive PowerShell script that runs with single elevation
    let ps_script = format!(r#"
$ErrorActionPreference = "Stop"
$ProgressFile = "{progress_file}"
$ErrorFile = "{error_file}"
$DiskNum = {disk_num}
$IsoPath = "{iso_path}"

function Update-Progress {{
    param($Stage, $Percent, $Message)
    "$Stage|$Percent|$Message" | Out-File -FilePath $ProgressFile -Encoding UTF8 -NoNewline
}}

function Handle-Error {{
    param($Message)
    $Message | Out-File -FilePath $ErrorFile -Encoding UTF8
    exit 1
}}

try {{
    # Stage 1: Clean disk
    Update-Progress "unmounting" 0 "Cleaning disk..."

    $diskpartClean = @"
select disk $DiskNum
clean
"@
    $diskpartClean | diskpart
    Start-Sleep -Seconds 1
    Update-Progress "unmounting" 100 "Disk cleaned"

    # Stage 2: Partition disk
    Update-Progress "partitioning" 0 "Creating partition table..."

    $diskpartPartition = @"
select disk $DiskNum
convert gpt
create partition efi size=512
format fs=fat32 quick label=BOOT
assign
create partition primary
format fs=ntfs quick label=USBWRITER
assign
"@
    $diskpartPartition | diskpart
    Start-Sleep -Seconds 2
    Update-Progress "partitioning" 100 "Partitioning complete"

    # Stage 3: Formatting done by diskpart
    Update-Progress "formatting" 100 "Formatting complete"

    # Stage 4: Mount ISO and copy files
    Update-Progress "copying" 0 "Mounting ISO..."

    $iso = Mount-DiskImage -ImagePath $IsoPath -PassThru
    $isoDriveLetter = ($iso | Get-Volume).DriveLetter
    if (-not $isoDriveLetter) {{
        Handle-Error "Failed to mount ISO"
    }}
    $isoPath = "${{isoDriveLetter}}:\"

    # Get USB drive letters
    Start-Sleep -Seconds 2
    $partitions = Get-Partition -DiskNumber $DiskNum | Where-Object {{ $_.DriveLetter }}
    if ($partitions.Count -lt 2) {{
        Dismount-DiskImage -ImagePath $IsoPath
        Handle-Error "Could not find USB partitions"
    }}

    $bootDrive = "$($partitions[0].DriveLetter):\"
    $dataDrive = "$($partitions[1].DriveLetter):\"

    # Count files for progress
    $files = Get-ChildItem -Path $isoPath -Recurse -File
    $totalFiles = $files.Count
    $copiedFiles = 0

    Update-Progress "copying" 1 "Copying files (0/$totalFiles)..."

    # CORRECT Windows 11 file layout:
    # - FAT32 (bootDrive): All files EXCEPT sources\install.wim
    # - NTFS (dataDrive): Complete copy of sources folder

    Update-Progress "copying" 2 "Copying boot files to FAT32 partition..."

    # Copy everything EXCEPT sources folder to FAT32
    Get-ChildItem -Path $isoPath -Exclude "sources" | ForEach-Object {{
        Copy-Item -Path $_.FullName -Destination $bootDrive -Recurse -Force
    }}

    Update-Progress "copying" 15 "Creating sources structure..."

    # Create sources folder on FAT32
    $bootSources = Join-Path $bootDrive "sources"
    New-Item -ItemType Directory -Path $bootSources -Force | Out-Null

    # Copy everything from sources EXCEPT install.wim and install.esd to FAT32
    $isoSources = Join-Path $isoPath "sources"
    Get-ChildItem -Path $isoSources -File | Where-Object {{ $_.Name -ne "install.wim" -and $_.Name -ne "install.esd" }} | ForEach-Object {{
        Copy-Item -Path $_.FullName -Destination $bootSources -Force
    }}

    # Copy any subdirectories in sources to FAT32
    Get-ChildItem -Path $isoSources -Directory | ForEach-Object {{
        Copy-Item -Path $_.FullName -Destination $bootSources -Recurse -Force
    }}

    Update-Progress "copying" 30 "Copying complete sources to NTFS partition..."

    # Copy the ENTIRE sources folder to NTFS (including install.wim)
    Copy-Item -Path $isoSources -Destination $dataDrive -Recurse -Force

    Update-Progress "copying" 100 "File copy complete"

    # Unmount ISO
    Dismount-DiskImage -ImagePath $IsoPath

    # Stage 5: Finalize
    Update-Progress "finalizing" 50 "Syncing data..."
    Start-Sleep -Seconds 1
    Update-Progress "finalizing" 100 "Complete"

    Update-Progress "complete" 100 "USB write completed successfully"
}}
catch {{
    Handle-Error $_.Exception.Message
}}
"#);

    // Write the PowerShell script to temp file
    tracing::info!("Creating write script at {}", script_file);
    {
        let mut file = fs::File::create(&script_file)
            .map_err(|e| WriterError::CommandFailed(format!("Failed to create script: {}", e)))?;
        file.write_all(ps_script.as_bytes())
            .map_err(|e| WriterError::CommandFailed(format!("Failed to write script: {}", e)))?;
    }

    // Initialize progress file
    fs::write(&progress_file, "preparing|0|Preparing...")
        .map_err(|e| WriterError::CommandFailed(format!("Failed to create progress file: {}", e)))?;

    // Start the script with elevation (single UAC prompt)
    tracing::info!("Executing write script with elevation (single UAC prompt)");
    state.set_stage(WriteStage::Preparing);

    // Use PowerShell to run elevated - this triggers single UAC prompt
    let mut child = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            &format!(
                "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"{}\"' -Verb RunAs -Wait",
                script_file
            ),
        ])
        .spawn()
        .map_err(|e| WriterError::CommandFailed(format!("Failed to start write process: {}", e)))?;

    // Monitor progress by reading the progress file
    loop {
        if state.is_cancelled() {
            let _ = child.kill();
            let _ = fs::remove_file(&script_file);
            let _ = fs::remove_file(&progress_file);
            let _ = fs::remove_file(&error_file);
            return Err(WriterError::Cancelled);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                // Check for error
                if let Ok(error_content) = fs::read_to_string(&error_file) {
                    if !error_content.trim().is_empty() {
                        let _ = fs::remove_file(&script_file);
                        let _ = fs::remove_file(&progress_file);
                        let _ = fs::remove_file(&error_file);
                        return Err(WriterError::WriteFailed(error_content.trim().to_string()));
                    }
                }
                if !status.success() {
                    let _ = fs::remove_file(&script_file);
                    let _ = fs::remove_file(&progress_file);
                    let _ = fs::remove_file(&error_file);
                    return Err(WriterError::WriteFailed("Write process failed".to_string()));
                }
                break;
            }
            Ok(None) => {}
            Err(e) => {
                let _ = fs::remove_file(&script_file);
                let _ = fs::remove_file(&progress_file);
                let _ = fs::remove_file(&error_file);
                return Err(WriterError::CommandFailed(format!("Process error: {}", e)));
            }
        }

        // Read progress file and update state
        if let Ok(progress_content) = fs::read_to_string(&progress_file) {
            let parts: Vec<&str> = progress_content.trim().split('|').collect();
            if parts.len() >= 3 {
                let stage_name = parts[0];
                let progress: f64 = parts[1].parse().unwrap_or(0.0) / 100.0;
                let message = parts[2];

                match stage_name {
                    "unmounting" => {
                        state.set_stage(WriteStage::Unmounting);
                        state.set_stage_progress(progress);
                    }
                    "partitioning" => {
                        state.set_stage(WriteStage::Partitioning);
                        state.set_stage_progress(progress);
                    }
                    "formatting" => {
                        state.set_stage(WriteStage::Formatting);
                        state.set_stage_progress(progress);
                    }
                    "copying" => {
                        state.set_stage(WriteStage::Copying);
                        state.set_stage_progress(progress);
                        if let Some(file_part) = message.split(": ").nth(1) {
                            *state.current_file.lock().unwrap() = Some(file_part.to_string());
                        }
                    }
                    "finalizing" => {
                        state.set_stage(WriteStage::Finalizing);
                        state.set_stage_progress(progress);
                    }
                    "complete" => {
                        state.set_stage(WriteStage::Complete);
                        state.set_stage_progress(1.0);
                    }
                    _ => {}
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Cleanup temp files
    let _ = fs::remove_file(&script_file);
    let _ = fs::remove_file(&progress_file);
    let _ = fs::remove_file(&error_file);

    state.set_stage(WriteStage::Complete);
    tracing::info!("USB write completed successfully");
    Ok(())
}
