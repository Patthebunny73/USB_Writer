// Tauri commands - Bridge between frontend and backend

use crate::disk::{self, IsoInfo, SystemInfo, UsbDrive, WriteMode, PartitionScheme, TargetSystem};
use crate::error::WriterError;
use crate::writer::{WriteProgress, WriterState};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;

/// Shared application state
pub struct AppState {
    pub writer_state: Arc<WriterState>,
    pub is_writing: Arc<Mutex<bool>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            writer_state: Arc::new(WriterState::new()),
            is_writing: Arc::new(Mutex::new(false)),
        }
    }
}

/// Get list of available USB drives
#[tauri::command]
pub async fn get_usb_drives() -> Result<Vec<UsbDrive>, String> {
    tracing::info!("Scanning for USB drives");
    let drives = disk::detect_usb_drives();
    tracing::info!("Found {} USB drives", drives.len());
    Ok(drives)
}

/// Get information about an ISO file
#[tauri::command]
pub async fn get_iso_info(path: String) -> Result<IsoInfo, String> {
    tracing::info!("Getting ISO info: {}", path);
    disk::get_iso_info(&path).map_err(|e| e.to_string())
}

/// Validate an ISO file
#[tauri::command]
pub async fn validate_iso(path: String) -> Result<bool, String> {
    tracing::info!("Validating ISO: {}", path);
    match disk::get_iso_info(&path) {
        Ok(info) => Ok(info.is_valid),
        Err(e) => Err(e.to_string()),
    }
}

/// Start the USB write process
#[tauri::command]
pub async fn start_write_process(
    iso_path: String,
    drive_path: String,
    write_mode: Option<String>,
    partition_scheme: Option<String>,
    target_system: Option<String>,
    app_state: State<'_, AppState>,
) -> Result<(), String> {
    tracing::info!("Starting write process: {} -> {} (mode: {:?}, scheme: {:?})",
        iso_path, drive_path, write_mode, partition_scheme);

    // Check if already writing
    let mut is_writing = app_state.is_writing.lock().await;
    if *is_writing {
        return Err(WriterError::WriteInProgress.to_string());
    }
    *is_writing = true;
    drop(is_writing);

    // Find the drive
    let drives = disk::detect_usb_drives();
    let drive = drives
        .into_iter()
        .find(|d| d.path == drive_path)
        .ok_or_else(|| WriterError::DriveNotFound(drive_path.clone()).to_string())?;

    // Parse write mode (default to auto-detect based on ISO type)
    let mode = match write_mode.as_deref() {
        Some("windows_dual") => WriteMode::WindowsDual,
        Some("dd_image") => WriteMode::DDImage,
        Some("iso_extract") => WriteMode::ISOExtract,
        Some("ventoy") => WriteMode::Ventoy,
        _ => {
            // Auto-detect based on ISO type
            if let Ok(iso_info) = disk::get_iso_info(&iso_path) {
                iso_info.recommended_mode
            } else {
                WriteMode::ISOExtract
            }
        }
    };

    // Parse partition scheme
    let scheme = match partition_scheme.as_deref() {
        Some("mbr") => PartitionScheme::MBR,
        Some("gpt") | _ => PartitionScheme::GPT,
    };

    // Parse target system
    let target = match target_system.as_deref() {
        Some("bios") => TargetSystem::BIOS,
        Some("uefi") => TargetSystem::UEFI,
        Some("both") | _ => TargetSystem::UEFIAndBIOS,
    };

    // Use the shared state from AppState
    let writer_state = app_state.writer_state.clone();
    let is_writing_flag = app_state.is_writing.clone();

    // Reset the shared state
    *writer_state.stage.lock().unwrap() = crate::writer::WriteStage::Preparing;
    writer_state.stage_progress.store(0.0f64.to_bits(), Ordering::Relaxed);
    writer_state.bytes_written.store(0, Ordering::Relaxed);
    writer_state.total_bytes.store(0, Ordering::Relaxed);
    *writer_state.current_file.lock().unwrap() = None;
    *writer_state.error.lock().unwrap() = None;
    writer_state.cancelled.store(false, Ordering::Relaxed);
    *writer_state.start_time.lock().unwrap() = None;

    // Spawn the write task
    tokio::spawn(async move {
        let result = crate::writer::write_usb(&iso_path, &drive, mode, scheme, target, writer_state.clone()).await;

        // Update shared state with result
        if let Err(e) = result {
            writer_state.set_error(e.to_string());
        }

        // Reset is_writing flag when done (success or error)
        let mut is_writing = is_writing_flag.lock().await;
        *is_writing = false;
    });

    Ok(())
}

/// Cancel the current write process
#[tauri::command]
pub async fn cancel_write_process(app_state: State<'_, AppState>) -> Result<(), String> {
    tracing::info!("Cancelling write process");
    app_state.writer_state.cancel();

    let mut is_writing = app_state.is_writing.lock().await;
    *is_writing = false;

    Ok(())
}

/// Get current write progress
#[tauri::command]
pub async fn get_write_progress(app_state: State<'_, AppState>) -> Result<WriteProgress, String> {
    Ok(app_state.writer_state.get_progress())
}

/// Get system information
#[tauri::command]
pub async fn get_system_info() -> Result<SystemInfo, String> {
    Ok(disk::get_system_info())
}
