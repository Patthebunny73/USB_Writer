// Kognit Labs USB Writer
// Cross-platform Windows 11 bootable USB creator

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod disk;
mod error;
mod writer;

use commands::AppState;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kognit_usb_writer=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Kognit USB Writer");

    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_os::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_usb_drives,
            commands::get_iso_info,
            commands::validate_iso,
            commands::start_write_process,
            commands::cancel_write_process,
            commands::get_write_progress,
            commands::get_system_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
