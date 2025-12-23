// Error types for Kognit USB Writer

use serde::Deserialize;
use thiserror::Error;

#[derive(Error, Debug, Deserialize)]
pub enum WriterError {
    #[error("No USB drive selected")]
    NoDriveSelected,

    #[error("No ISO file selected")]
    NoIsoSelected,

    #[error("ISO file not found: {0}")]
    IsoNotFound(String),

    #[error("Invalid ISO file: {0}")]
    InvalidIso(String),

    #[error("USB drive not found: {0}")]
    DriveNotFound(String),

    #[error("USB drive is too small. Required: {required} GB, Available: {available} GB")]
    DriveTooSmall { required: f64, available: f64 },

    #[error("Failed to unmount drive: {0}")]
    UnmountFailed(String),

    #[error("Failed to format drive: {0}")]
    FormatFailed(String),

    #[error("Failed to write data: {0}")]
    WriteFailed(String),

    #[error("Operation cancelled by user")]
    Cancelled,

    #[error("Insufficient permissions. Please run with administrator/root privileges.")]
    InsufficientPermissions,

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("Write mode not supported: {0}")]
    UnsupportedMode(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    #[error("Write operation already in progress")]
    WriteInProgress,
}

impl From<std::io::Error> for WriterError {
    fn from(err: std::io::Error) -> Self {
        WriterError::IoError(err.to_string())
    }
}

// Make WriterError compatible with Tauri's invoke system
impl serde::Serialize for WriterError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, WriterError>;
