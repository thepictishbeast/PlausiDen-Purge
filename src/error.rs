//! Error types for PlausiDen Purge.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PurgeError {
    #[error("path not found: {0}")]
    PathNotFound(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("verification failed at offset {offset}: expected 0x{expected:02X}, found 0x{found:02X}")]
    VerificationFailed { offset: u64, expected: u8, found: u8 },

    #[error("archive error: {0}")]
    Archive(String),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, PurgeError>;
