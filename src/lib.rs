//! PlausiDen Purge — library crate.
//!
//! Re-exports core modules for integration tests and downstream consumers.

pub mod algorithms;
pub mod destroyer;
pub mod error;
pub mod file_type;
pub mod metadata_strip;
pub mod shredder;
pub mod report;
pub mod temp_monitor;
pub mod scheduler;
