//! PlausiDen Purge — library crate.
//!
//! Re-exports core modules for integration tests and downstream consumers.

pub mod algorithms;
pub mod cron_manager;
pub mod destroyer;
pub mod error;
pub mod file_age;
pub mod file_type;
pub mod log_cleaner;
pub mod metadata_extractor;
pub mod metadata_strip;
pub mod shredder;
pub mod snapshot;
pub mod report;
pub mod restore;
pub mod temp_monitor;
pub mod privacy_audit;
pub mod disk_analysis;
pub mod duplicates;
pub mod forensic_wipe;
pub mod free_space_wipe;
pub mod scheduler;
pub mod secure_random;
pub mod swap_cleaner;
pub mod junk_detector;
pub mod disk_watcher;
pub mod backup_rotation;
pub mod archive_catalog;
pub mod file_registry;
pub mod wipe_patterns;
pub mod log_archiver;
pub mod content_dedup;
pub mod age_index;
