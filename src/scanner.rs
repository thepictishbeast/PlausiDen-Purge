//! Filesystem scanner — finds unused files and apps.
//!
//! Walks directory trees checking access times (atime) to identify
//! files that haven't been touched in a configurable number of days.

use crate::error::{PurgeError, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use walkdir::WalkDir;

/// Results of a filesystem scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Total files scanned.
    pub total_files: u64,
    /// Files not accessed within the threshold.
    pub unused_files: u64,
    /// Total bytes that could be reclaimed.
    pub reclaimable_bytes: u64,
    /// List of unused file paths with metadata.
    pub unused_entries: Vec<UnusedEntry>,
    /// Scan duration in milliseconds.
    pub scan_duration_ms: u64,
}

/// A single unused file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusedEntry {
    /// File path.
    pub path: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Last access time (Unix timestamp).
    pub last_accessed: i64,
    /// Days since last access.
    pub days_unused: u64,
    /// File type (file, directory, symlink).
    pub file_type: String,
}

/// Scan a directory for files unused beyond the threshold.
pub fn scan_directory(path: &str, unused_days: u64) -> Result<ScanReport> {
    let start = std::time::Instant::now();
    let threshold = Utc::now() - Duration::days(unused_days as i64);
    let threshold_ts = threshold.timestamp();

    let root = Path::new(path);
    if !root.exists() {
        return Err(PurgeError::PathNotFound(path.to_string()));
    }

    let mut total_files = 0u64;
    let mut unused_files = 0u64;
    let mut reclaimable_bytes = 0u64;
    let mut unused_entries = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if !metadata.is_file() {
            continue;
        }

        total_files += 1;

        // Check access time
        let accessed = metadata
            .accessed()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        if accessed < threshold_ts && accessed > 0 {
            let size = metadata.len();
            let days = ((Utc::now().timestamp() - accessed) / 86400) as u64;

            unused_files += 1;
            reclaimable_bytes += size;

            // Only keep first 1000 entries to avoid memory issues
            if unused_entries.len() < 1000 {
                unused_entries.push(UnusedEntry {
                    path: entry.path().to_string_lossy().to_string(),
                    size_bytes: size,
                    last_accessed: accessed,
                    days_unused: days,
                    file_type: "file".to_string(),
                });
            }
        }
    }

    // Sort by size descending — largest reclaimable files first
    unused_entries.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

    Ok(ScanReport {
        total_files,
        unused_files,
        reclaimable_bytes,
        unused_entries,
        scan_duration_ms: start.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_scan_empty_directory() {
        let dir = TempDir::new().unwrap();
        let report = scan_directory(dir.path().to_str().unwrap(), 90).unwrap();
        assert_eq!(report.total_files, 0);
        assert_eq!(report.unused_files, 0);
    }

    #[test]
    fn test_scan_with_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("test.txt"), "hello").unwrap();
        fs::write(dir.path().join("test2.txt"), "world").unwrap();

        let report = scan_directory(dir.path().to_str().unwrap(), 90).unwrap();
        assert_eq!(report.total_files, 2);
        // Files just created should not be "unused"
        assert_eq!(report.unused_files, 0);
    }

    #[test]
    fn test_scan_nonexistent_path() {
        let result = scan_directory("/nonexistent/path/12345", 90);
        assert!(result.is_err());
    }
}
