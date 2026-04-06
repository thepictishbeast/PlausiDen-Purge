//! Log cleaner — rotate, compress, and securely delete old logs.

use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogCleanResult {
    pub files_rotated: u32,
    pub files_deleted: u32,
    pub bytes_freed: u64,
    pub errors: Vec<String>,
}

pub struct LogCleaner {
    max_age_days: u32,
    max_size_mb: u64,
}

impl LogCleaner {
    pub fn new(max_age_days: u32, max_size_mb: u64) -> Self { Self { max_age_days, max_size_mb } }

    pub fn scan_logs(&self, log_dir: &Path) -> Vec<PathBuf> {
        let mut logs = Vec::new();
        if let Ok(entries) = std::fs::read_dir(log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name.ends_with(".log") || name.ends_with(".gz") || name.ends_with(".old") || name.ends_with(".1") || name.ends_with(".2") {
                        logs.push(path);
                    }
                }
            }
        }
        logs
    }

    pub fn identify_stale(&self, logs: &[PathBuf]) -> Vec<PathBuf> {
        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(self.max_age_days as u64 * 86400);
        logs.iter().filter(|p| {
            p.metadata().ok().and_then(|m| m.modified().ok()).map(|t| t < cutoff).unwrap_or(false)
        }).cloned().collect()
    }

    pub fn total_log_size(&self, logs: &[PathBuf]) -> u64 {
        logs.iter().filter_map(|p| p.metadata().ok()).map(|m| m.len()).sum()
    }
}

impl Default for LogCleaner { fn default() -> Self { Self::new(30, 500) } }

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_scan_logs() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.log"), "data").unwrap();
        std::fs::write(dir.path().join("app.log.gz"), "compressed").unwrap();
        std::fs::write(dir.path().join("other.txt"), "not a log").unwrap();
        let cleaner = LogCleaner::default();
        let logs = cleaner.scan_logs(dir.path());
        assert_eq!(logs.len(), 2); // .log and .gz, not .txt
    }

    #[test]
    fn test_total_size() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.log"), vec![0u8; 1000]).unwrap();
        std::fs::write(dir.path().join("b.log"), vec![0u8; 2000]).unwrap();
        let cleaner = LogCleaner::default();
        let logs = cleaner.scan_logs(dir.path());
        assert_eq!(cleaner.total_log_size(&logs), 3000);
    }
}
