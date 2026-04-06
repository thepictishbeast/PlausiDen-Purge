//! Temp file monitor — watches /tmp and tracks growth.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempSnapshot {
    pub timestamp: DateTime<Utc>,
    pub total_files: u64,
    pub total_bytes: u64,
    pub largest_files: Vec<(PathBuf, u64)>,
}

pub struct TempMonitor {
    snapshots: Vec<TempSnapshot>,
    max_snapshots: usize,
}

impl TempMonitor {
    pub fn new(max_snapshots: usize) -> Self { Self { snapshots: Vec::new(), max_snapshots } }

    pub fn take_snapshot(&mut self, dir: &std::path::Path) -> TempSnapshot {
        let mut total_files = 0u64;
        let mut total_bytes = 0u64;
        let mut files: Vec<(PathBuf, u64)> = Vec::new();

        if let Ok(entries) = walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()).collect::<Vec<_>>() {
            for entry in &entries {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                total_files += 1;
                total_bytes += size;
                files.push((entry.path().to_path_buf(), size));
            }
        }

        files.sort_by(|a, b| b.1.cmp(&a.1));
        files.truncate(10);

        let snapshot = TempSnapshot { timestamp: Utc::now(), total_files, total_bytes, largest_files: files };
        self.snapshots.push(snapshot.clone());
        if self.snapshots.len() > self.max_snapshots { self.snapshots.remove(0); }
        snapshot
    }

    pub fn growth_rate(&self) -> Option<f64> {
        if self.snapshots.len() < 2 { return None; }
        let first = &self.snapshots[0];
        let last = self.snapshots.last().unwrap();
        let time_diff = (last.timestamp - first.timestamp).num_seconds() as f64;
        if time_diff <= 0.0 { return None; }
        Some((last.total_bytes as f64 - first.total_bytes as f64) / time_diff)
    }

    pub fn snapshot_count(&self) -> usize { self.snapshots.len() }
}

impl Default for TempMonitor { fn default() -> Self { Self::new(100) } }

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_snapshot() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        std::fs::write(dir.path().join("b.bin"), vec![0u8; 1000]).unwrap();
        let mut mon = TempMonitor::new(10);
        let snap = mon.take_snapshot(dir.path());
        assert_eq!(snap.total_files, 2);
        assert!(snap.total_bytes > 1000);
    }

    #[test]
    fn test_empty_dir() {
        let dir = TempDir::new().unwrap();
        let mut mon = TempMonitor::new(10);
        let snap = mon.take_snapshot(dir.path());
        assert_eq!(snap.total_files, 0);
    }

    #[test]
    fn test_growth_rate_needs_two() {
        let mut mon = TempMonitor::new(10);
        let dir = TempDir::new().unwrap();
        mon.take_snapshot(dir.path());
        assert!(mon.growth_rate().is_none());
    }
}
