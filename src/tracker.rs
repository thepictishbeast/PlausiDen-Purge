//! File access tracker — monitors which files are actively used.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessRecord {
    pub path: PathBuf,
    pub last_accessed: DateTime<Utc>,
    pub access_count: u64,
    pub total_bytes_read: u64,
}

pub struct FileTracker {
    records: HashMap<PathBuf, FileAccessRecord>,
}

impl FileTracker {
    pub fn new() -> Self { Self { records: HashMap::new() } }

    pub fn record_access(&mut self, path: &std::path::Path, bytes: u64) {
        let entry = self.records.entry(path.to_path_buf()).or_insert(FileAccessRecord {
            path: path.to_path_buf(), last_accessed: Utc::now(), access_count: 0, total_bytes_read: 0,
        });
        entry.access_count += 1;
        entry.total_bytes_read += bytes;
        entry.last_accessed = Utc::now();
    }

    pub fn get_record(&self, path: &std::path::Path) -> Option<&FileAccessRecord> {
        self.records.get(path)
    }

    pub fn most_accessed(&self, count: usize) -> Vec<&FileAccessRecord> {
        let mut records: Vec<_> = self.records.values().collect();
        records.sort_by(|a, b| b.access_count.cmp(&a.access_count));
        records.truncate(count);
        records
    }

    pub fn tracked_count(&self) -> usize { self.records.len() }
}

impl Default for FileTracker { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_track_access() {
        let mut tracker = FileTracker::new();
        tracker.record_access(Path::new("/tmp/test.txt"), 1024);
        tracker.record_access(Path::new("/tmp/test.txt"), 2048);
        let record = tracker.get_record(Path::new("/tmp/test.txt")).unwrap();
        assert_eq!(record.access_count, 2);
        assert_eq!(record.total_bytes_read, 3072);
    }

    #[test]
    fn test_most_accessed() {
        let mut tracker = FileTracker::new();
        for _ in 0..10 { tracker.record_access(Path::new("/hot"), 100); }
        for _ in 0..2 { tracker.record_access(Path::new("/cold"), 100); }
        let top = tracker.most_accessed(1);
        assert_eq!(top[0].path, Path::new("/hot"));
    }
}
