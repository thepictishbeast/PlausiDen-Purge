//! File age index — fast lookup of files by access and modification age.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A file age record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAge {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub atime: DateTime<Utc>,
    pub mtime: DateTime<Utc>,
    pub ctime: DateTime<Utc>,
    pub indexed_at: DateTime<Utc>,
}

impl FileAge {
    /// Days since last access.
    pub fn atime_days_ago(&self) -> i64 {
        (Utc::now() - self.atime).num_days()
    }

    /// Days since last modification.
    pub fn mtime_days_ago(&self) -> i64 {
        (Utc::now() - self.mtime).num_days()
    }

    /// Days since creation.
    pub fn ctime_days_ago(&self) -> i64 {
        (Utc::now() - self.ctime).num_days()
    }

    /// Is this file stale (neither accessed nor modified recently)?
    pub fn is_stale(&self, threshold_days: i64) -> bool {
        self.atime_days_ago() > threshold_days && self.mtime_days_ago() > threshold_days
    }
}

/// Age-bucketed index.
pub struct AgeIndex {
    files: HashMap<PathBuf, FileAge>,
    total_size: u64,
}

impl AgeIndex {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            total_size: 0,
        }
    }

    /// Index a file.
    pub fn add(&mut self, file: FileAge) {
        if let Some(existing) = self.files.get(&file.path) {
            self.total_size = self.total_size.saturating_sub(existing.size_bytes);
        }
        self.total_size += file.size_bytes;
        self.files.insert(file.path.clone(), file);
    }

    /// Remove a file from the index.
    pub fn remove(&mut self, path: &std::path::Path) -> Option<FileAge> {
        if let Some(file) = self.files.remove(path) {
            self.total_size = self.total_size.saturating_sub(file.size_bytes);
            return Some(file);
        }
        None
    }

    /// Files not accessed in N days.
    pub fn not_accessed_since(&self, days: i64) -> Vec<&FileAge> {
        self.files.values()
            .filter(|f| f.atime_days_ago() >= days)
            .collect()
    }

    /// Files not modified in N days.
    pub fn not_modified_since(&self, days: i64) -> Vec<&FileAge> {
        self.files.values()
            .filter(|f| f.mtime_days_ago() >= days)
            .collect()
    }

    /// Stale files (neither accessed nor modified recently).
    pub fn stale(&self, threshold_days: i64) -> Vec<&FileAge> {
        self.files.values()
            .filter(|f| f.is_stale(threshold_days))
            .collect()
    }

    /// Total bytes of stale files.
    pub fn stale_bytes(&self, threshold_days: i64) -> u64 {
        self.stale(threshold_days).iter().map(|f| f.size_bytes).sum()
    }

    /// Top N largest files.
    pub fn largest(&self, n: usize) -> Vec<&FileAge> {
        let mut sorted: Vec<&FileAge> = self.files.values().collect();
        sorted.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        sorted.truncate(n);
        sorted
    }

    /// Top N oldest files by mtime.
    pub fn oldest(&self, n: usize) -> Vec<&FileAge> {
        let mut sorted: Vec<&FileAge> = self.files.values().collect();
        sorted.sort_by(|a, b| a.mtime.cmp(&b.mtime));
        sorted.truncate(n);
        sorted
    }

    /// Total size.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// File count.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Look up a specific file.
    pub fn get(&self, path: &std::path::Path) -> Option<&FileAge> {
        self.files.get(path)
    }
}

impl Default for AgeIndex {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, size: u64, mtime_days_ago: i64, atime_days_ago: i64) -> FileAge {
        FileAge {
            path: PathBuf::from(path),
            size_bytes: size,
            atime: Utc::now() - chrono::Duration::days(atime_days_ago),
            mtime: Utc::now() - chrono::Duration::days(mtime_days_ago),
            ctime: Utc::now() - chrono::Duration::days(mtime_days_ago),
            indexed_at: Utc::now(),
        }
    }

    #[test]
    fn test_add_and_count() {
        let mut idx = AgeIndex::new();
        idx.add(file("/a", 100, 10, 5));
        idx.add(file("/b", 200, 20, 15));
        assert_eq!(idx.file_count(), 2);
        assert_eq!(idx.total_size(), 300);
    }

    #[test]
    fn test_remove() {
        let mut idx = AgeIndex::new();
        idx.add(file("/a", 100, 10, 5));
        assert!(idx.remove(&PathBuf::from("/a")).is_some());
        assert_eq!(idx.file_count(), 0);
        assert_eq!(idx.total_size(), 0);
    }

    #[test]
    fn test_update_existing() {
        let mut idx = AgeIndex::new();
        idx.add(file("/a", 100, 10, 5));
        idx.add(file("/a", 200, 10, 5));
        assert_eq!(idx.file_count(), 1);
        assert_eq!(idx.total_size(), 200);
    }

    #[test]
    fn test_not_accessed_since() {
        let mut idx = AgeIndex::new();
        idx.add(file("/stale", 100, 10, 100));
        idx.add(file("/fresh", 100, 10, 1));
        assert_eq!(idx.not_accessed_since(30).len(), 1);
    }

    #[test]
    fn test_stale() {
        let mut idx = AgeIndex::new();
        idx.add(file("/old", 100, 100, 100));
        idx.add(file("/new", 100, 1, 1));
        assert_eq!(idx.stale(30).len(), 1);
    }

    #[test]
    fn test_stale_bytes() {
        let mut idx = AgeIndex::new();
        idx.add(file("/a", 1000, 100, 100));
        idx.add(file("/b", 500, 100, 100));
        idx.add(file("/c", 100, 1, 1));
        assert_eq!(idx.stale_bytes(30), 1500);
    }

    #[test]
    fn test_largest() {
        let mut idx = AgeIndex::new();
        idx.add(file("/small", 100, 1, 1));
        idx.add(file("/big", 10000, 1, 1));
        idx.add(file("/medium", 1000, 1, 1));
        let top = idx.largest(2);
        assert_eq!(top[0].size_bytes, 10000);
    }

    #[test]
    fn test_oldest() {
        let mut idx = AgeIndex::new();
        idx.add(file("/young", 100, 1, 1));
        idx.add(file("/old", 100, 100, 100));
        let oldest = idx.oldest(1);
        assert_eq!(oldest[0].path, PathBuf::from("/old"));
    }

    #[test]
    fn test_not_modified_since() {
        let mut idx = AgeIndex::new();
        idx.add(file("/a", 100, 60, 1));
        idx.add(file("/b", 100, 5, 5));
        assert_eq!(idx.not_modified_since(30).len(), 1);
    }
}
