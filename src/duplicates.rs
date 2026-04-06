//! Duplicate file detection — find and optionally remove duplicate files.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A group of duplicate files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub hash: String,
    pub size_bytes: u64,
    pub files: Vec<PathBuf>,
}

impl DuplicateGroup {
    /// Total wasted space (all duplicates except one).
    pub fn wasted_space(&self) -> u64 {
        self.size_bytes * (self.files.len().saturating_sub(1) as u64)
    }
}

/// Duplicate detector.
pub struct DuplicateDetector {
    /// Map: hash → list of files with that hash
    by_hash: HashMap<String, Vec<(PathBuf, u64)>>,
}

impl DuplicateDetector {
    pub fn new() -> Self {
        Self { by_hash: HashMap::new() }
    }

    /// Add a file to the detector.
    pub fn add(&mut self, path: PathBuf, hash: String, size: u64) {
        self.by_hash.entry(hash).or_default().push((path, size));
    }

    /// Find all duplicate groups.
    pub fn find_duplicates(&self) -> Vec<DuplicateGroup> {
        self.by_hash.iter()
            .filter(|(_, files)| files.len() >= 2)
            .map(|(hash, files)| DuplicateGroup {
                hash: hash.clone(),
                size_bytes: files[0].1,
                files: files.iter().map(|(p, _)| p.clone()).collect(),
            })
            .collect()
    }

    /// Total wasted space across all duplicates.
    pub fn total_wasted_space(&self) -> u64 {
        self.find_duplicates().iter().map(|g| g.wasted_space()).sum()
    }

    /// Find the largest duplicate groups by wasted space.
    pub fn largest_duplicates(&self, n: usize) -> Vec<DuplicateGroup> {
        let mut groups = self.find_duplicates();
        groups.sort_by(|a, b| b.wasted_space().cmp(&a.wasted_space()));
        groups.truncate(n);
        groups
    }

    /// Suggest which files to delete (keep one per group).
    pub fn suggest_deletions(&self) -> Vec<PathBuf> {
        self.find_duplicates().into_iter()
            .flat_map(|g| {
                let mut files = g.files;
                // Keep first, delete rest.
                if files.len() > 1 {
                    files.remove(0);
                    files
                } else {
                    Vec::new()
                }
            })
            .collect()
    }

    pub fn file_count(&self) -> usize {
        self.by_hash.values().map(|v| v.len()).sum()
    }

    pub fn unique_count(&self) -> usize { self.by_hash.len() }
}

impl Default for DuplicateDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_duplicates() {
        let mut det = DuplicateDetector::new();
        det.add(PathBuf::from("/a"), "hash1".into(), 100);
        det.add(PathBuf::from("/b"), "hash2".into(), 200);
        assert!(det.find_duplicates().is_empty());
    }

    #[test]
    fn test_find_duplicates() {
        let mut det = DuplicateDetector::new();
        det.add(PathBuf::from("/a"), "hash1".into(), 100);
        det.add(PathBuf::from("/b"), "hash1".into(), 100);
        det.add(PathBuf::from("/c"), "hash2".into(), 200);
        let dupes = det.find_duplicates();
        assert_eq!(dupes.len(), 1);
        assert_eq!(dupes[0].files.len(), 2);
    }

    #[test]
    fn test_wasted_space() {
        let mut det = DuplicateDetector::new();
        // 3 copies of a 100-byte file = 200 bytes wasted.
        det.add(PathBuf::from("/a"), "h".into(), 100);
        det.add(PathBuf::from("/b"), "h".into(), 100);
        det.add(PathBuf::from("/c"), "h".into(), 100);
        assert_eq!(det.total_wasted_space(), 200);
    }

    #[test]
    fn test_suggest_deletions() {
        let mut det = DuplicateDetector::new();
        det.add(PathBuf::from("/a"), "h".into(), 100);
        det.add(PathBuf::from("/b"), "h".into(), 100);
        det.add(PathBuf::from("/c"), "h".into(), 100);
        let to_delete = det.suggest_deletions();
        assert_eq!(to_delete.len(), 2); // Keep 1, delete 2.
    }

    #[test]
    fn test_largest_duplicates() {
        let mut det = DuplicateDetector::new();
        det.add(PathBuf::from("/big_a"), "h1".into(), 10_000);
        det.add(PathBuf::from("/big_b"), "h1".into(), 10_000);
        det.add(PathBuf::from("/small_a"), "h2".into(), 100);
        det.add(PathBuf::from("/small_b"), "h2".into(), 100);
        let largest = det.largest_duplicates(1);
        assert_eq!(largest[0].size_bytes, 10_000);
    }

    #[test]
    fn test_unique_count() {
        let mut det = DuplicateDetector::new();
        det.add(PathBuf::from("/a"), "h1".into(), 100);
        det.add(PathBuf::from("/b"), "h1".into(), 100);
        det.add(PathBuf::from("/c"), "h2".into(), 200);
        assert_eq!(det.unique_count(), 2);
    }

    #[test]
    fn test_file_count() {
        let mut det = DuplicateDetector::new();
        det.add(PathBuf::from("/a"), "h1".into(), 100);
        det.add(PathBuf::from("/b"), "h1".into(), 100);
        assert_eq!(det.file_count(), 2);
    }
}
