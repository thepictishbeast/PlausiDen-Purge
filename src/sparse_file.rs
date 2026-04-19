//! Sparse file detector — identify files with significant allocated-vs-actual gaps.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A sparse file record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseFile {
    pub path: PathBuf,
    pub apparent_size: u64,  // what the file reports as its logical size
    pub actual_size: u64,    // disk blocks actually allocated
}

impl SparseFile {
    /// Sparseness ratio: 0.0 = fully allocated, 1.0 = entirely sparse.
    pub fn sparseness(&self) -> f64 {
        if self.apparent_size == 0 {
            return 0.0;
        }
        let saved = self.apparent_size.saturating_sub(self.actual_size);
        saved as f64 / self.apparent_size as f64
    }

    /// Bytes saved by the sparse representation.
    pub fn bytes_saved(&self) -> u64 {
        self.apparent_size.saturating_sub(self.actual_size)
    }

    /// Is this file actually sparse?
    pub fn is_sparse(&self, min_sparseness: f64) -> bool {
        self.sparseness() >= min_sparseness
    }
}

/// Sparse file detector.
pub struct SparseDetector {
    files: Vec<SparseFile>,
    min_sparseness: f64,
    min_apparent_size: u64,
}

impl SparseDetector {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            min_sparseness: 0.1,
            min_apparent_size: 4096,
        }
    }

    /// Set the sparseness threshold.
    pub fn set_min_sparseness(&mut self, ratio: f64) {
        self.min_sparseness = ratio;
    }

    /// Set the minimum apparent size to consider.
    pub fn set_min_apparent_size(&mut self, bytes: u64) {
        self.min_apparent_size = bytes;
    }

    /// Observe a file. Returns Some(SparseFile) if it meets the criteria.
    pub fn observe(&mut self, path: PathBuf, apparent: u64, actual: u64) -> Option<&SparseFile> {
        if apparent < self.min_apparent_size {
            return None;
        }
        let file = SparseFile {
            path,
            apparent_size: apparent,
            actual_size: actual,
        };
        if !file.is_sparse(self.min_sparseness) {
            return None;
        }
        self.files.push(file);
        self.files.last()
    }

    /// All sparse files.
    pub fn files(&self) -> &[SparseFile] {
        &self.files
    }

    /// Top N sparsest files.
    pub fn top_sparsest(&self, n: usize) -> Vec<&SparseFile> {
        let mut sorted: Vec<&SparseFile> = self.files.iter().collect();
        sorted.sort_by(|a, b| b.sparseness().partial_cmp(&a.sparseness()).unwrap_or(std::cmp::Ordering::Equal)); // SAFETY: sparseness is a ratio in [0.0, 1.0]; never NaN, but Equal fallback for total ordering
        sorted.truncate(n);
        sorted
    }

    /// Top N files by bytes saved.
    pub fn top_savers(&self, n: usize) -> Vec<&SparseFile> {
        let mut sorted: Vec<&SparseFile> = self.files.iter().collect();
        sorted.sort_by(|a, b| b.bytes_saved().cmp(&a.bytes_saved()));
        sorted.truncate(n);
        sorted
    }

    /// Total bytes saved across all sparse files.
    pub fn total_bytes_saved(&self) -> u64 {
        self.files.iter().map(|f| f.bytes_saved()).sum()
    }

    /// Total apparent bytes.
    pub fn total_apparent_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.apparent_size).sum()
    }

    /// Total actual bytes.
    pub fn total_actual_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.actual_size).sum()
    }

    /// Overall sparseness ratio.
    pub fn overall_sparseness(&self) -> f64 {
        let apparent = self.total_apparent_bytes();
        if apparent == 0 { return 0.0; }
        self.total_bytes_saved() as f64 / apparent as f64
    }

    /// Clear all records.
    pub fn clear(&mut self) {
        self.files.clear();
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

impl Default for SparseDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparseness_calc() {
        let f = SparseFile {
            path: PathBuf::from("/x"),
            apparent_size: 1000,
            actual_size: 200,
        };
        assert_eq!(f.sparseness(), 0.8);
        assert_eq!(f.bytes_saved(), 800);
    }

    #[test]
    fn test_is_sparse() {
        let f = SparseFile {
            path: PathBuf::from("/x"),
            apparent_size: 1000,
            actual_size: 500,
        };
        assert!(f.is_sparse(0.4));
        assert!(!f.is_sparse(0.6));
    }

    #[test]
    fn test_observe_sparse_file() {
        let mut d = SparseDetector::new();
        assert!(d.observe(PathBuf::from("/big"), 100_000, 10_000).is_some());
    }

    #[test]
    fn test_observe_non_sparse_file() {
        let mut d = SparseDetector::new();
        assert!(d.observe(PathBuf::from("/full"), 100_000, 100_000).is_none());
    }

    #[test]
    fn test_observe_too_small_file() {
        let mut d = SparseDetector::new();
        assert!(d.observe(PathBuf::from("/tiny"), 100, 10).is_none());
    }

    #[test]
    fn test_top_sparsest() {
        let mut d = SparseDetector::new();
        d.observe(PathBuf::from("/half"), 100_000, 50_000);
        d.observe(PathBuf::from("/very"), 100_000, 10_000);
        d.observe(PathBuf::from("/some"), 100_000, 80_000);
        let top = d.top_sparsest(2);
        assert_eq!(top[0].path, PathBuf::from("/very"));
    }

    #[test]
    fn test_top_savers() {
        let mut d = SparseDetector::new();
        d.observe(PathBuf::from("/small"), 10_000, 1_000);
        d.observe(PathBuf::from("/huge"), 1_000_000, 100_000);
        let top = d.top_savers(1);
        assert_eq!(top[0].path, PathBuf::from("/huge"));
    }

    #[test]
    fn test_totals() {
        let mut d = SparseDetector::new();
        d.observe(PathBuf::from("/a"), 100_000, 20_000);
        d.observe(PathBuf::from("/b"), 50_000, 10_000);
        assert_eq!(d.total_apparent_bytes(), 150_000);
        assert_eq!(d.total_actual_bytes(), 30_000);
        assert_eq!(d.total_bytes_saved(), 120_000);
    }

    #[test]
    fn test_overall_sparseness() {
        let mut d = SparseDetector::new();
        d.observe(PathBuf::from("/a"), 100_000, 20_000);
        let ratio = d.overall_sparseness();
        assert!((ratio - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_clear() {
        let mut d = SparseDetector::new();
        d.observe(PathBuf::from("/a"), 100_000, 10_000);
        d.clear();
        assert_eq!(d.file_count(), 0);
    }
}
