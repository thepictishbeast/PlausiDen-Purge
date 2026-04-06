//! File age tracking — identify old/unused files for cleanup.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Age category for files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgeCategory {
    Fresh,      // < 7 days
    Recent,     // 7-30 days
    Aging,      // 30-90 days
    Old,        // 90-365 days
    Ancient,    // > 1 year
}

/// File age info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAge {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub last_accessed: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub age_category: AgeCategory,
    pub days_since_access: i64,
}

impl FileAge {
    pub fn classify(last_accessed: DateTime<Utc>) -> AgeCategory {
        let days = (Utc::now() - last_accessed).num_days();
        if days < 7 { AgeCategory::Fresh }
        else if days < 30 { AgeCategory::Recent }
        else if days < 90 { AgeCategory::Aging }
        else if days < 365 { AgeCategory::Old }
        else { AgeCategory::Ancient }
    }
}

/// File age analyzer.
pub struct FileAgeAnalyzer {
    files: Vec<FileAge>,
}

impl FileAgeAnalyzer {
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Add a file for analysis.
    pub fn add(&mut self, path: PathBuf, size_bytes: u64, last_accessed: DateTime<Utc>, last_modified: DateTime<Utc>) {
        let age_category = FileAge::classify(last_accessed);
        let days_since_access = (Utc::now() - last_accessed).num_days();
        self.files.push(FileAge {
            path, size_bytes, last_accessed, last_modified,
            age_category, days_since_access,
        });
    }

    /// Get files in a specific age category.
    pub fn by_category(&self, category: &AgeCategory) -> Vec<&FileAge> {
        self.files.iter().filter(|f| &f.age_category == category).collect()
    }

    /// Get files older than N days.
    pub fn older_than(&self, days: i64) -> Vec<&FileAge> {
        self.files.iter().filter(|f| f.days_since_access >= days).collect()
    }

    /// Get reclaimable size (files older than threshold).
    pub fn reclaimable_size(&self, days_threshold: i64) -> u64 {
        self.older_than(days_threshold).iter().map(|f| f.size_bytes).sum()
    }

    /// Get the largest old files.
    pub fn largest_old_files(&self, n: usize, min_days: i64) -> Vec<&FileAge> {
        let mut old_files: Vec<_> = self.older_than(min_days);
        old_files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        old_files.truncate(n);
        old_files
    }

    pub fn count(&self) -> usize { self.files.len() }
}

impl Default for FileAgeAnalyzer {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_age(path: &str, size: u64, days_old: i64) -> (PathBuf, u64, DateTime<Utc>, DateTime<Utc>) {
        let access_time = Utc::now() - Duration::days(days_old);
        (PathBuf::from(path), size, access_time, access_time)
    }

    #[test]
    fn test_classify_fresh() {
        let now = Utc::now();
        assert_eq!(FileAge::classify(now), AgeCategory::Fresh);
    }

    #[test]
    fn test_classify_old() {
        let old = Utc::now() - Duration::days(120);
        assert_eq!(FileAge::classify(old), AgeCategory::Old);
    }

    #[test]
    fn test_classify_ancient() {
        let ancient = Utc::now() - Duration::days(400);
        assert_eq!(FileAge::classify(ancient), AgeCategory::Ancient);
    }

    #[test]
    fn test_add_and_count() {
        let mut analyzer = FileAgeAnalyzer::new();
        let (p, s, a, m) = make_age("/file1", 1024, 5);
        analyzer.add(p, s, a, m);
        assert_eq!(analyzer.count(), 1);
    }

    #[test]
    fn test_by_category() {
        let mut analyzer = FileAgeAnalyzer::new();
        let (p1, s1, a1, m1) = make_age("/fresh", 100, 2);
        let (p2, s2, a2, m2) = make_age("/old", 200, 100);
        analyzer.add(p1, s1, a1, m1);
        analyzer.add(p2, s2, a2, m2);
        assert_eq!(analyzer.by_category(&AgeCategory::Fresh).len(), 1);
        assert_eq!(analyzer.by_category(&AgeCategory::Old).len(), 1);
    }

    #[test]
    fn test_older_than() {
        let mut analyzer = FileAgeAnalyzer::new();
        let (p1, s1, a1, m1) = make_age("/recent", 100, 10);
        let (p2, s2, a2, m2) = make_age("/old", 200, 100);
        analyzer.add(p1, s1, a1, m1);
        analyzer.add(p2, s2, a2, m2);
        assert_eq!(analyzer.older_than(50).len(), 1);
    }

    #[test]
    fn test_reclaimable_size() {
        let mut analyzer = FileAgeAnalyzer::new();
        for i in 0..5 {
            let (p, s, a, m) = make_age(&format!("/old{i}"), 1024, 100);
            analyzer.add(p, s, a, m);
        }
        let (p, s, a, m) = make_age("/fresh", 5000, 2);
        analyzer.add(p, s, a, m);
        assert_eq!(analyzer.reclaimable_size(50), 5 * 1024);
    }

    #[test]
    fn test_largest_old_files() {
        let mut analyzer = FileAgeAnalyzer::new();
        let (p1, s1, a1, m1) = make_age("/big", 10_000, 100);
        let (p2, s2, a2, m2) = make_age("/small", 100, 100);
        let (p3, s3, a3, m3) = make_age("/medium", 5000, 100);
        analyzer.add(p1, s1, a1, m1);
        analyzer.add(p2, s2, a2, m2);
        analyzer.add(p3, s3, a3, m3);
        let top = analyzer.largest_old_files(2, 50);
        assert_eq!(top[0].size_bytes, 10_000);
    }
}
