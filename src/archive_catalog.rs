//! Archive catalog — track encrypted archives created by purge operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A cataloged archive entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub id: String,
    pub label: String,
    pub source_path: PathBuf,
    pub archive_path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub original_size_bytes: u64,
    pub file_count: u32,
    pub encrypted: bool,
    pub key_hash: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
}

impl ArchiveEntry {
    pub fn compression_ratio(&self) -> f64 {
        if self.original_size_bytes == 0 {
            return 1.0;
        }
        self.size_bytes as f64 / self.original_size_bytes as f64
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
    }

    pub fn age_days(&self) -> i64 {
        (Utc::now() - self.created_at).num_days()
    }
}

/// Archive catalog.
pub struct ArchiveCatalog {
    entries: HashMap<String, ArchiveEntry>,
}

impl ArchiveCatalog {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Add an archive entry.
    pub fn add(&mut self, entry: ArchiveEntry) {
        self.entries.insert(entry.id.clone(), entry);
    }

    /// Remove an archive by ID.
    pub fn remove(&mut self, id: &str) -> Option<ArchiveEntry> {
        self.entries.remove(id)
    }

    /// Look up an archive by ID.
    pub fn get(&self, id: &str) -> Option<&ArchiveEntry> {
        self.entries.get(id)
    }

    /// All archives.
    pub fn list(&self) -> Vec<&ArchiveEntry> {
        self.entries.values().collect()
    }

    /// Archives by tag.
    pub fn by_tag(&self, tag: &str) -> Vec<&ArchiveEntry> {
        self.entries.values()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Archives that have expired.
    pub fn expired(&self) -> Vec<&ArchiveEntry> {
        self.entries.values().filter(|e| e.is_expired()).collect()
    }

    /// Archives older than N days.
    pub fn older_than_days(&self, days: i64) -> Vec<&ArchiveEntry> {
        self.entries.values().filter(|e| e.age_days() > days).collect()
    }

    /// Search archives by label (substring match).
    pub fn search(&self, needle: &str) -> Vec<&ArchiveEntry> {
        let lower = needle.to_lowercase();
        self.entries.values()
            .filter(|e| e.label.to_lowercase().contains(&lower))
            .collect()
    }

    /// Total bytes stored across all archives.
    pub fn total_bytes(&self) -> u64 {
        self.entries.values().map(|e| e.size_bytes).sum()
    }

    /// Total original bytes (before compression/encryption).
    pub fn total_original_bytes(&self) -> u64 {
        self.entries.values().map(|e| e.original_size_bytes).sum()
    }

    /// Overall compression ratio.
    pub fn compression_ratio(&self) -> f64 {
        let original = self.total_original_bytes();
        if original == 0 {
            return 1.0;
        }
        self.total_bytes() as f64 / original as f64
    }

    /// Unique tags in the catalog.
    pub fn tags(&self) -> Vec<String> {
        let mut set = std::collections::HashSet::new();
        for e in self.entries.values() {
            for tag in &e.tags {
                set.insert(tag.clone());
            }
        }
        let mut out: Vec<String> = set.into_iter().collect();
        out.sort();
        out
    }

    pub fn archive_count(&self) -> usize { self.entries.len() }

    /// Archives with encryption disabled (flagged for review).
    pub fn unencrypted(&self) -> Vec<&ArchiveEntry> {
        self.entries.values().filter(|e| !e.encrypted).collect()
    }
}

impl Default for ArchiveCatalog {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, label: &str, size: u64, orig: u64) -> ArchiveEntry {
        ArchiveEntry {
            id: id.into(),
            label: label.into(),
            source_path: PathBuf::from("/home/user/data"),
            archive_path: PathBuf::from(format!("/archives/{}.enc", id)),
            created_at: Utc::now(),
            size_bytes: size,
            original_size_bytes: orig,
            file_count: 10,
            encrypted: true,
            key_hash: Some("abc".into()),
            expires_at: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn test_add_and_get() {
        let mut c = ArchiveCatalog::new();
        c.add(entry("a1", "photos", 500, 1000));
        assert!(c.get("a1").is_some());
    }

    #[test]
    fn test_compression_ratio() {
        let e = entry("a1", "x", 500, 1000);
        assert_eq!(e.compression_ratio(), 0.5);
    }

    #[test]
    fn test_total_bytes() {
        let mut c = ArchiveCatalog::new();
        c.add(entry("a1", "x", 100, 200));
        c.add(entry("a2", "y", 300, 500));
        assert_eq!(c.total_bytes(), 400);
        assert_eq!(c.total_original_bytes(), 700);
    }

    #[test]
    fn test_search() {
        let mut c = ArchiveCatalog::new();
        c.add(entry("a1", "Photos 2024", 100, 200));
        c.add(entry("a2", "Work docs", 100, 200));
        c.add(entry("a3", "Photo backup", 100, 200));
        let results = c.search("photo");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_by_tag() {
        let mut c = ArchiveCatalog::new();
        let mut e = entry("a1", "x", 100, 200);
        e.tags = vec!["backup".into(), "critical".into()];
        c.add(e);
        c.add(entry("a2", "y", 100, 200));
        assert_eq!(c.by_tag("backup").len(), 1);
    }

    #[test]
    fn test_expired() {
        let mut c = ArchiveCatalog::new();
        let mut e1 = entry("a1", "x", 100, 200);
        e1.expires_at = Some(Utc::now() - chrono::Duration::days(1));
        let mut e2 = entry("a2", "y", 100, 200);
        e2.expires_at = Some(Utc::now() + chrono::Duration::days(1));
        c.add(e1);
        c.add(e2);
        assert_eq!(c.expired().len(), 1);
    }

    #[test]
    fn test_older_than_days() {
        let mut c = ArchiveCatalog::new();
        let mut old = entry("old", "x", 100, 200);
        old.created_at = Utc::now() - chrono::Duration::days(100);
        let new = entry("new", "y", 100, 200);
        c.add(old);
        c.add(new);
        assert_eq!(c.older_than_days(30).len(), 1);
    }

    #[test]
    fn test_unencrypted() {
        let mut c = ArchiveCatalog::new();
        let mut e = entry("a1", "x", 100, 200);
        e.encrypted = false;
        c.add(e);
        c.add(entry("a2", "y", 100, 200));
        assert_eq!(c.unencrypted().len(), 1);
    }

    #[test]
    fn test_tags_aggregation() {
        let mut c = ArchiveCatalog::new();
        let mut e1 = entry("a1", "x", 100, 200);
        e1.tags = vec!["a".into(), "b".into()];
        let mut e2 = entry("a2", "y", 100, 200);
        e2.tags = vec!["b".into(), "c".into()];
        c.add(e1);
        c.add(e2);
        let tags = c.tags();
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn test_remove() {
        let mut c = ArchiveCatalog::new();
        c.add(entry("a1", "x", 100, 200));
        assert!(c.remove("a1").is_some());
        assert_eq!(c.archive_count(), 0);
    }
}
