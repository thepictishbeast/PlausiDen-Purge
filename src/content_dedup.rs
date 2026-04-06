//! Content deduplication — find duplicate files by content hash.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A file catalog entry keyed by content hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub content_hash: String,
    pub modified_at: DateTime<Utc>,
    pub hash_algorithm: String,
}

/// A group of duplicate files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub content_hash: String,
    pub size_bytes: u64,
    pub files: Vec<CatalogEntry>,
}

impl DuplicateGroup {
    /// Total bytes that could be reclaimed by deleting duplicates.
    pub fn reclaimable_bytes(&self) -> u64 {
        if self.files.len() < 2 { return 0; }
        self.size_bytes * (self.files.len() as u64 - 1)
    }

    /// The canonical (oldest) file in the group.
    pub fn canonical(&self) -> Option<&CatalogEntry> {
        self.files.iter().min_by_key(|f| f.modified_at)
    }

    /// Non-canonical files (candidates for deletion).
    pub fn duplicates_of(&self, canonical: &CatalogEntry) -> Vec<&CatalogEntry> {
        self.files.iter().filter(|f| f.path != canonical.path).collect()
    }
}

/// Content dedup catalog.
pub struct ContentDedup {
    entries: Vec<CatalogEntry>,
    index: HashMap<String, Vec<usize>>, // hash → indices into entries
}

impl ContentDedup {
    pub fn new() -> Self {
        Self { entries: Vec::new(), index: HashMap::new() }
    }

    /// Add an entry.
    pub fn add(&mut self, entry: CatalogEntry) {
        let idx = self.entries.len();
        self.index.entry(entry.content_hash.clone()).or_default().push(idx);
        self.entries.push(entry);
    }

    /// Find duplicate groups.
    pub fn duplicate_groups(&self) -> Vec<DuplicateGroup> {
        self.index.iter()
            .filter(|(_, indices)| indices.len() > 1)
            .map(|(hash, indices)| {
                let files: Vec<CatalogEntry> = indices.iter()
                    .map(|i| self.entries[*i].clone())
                    .collect();
                let size = files.first().map(|f| f.size_bytes).unwrap_or(0);
                DuplicateGroup {
                    content_hash: hash.clone(),
                    size_bytes: size,
                    files,
                }
            })
            .collect()
    }

    /// Total reclaimable bytes.
    pub fn total_reclaimable(&self) -> u64 {
        self.duplicate_groups().iter().map(|g| g.reclaimable_bytes()).sum()
    }

    /// Number of duplicate groups.
    pub fn duplicate_group_count(&self) -> usize {
        self.index.values().filter(|v| v.len() > 1).count()
    }

    /// Total entries cataloged.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Unique file count (distinct hashes).
    pub fn unique_count(&self) -> usize {
        self.index.len()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.index.clear();
    }

    /// Entries with a specific hash.
    pub fn entries_with_hash(&self, hash: &str) -> Vec<&CatalogEntry> {
        self.index.get(hash)
            .map(|indices| indices.iter().map(|i| &self.entries[*i]).collect())
            .unwrap_or_default()
    }

    /// Compute a quick content hash (DefaultHasher-based, not cryptographic).
    pub fn quick_hash(content: &[u8]) -> String {
        use std::hash::{Hasher, BuildHasher};
        let mut h1 = std::collections::hash_map::RandomState::new().build_hasher();
        h1.write(content);
        format!("{:016x}", h1.finish())
    }
}

impl Default for ContentDedup {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, hash: &str, size: u64) -> CatalogEntry {
        CatalogEntry {
            path: PathBuf::from(path),
            size_bytes: size,
            content_hash: hash.into(),
            modified_at: Utc::now(),
            hash_algorithm: "blake3".into(),
        }
    }

    #[test]
    fn test_add_entry() {
        let mut d = ContentDedup::new();
        d.add(entry("/a", "hash1", 100));
        assert_eq!(d.entry_count(), 1);
    }

    #[test]
    fn test_duplicate_detection() {
        let mut d = ContentDedup::new();
        d.add(entry("/a", "hash1", 100));
        d.add(entry("/b", "hash1", 100));
        d.add(entry("/c", "hash2", 200));
        let groups = d.duplicate_groups();
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn test_reclaimable_bytes() {
        let group = DuplicateGroup {
            content_hash: "x".into(),
            size_bytes: 1000,
            files: vec![
                entry("/a", "x", 1000),
                entry("/b", "x", 1000),
                entry("/c", "x", 1000),
            ],
        };
        // 3 files of 1000 bytes: can reclaim 2000 (delete 2 duplicates).
        assert_eq!(group.reclaimable_bytes(), 2000);
    }

    #[test]
    fn test_single_file_no_reclaim() {
        let group = DuplicateGroup {
            content_hash: "x".into(),
            size_bytes: 1000,
            files: vec![entry("/a", "x", 1000)],
        };
        assert_eq!(group.reclaimable_bytes(), 0);
    }

    #[test]
    fn test_canonical_oldest() {
        let mut old = entry("/old", "x", 100);
        old.modified_at = Utc::now() - chrono::Duration::days(10);
        let new = entry("/new", "x", 100);
        let group = DuplicateGroup {
            content_hash: "x".into(),
            size_bytes: 100,
            files: vec![old.clone(), new],
        };
        assert_eq!(group.canonical().unwrap().path, old.path);
    }

    #[test]
    fn test_total_reclaimable() {
        let mut d = ContentDedup::new();
        d.add(entry("/a", "h1", 1000));
        d.add(entry("/b", "h1", 1000));
        d.add(entry("/c", "h2", 500));
        d.add(entry("/d", "h2", 500));
        d.add(entry("/e", "h2", 500));
        // h1: 1000, h2: 1000 → 2000.
        assert_eq!(d.total_reclaimable(), 2000);
    }

    #[test]
    fn test_unique_count() {
        let mut d = ContentDedup::new();
        d.add(entry("/a", "h1", 100));
        d.add(entry("/b", "h1", 100));
        d.add(entry("/c", "h2", 100));
        assert_eq!(d.unique_count(), 2);
    }

    #[test]
    fn test_entries_with_hash() {
        let mut d = ContentDedup::new();
        d.add(entry("/a", "h1", 100));
        d.add(entry("/b", "h1", 100));
        assert_eq!(d.entries_with_hash("h1").len(), 2);
    }

    #[test]
    fn test_quick_hash_deterministic() {
        let h1 = ContentDedup::quick_hash(b"hello");
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn test_clear() {
        let mut d = ContentDedup::new();
        d.add(entry("/a", "h1", 100));
        d.clear();
        assert_eq!(d.entry_count(), 0);
    }

    #[test]
    fn test_duplicates_of() {
        let canon = entry("/canonical", "x", 100);
        let dup1 = entry("/dup1", "x", 100);
        let dup2 = entry("/dup2", "x", 100);
        let group = DuplicateGroup {
            content_hash: "x".into(),
            size_bytes: 100,
            files: vec![canon.clone(), dup1, dup2],
        };
        assert_eq!(group.duplicates_of(&canon).len(), 2);
    }
}
