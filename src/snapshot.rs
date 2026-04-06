//! Snapshot manager — capture system state for rollback before destructive operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A system state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub description: String,
    pub files: Vec<FileSnapshot>,
    pub metadata: HashMap<String, String>,
}

/// Snapshot of a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub hash: String,
    pub modified: DateTime<Utc>,
}

/// Snapshot manager.
pub struct SnapshotManager {
    snapshots: Vec<Snapshot>,
    max_snapshots: usize,
}

impl SnapshotManager {
    pub fn new(max_snapshots: usize) -> Self {
        Self {
            snapshots: Vec::new(),
            max_snapshots,
        }
    }

    /// Create a new snapshot.
    pub fn create(&mut self, description: &str, files: Vec<FileSnapshot>) -> String {
        let id = format!("snap-{}", Utc::now().timestamp_millis());
        let snapshot = Snapshot {
            id: id.clone(),
            created_at: Utc::now(),
            description: description.into(),
            files,
            metadata: HashMap::new(),
        };
        self.snapshots.push(snapshot);

        // Evict oldest if over limit.
        while self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0);
        }

        id
    }

    /// Get a snapshot by ID.
    pub fn get(&self, id: &str) -> Option<&Snapshot> {
        self.snapshots.iter().find(|s| s.id == id)
    }

    /// Delete a snapshot.
    pub fn delete(&mut self, id: &str) -> bool {
        let len_before = self.snapshots.len();
        self.snapshots.retain(|s| s.id != id);
        self.snapshots.len() != len_before
    }

    /// List all snapshots.
    pub fn list(&self) -> Vec<&Snapshot> {
        self.snapshots.iter().collect()
    }

    /// Get the most recent snapshot.
    pub fn latest(&self) -> Option<&Snapshot> {
        self.snapshots.last()
    }

    /// Compare two snapshots — files added, removed, modified.
    pub fn diff(&self, old_id: &str, new_id: &str) -> Option<SnapshotDiff> {
        let old = self.get(old_id)?;
        let new = self.get(new_id)?;

        let old_paths: HashMap<&PathBuf, &FileSnapshot> = old.files.iter()
            .map(|f| (&f.path, f))
            .collect();
        let new_paths: HashMap<&PathBuf, &FileSnapshot> = new.files.iter()
            .map(|f| (&f.path, f))
            .collect();

        let added: Vec<PathBuf> = new_paths.keys()
            .filter(|p| !old_paths.contains_key(*p))
            .map(|p| (*p).clone())
            .collect();

        let removed: Vec<PathBuf> = old_paths.keys()
            .filter(|p| !new_paths.contains_key(*p))
            .map(|p| (*p).clone())
            .collect();

        let modified: Vec<PathBuf> = new_paths.iter()
            .filter(|(p, new_f)| {
                old_paths.get(p).map(|old_f| old_f.hash != new_f.hash).unwrap_or(false)
            })
            .map(|(p, _)| (*p).clone())
            .collect();

        Some(SnapshotDiff { added, removed, modified })
    }

    pub fn count(&self) -> usize { self.snapshots.len() }
}

impl Default for SnapshotManager {
    fn default() -> Self { Self::new(10) }
}

/// Diff between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiff {
    pub added: Vec<PathBuf>,
    pub removed: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
}

impl SnapshotDiff {
    pub fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file(path: &str, hash: &str) -> FileSnapshot {
        FileSnapshot {
            path: PathBuf::from(path),
            size_bytes: 1024,
            hash: hash.into(),
            modified: Utc::now(),
        }
    }

    #[test]
    fn test_create_snapshot() {
        let mut mgr = SnapshotManager::default();
        let id = mgr.create("test", vec![make_file("/etc/test", "h1")]);
        assert!(!id.is_empty());
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_get_snapshot() {
        let mut mgr = SnapshotManager::default();
        let id = mgr.create("test", vec![]);
        assert!(mgr.get(&id).is_some());
    }

    #[test]
    fn test_delete_snapshot() {
        let mut mgr = SnapshotManager::default();
        let id = mgr.create("test", vec![]);
        assert!(mgr.delete(&id));
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_max_snapshots() {
        let mut mgr = SnapshotManager::new(3);
        for i in 0..5 {
            mgr.create(&format!("snap{i}"), vec![]);
        }
        assert_eq!(mgr.count(), 3);
    }

    #[test]
    fn test_diff_added() {
        let mut mgr = SnapshotManager::default();
        let id1 = mgr.create("v1", vec![make_file("/a", "h")]);
        let id2 = mgr.create("v2", vec![
            make_file("/a", "h"),
            make_file("/b", "h"),
        ]);
        let diff = mgr.diff(&id1, &id2).unwrap();
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.modified.len(), 0);
    }

    #[test]
    fn test_diff_removed() {
        let mut mgr = SnapshotManager::default();
        let id1 = mgr.create("v1", vec![make_file("/a", "h"), make_file("/b", "h")]);
        let id2 = mgr.create("v2", vec![make_file("/a", "h")]);
        let diff = mgr.diff(&id1, &id2).unwrap();
        assert_eq!(diff.removed.len(), 1);
    }

    #[test]
    fn test_diff_modified() {
        let mut mgr = SnapshotManager::default();
        let id1 = mgr.create("v1", vec![make_file("/a", "h1")]);
        let id2 = mgr.create("v2", vec![make_file("/a", "h2")]);
        let diff = mgr.diff(&id1, &id2).unwrap();
        assert_eq!(diff.modified.len(), 1);
    }

    #[test]
    fn test_latest() {
        let mut mgr = SnapshotManager::default();
        mgr.create("v1", vec![]);
        let id = mgr.create("v2", vec![]);
        assert_eq!(mgr.latest().unwrap().id, id);
    }

    #[test]
    fn test_total_changes() {
        let diff = SnapshotDiff {
            added: vec![PathBuf::from("/a")],
            removed: vec![PathBuf::from("/b"), PathBuf::from("/c")],
            modified: vec![PathBuf::from("/d")],
        };
        assert_eq!(diff.total_changes(), 4);
    }
}
