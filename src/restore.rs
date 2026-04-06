//! Restore — recover files from snapshots after destructive operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A restorable backup entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub original_path: PathBuf,
    pub backup_path: PathBuf,
    pub backed_up_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub content_hash: String,
}

/// Restore status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestoreStatus {
    Available,
    InProgress,
    Restored,
    Failed { reason: String },
    Expired,
}

/// Restore manager.
pub struct RestoreManager {
    backups: HashMap<PathBuf, BackupEntry>,
    statuses: HashMap<PathBuf, RestoreStatus>,
    /// How long to keep backups (seconds).
    retention_secs: i64,
}

impl RestoreManager {
    pub fn new(retention_secs: i64) -> Self {
        Self {
            backups: HashMap::new(),
            statuses: HashMap::new(),
            retention_secs,
        }
    }

    /// Register a backup.
    pub fn register_backup(&mut self, entry: BackupEntry) {
        self.statuses.insert(entry.original_path.clone(), RestoreStatus::Available);
        self.backups.insert(entry.original_path.clone(), entry);
    }

    /// Mark a restore as in progress.
    pub fn start_restore(&mut self, path: &PathBuf) -> bool {
        if self.backups.contains_key(path) {
            self.statuses.insert(path.clone(), RestoreStatus::InProgress);
            true
        } else {
            false
        }
    }

    /// Mark restore complete.
    pub fn complete_restore(&mut self, path: &PathBuf) {
        self.statuses.insert(path.clone(), RestoreStatus::Restored);
    }

    /// Mark restore failed.
    pub fn fail_restore(&mut self, path: &PathBuf, reason: &str) {
        self.statuses.insert(path.clone(), RestoreStatus::Failed { reason: reason.into() });
    }

    /// Get the backup for a file.
    pub fn get_backup(&self, path: &PathBuf) -> Option<&BackupEntry> {
        self.backups.get(path)
    }

    /// Get the status of a path.
    pub fn status(&self, path: &PathBuf) -> Option<&RestoreStatus> {
        self.statuses.get(path)
    }

    /// Find available backups.
    pub fn available(&self) -> Vec<&BackupEntry> {
        self.backups.values()
            .filter(|b| matches!(self.statuses.get(&b.original_path), Some(RestoreStatus::Available)))
            .collect()
    }

    /// Expire old backups.
    pub fn expire_old(&mut self) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.retention_secs);
        let to_expire: Vec<PathBuf> = self.backups.iter()
            .filter(|(_, b)| b.backed_up_at < cutoff)
            .map(|(p, _)| p.clone())
            .collect();
        let count = to_expire.len();
        for path in to_expire {
            self.statuses.insert(path, RestoreStatus::Expired);
        }
        count
    }

    /// Total backup storage used.
    pub fn total_size(&self) -> u64 {
        self.backups.values().map(|b| b.size_bytes).sum()
    }

    pub fn backup_count(&self) -> usize { self.backups.len() }
}

impl Default for RestoreManager {
    fn default() -> Self { Self::new(86400 * 30) } // 30 days
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backup(path: &str) -> BackupEntry {
        BackupEntry {
            original_path: PathBuf::from(path),
            backup_path: PathBuf::from(format!("/var/backup{path}")),
            backed_up_at: Utc::now(),
            size_bytes: 1024,
            content_hash: "abc123".into(),
        }
    }

    #[test]
    fn test_register() {
        let mut mgr = RestoreManager::default();
        mgr.register_backup(make_backup("/etc/hosts"));
        assert_eq!(mgr.backup_count(), 1);
    }

    #[test]
    fn test_status_lifecycle() {
        let mut mgr = RestoreManager::default();
        let path = PathBuf::from("/etc/passwd");
        mgr.register_backup(make_backup("/etc/passwd"));
        assert_eq!(mgr.status(&path), Some(&RestoreStatus::Available));
        mgr.start_restore(&path);
        assert_eq!(mgr.status(&path), Some(&RestoreStatus::InProgress));
        mgr.complete_restore(&path);
        assert_eq!(mgr.status(&path), Some(&RestoreStatus::Restored));
    }

    #[test]
    fn test_failed_restore() {
        let mut mgr = RestoreManager::default();
        let path = PathBuf::from("/etc/file");
        mgr.register_backup(make_backup("/etc/file"));
        mgr.fail_restore(&path, "permission denied");
        match mgr.status(&path) {
            Some(RestoreStatus::Failed { reason }) => assert!(reason.contains("denied")),
            _ => panic!("Expected Failed"),
        }
    }

    #[test]
    fn test_available_filter() {
        let mut mgr = RestoreManager::default();
        mgr.register_backup(make_backup("/a"));
        mgr.register_backup(make_backup("/b"));
        mgr.start_restore(&PathBuf::from("/b"));
        let avail = mgr.available();
        assert_eq!(avail.len(), 1);
    }

    #[test]
    fn test_total_size() {
        let mut mgr = RestoreManager::default();
        mgr.register_backup(make_backup("/a"));
        mgr.register_backup(make_backup("/b"));
        assert_eq!(mgr.total_size(), 2048);
    }

    #[test]
    fn test_get_backup() {
        let mut mgr = RestoreManager::default();
        mgr.register_backup(make_backup("/etc/test"));
        let b = mgr.get_backup(&PathBuf::from("/etc/test")).unwrap();
        assert_eq!(b.size_bytes, 1024);
    }

    #[test]
    fn test_unknown_restore() {
        let mut mgr = RestoreManager::default();
        assert!(!mgr.start_restore(&PathBuf::from("/nonexistent")));
    }
}
