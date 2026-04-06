//! Log archiver — compress and archive old system logs before purging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A log archive operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveOp {
    pub id: String,
    pub source: PathBuf,
    pub destination: PathBuf,
    pub original_size: u64,
    pub archived_size: u64,
    pub compression: Compression,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub state: OpState,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compression {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lz4,
}

impl Compression {
    /// Expected compression ratio (rough).
    pub fn expected_ratio(&self) -> f64 {
        match self {
            Compression::None => 1.0,
            Compression::Gzip => 0.25,
            Compression::Bzip2 => 0.20,
            Compression::Xz => 0.15,
            Compression::Zstd => 0.22,
            Compression::Lz4 => 0.35,
        }
    }

    /// File extension.
    pub fn extension(&self) -> &'static str {
        match self {
            Compression::None => "",
            Compression::Gzip => ".gz",
            Compression::Bzip2 => ".bz2",
            Compression::Xz => ".xz",
            Compression::Zstd => ".zst",
            Compression::Lz4 => ".lz4",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpState {
    Queued,
    Running,
    Completed,
    Failed,
}

/// Log archiver.
pub struct LogArchiver {
    ops: HashMap<String, ArchiveOp>,
    total_bytes_archived: u64,
    total_bytes_saved: u64,
    default_compression: Compression,
}

impl LogArchiver {
    pub fn new(default_compression: Compression) -> Self {
        Self {
            ops: HashMap::new(),
            total_bytes_archived: 0,
            total_bytes_saved: 0,
            default_compression,
        }
    }

    /// Queue an archive operation.
    pub fn queue(&mut self, id: &str, source: PathBuf, destination: PathBuf, size: u64) -> String {
        self.ops.insert(id.into(), ArchiveOp {
            id: id.into(),
            source,
            destination,
            original_size: size,
            archived_size: 0,
            compression: self.default_compression.clone(),
            started_at: Utc::now(),
            completed_at: None,
            state: OpState::Queued,
            error: None,
        });
        id.into()
    }

    /// Start an operation.
    pub fn start(&mut self, id: &str) -> bool {
        if let Some(op) = self.ops.get_mut(id) {
            if op.state == OpState::Queued {
                op.state = OpState::Running;
                op.started_at = Utc::now();
                return true;
            }
        }
        false
    }

    /// Mark completed with the resulting archive size.
    pub fn complete(&mut self, id: &str, archived_size: u64) -> bool {
        if let Some(op) = self.ops.get_mut(id) {
            op.state = OpState::Completed;
            op.archived_size = archived_size;
            op.completed_at = Some(Utc::now());
            self.total_bytes_archived += archived_size;
            if op.original_size > archived_size {
                self.total_bytes_saved += op.original_size - archived_size;
            }
            return true;
        }
        false
    }

    /// Mark failed.
    pub fn fail(&mut self, id: &str, error: &str) -> bool {
        if let Some(op) = self.ops.get_mut(id) {
            op.state = OpState::Failed;
            op.error = Some(error.into());
            op.completed_at = Some(Utc::now());
            return true;
        }
        false
    }

    /// Get an operation.
    pub fn get(&self, id: &str) -> Option<&ArchiveOp> {
        self.ops.get(id)
    }

    /// Queued operations.
    pub fn queued(&self) -> Vec<&ArchiveOp> {
        self.ops.values().filter(|o| o.state == OpState::Queued).collect()
    }

    /// Completed operations.
    pub fn completed(&self) -> Vec<&ArchiveOp> {
        self.ops.values().filter(|o| o.state == OpState::Completed).collect()
    }

    /// Failed operations.
    pub fn failed(&self) -> Vec<&ArchiveOp> {
        self.ops.values().filter(|o| o.state == OpState::Failed).collect()
    }

    /// Compression efficiency (fraction of bytes saved).
    pub fn compression_ratio(&self) -> f64 {
        let total_original: u64 = self.ops.values()
            .filter(|o| o.state == OpState::Completed)
            .map(|o| o.original_size)
            .sum();
        if total_original == 0 { return 0.0; }
        self.total_bytes_saved as f64 / total_original as f64
    }

    pub fn total_saved(&self) -> u64 { self.total_bytes_saved }
    pub fn total_archived(&self) -> u64 { self.total_bytes_archived }
    pub fn op_count(&self) -> usize { self.ops.len() }
}

impl Default for LogArchiver {
    fn default() -> Self { Self::new(Compression::Zstd) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_ratios() {
        assert!(Compression::Xz.expected_ratio() < Compression::Gzip.expected_ratio());
        assert!(Compression::None.expected_ratio() == 1.0);
    }

    #[test]
    fn test_extensions() {
        assert_eq!(Compression::Gzip.extension(), ".gz");
        assert_eq!(Compression::Zstd.extension(), ".zst");
    }

    #[test]
    fn test_queue_op() {
        let mut a = LogArchiver::default();
        a.queue("op1", PathBuf::from("/var/log/x"), PathBuf::from("/archive/x.zst"), 1000);
        assert_eq!(a.op_count(), 1);
        assert_eq!(a.get("op1").unwrap().state, OpState::Queued);
    }

    #[test]
    fn test_complete_updates_totals() {
        let mut a = LogArchiver::default();
        a.queue("op1", PathBuf::from("/x"), PathBuf::from("/y"), 1000);
        a.start("op1");
        a.complete("op1", 200);
        assert_eq!(a.total_archived(), 200);
        assert_eq!(a.total_saved(), 800);
    }

    #[test]
    fn test_fail() {
        let mut a = LogArchiver::default();
        a.queue("op1", PathBuf::from("/x"), PathBuf::from("/y"), 1000);
        a.fail("op1", "io error");
        let op = a.get("op1").unwrap();
        assert_eq!(op.state, OpState::Failed);
        assert_eq!(op.error.as_deref(), Some("io error"));
    }

    #[test]
    fn test_queued_list() {
        let mut a = LogArchiver::default();
        a.queue("op1", PathBuf::from("/a"), PathBuf::from("/a.zst"), 100);
        a.queue("op2", PathBuf::from("/b"), PathBuf::from("/b.zst"), 100);
        a.start("op1");
        assert_eq!(a.queued().len(), 1);
    }

    #[test]
    fn test_compression_ratio() {
        let mut a = LogArchiver::default();
        a.queue("op1", PathBuf::from("/x"), PathBuf::from("/y"), 1000);
        a.complete("op1", 200);
        assert!((a.compression_ratio() - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_state_transitions() {
        let mut a = LogArchiver::default();
        a.queue("op1", PathBuf::from("/x"), PathBuf::from("/y"), 1000);
        assert!(a.start("op1"));
        assert_eq!(a.get("op1").unwrap().state, OpState::Running);
        assert!(a.complete("op1", 100));
        assert_eq!(a.get("op1").unwrap().state, OpState::Completed);
    }

    #[test]
    fn test_failed_list() {
        let mut a = LogArchiver::default();
        a.queue("op1", PathBuf::from("/x"), PathBuf::from("/y"), 1000);
        a.fail("op1", "err");
        assert_eq!(a.failed().len(), 1);
    }
}
