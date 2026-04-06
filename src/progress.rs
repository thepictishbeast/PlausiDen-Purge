//! Shared progress & cancellation primitive for long-running Purge
//! operations.
//!
//! Ported from the ScanProgress pattern in plausiden-tidy's scanner
//! per the AVP-2 cross-repo contribution protocol: any operation that
//! can run for more than a second needs a caller-visible progress
//! handle and a cancel flag.
//!
//! BUG ASSUMPTION: multiple worker threads may update these counters
//! concurrently; the UI thread reads them at arbitrary frequency; the
//! cancel flag may be set from any thread at any time.

use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Shared progress state for a running Purge operation.
#[derive(Debug, Default)]
pub struct PurgeProgress {
    /// Total bytes the operation expects to write when known.
    pub total_bytes: AtomicU64,
    /// Bytes actually written so far.
    pub bytes_written: AtomicU64,
    /// Passes fully completed (each multi-pass wipe advances this).
    pub passes_completed: AtomicU64,
    /// Total passes the operation plans to run.
    pub total_passes: AtomicU64,
    /// Human-readable label of the current step, e.g. "pass 2/7: complement".
    pub current_step: Mutex<Option<String>>,
    /// Path currently being processed.
    pub current_path: Mutex<Option<PathBuf>>,
    /// Set true to request cancellation. Long-running loops check this.
    pub cancel: AtomicBool,
}

impl PurgeProgress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn set_step(&self, step: impl Into<String>) {
        if let Ok(mut guard) = self.current_step.lock() {
            *guard = Some(step.into());
        }
    }

    pub fn set_path(&self, path: PathBuf) {
        if let Ok(mut guard) = self.current_path.lock() {
            *guard = Some(path);
        }
    }

    pub fn snapshot(&self) -> PurgeProgressSnapshot {
        PurgeProgressSnapshot {
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            passes_completed: self.passes_completed.load(Ordering::Relaxed),
            total_passes: self.total_passes.load(Ordering::Relaxed),
            current_step: self
                .current_step
                .lock()
                .ok()
                .and_then(|g| g.clone()),
            current_path: self
                .current_path
                .lock()
                .ok()
                .and_then(|g| g.clone()),
            cancelled: self.is_cancelled(),
        }
    }

    pub fn fraction(&self) -> f64 {
        let total = self.total_bytes.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let done = self.bytes_written.load(Ordering::Relaxed) as f64;
        (done / total as f64).clamp(0.0, 1.0)
    }
}

/// Point-in-time copy of progress safe to send to a UI thread.
#[derive(Debug, Clone, Serialize)]
pub struct PurgeProgressSnapshot {
    pub total_bytes: u64,
    pub bytes_written: u64,
    pub passes_completed: u64,
    pub total_passes: u64,
    pub current_step: Option<String>,
    pub current_path: Option<PathBuf>,
    pub cancelled: bool,
}

/// Trait implemented by long-running Purge operations that want to
/// surface progress. The operation owns the progress instance and
/// returns the shared Arc to the caller, who can poll snapshots and
/// request cancellation.
pub trait ProgressHandle {
    fn progress(&self) -> Arc<PurgeProgress>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_progress_is_blank() {
        let p = PurgeProgress::new();
        assert_eq!(p.total_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(p.bytes_written.load(Ordering::Relaxed), 0);
        assert!(!p.is_cancelled());
    }

    #[test]
    fn test_cancel_flips_flag() {
        let p = PurgeProgress::new();
        p.request_cancel();
        assert!(p.is_cancelled());
    }

    #[test]
    fn test_fraction_is_zero_with_no_total() {
        let p = PurgeProgress::new();
        assert_eq!(p.fraction(), 0.0);
    }

    #[test]
    fn test_fraction_clamps_to_one() {
        let p = PurgeProgress::new();
        p.total_bytes.store(100, Ordering::Relaxed);
        p.bytes_written.store(250, Ordering::Relaxed);
        assert_eq!(p.fraction(), 1.0);
    }

    #[test]
    fn test_fraction_mid() {
        let p = PurgeProgress::new();
        p.total_bytes.store(100, Ordering::Relaxed);
        p.bytes_written.store(25, Ordering::Relaxed);
        assert_eq!(p.fraction(), 0.25);
    }

    #[test]
    fn test_set_and_read_step() {
        let p = PurgeProgress::new();
        p.set_step("pass 1/3: random");
        let snap = p.snapshot();
        assert_eq!(snap.current_step.as_deref(), Some("pass 1/3: random"));
    }

    #[test]
    fn test_set_and_read_path() {
        let p = PurgeProgress::new();
        p.set_path(PathBuf::from("/tmp/x"));
        let snap = p.snapshot();
        assert_eq!(snap.current_path, Some(PathBuf::from("/tmp/x")));
    }

    #[test]
    fn test_snapshot_carries_cancel_state() {
        let p = PurgeProgress::new();
        p.request_cancel();
        assert!(p.snapshot().cancelled);
    }

    #[test]
    fn test_counters_can_be_updated_concurrently() {
        use std::thread;
        let p = PurgeProgress::new();
        let mut handles = vec![];
        for _ in 0..8 {
            let p2 = p.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    p2.bytes_written.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(p.bytes_written.load(Ordering::Relaxed), 8000);
    }
}
