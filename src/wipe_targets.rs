//! Wipe targets — manage prioritized lists of files for secure deletion.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A file marked for wipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeTarget {
    pub id: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub priority: WipePriority,
    pub reason: WipeReason,
    pub state: WipeState,
    pub queued_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub passes: u8,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WipePriority {
    Background,
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipeReason {
    Junk,
    Sensitive,
    Expired,
    Quota,
    UserRequest,
    Compromise,
    DeadMan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipeState {
    Queued,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Wipe target queue.
pub struct WipeQueue {
    targets: HashMap<String, WipeTarget>,
}

impl WipeQueue {
    pub fn new() -> Self {
        Self { targets: HashMap::new() }
    }

    /// Queue a file for wipe.
    pub fn enqueue(&mut self, target: WipeTarget) {
        self.targets.insert(target.id.clone(), target);
    }

    /// Cancel a target.
    pub fn cancel(&mut self, id: &str) -> bool {
        if let Some(t) = self.targets.get_mut(id) {
            if t.state == WipeState::Queued {
                t.state = WipeState::Cancelled;
                return true;
            }
        }
        false
    }

    /// Mark a target as in progress.
    pub fn start(&mut self, id: &str) -> bool {
        if let Some(t) = self.targets.get_mut(id) {
            if t.state == WipeState::Queued {
                t.state = WipeState::InProgress;
                return true;
            }
        }
        false
    }

    /// Mark a target as completed.
    pub fn complete(&mut self, id: &str) -> bool {
        if let Some(t) = self.targets.get_mut(id) {
            t.state = WipeState::Completed;
            t.completed_at = Some(Utc::now());
            return true;
        }
        false
    }

    /// Mark a target as failed.
    pub fn fail(&mut self, id: &str, error: &str) -> bool {
        if let Some(t) = self.targets.get_mut(id) {
            t.state = WipeState::Failed;
            t.error = Some(error.into());
            t.completed_at = Some(Utc::now());
            return true;
        }
        false
    }

    /// Next target to process, ordered by priority.
    pub fn next_queued(&self) -> Option<&WipeTarget> {
        let mut queued: Vec<&WipeTarget> = self.targets.values()
            .filter(|t| t.state == WipeState::Queued)
            .collect();
        queued.sort_by(|a, b| b.priority.cmp(&a.priority));
        queued.into_iter().next()
    }

    /// Targets in a specific state.
    pub fn by_state(&self, state: &WipeState) -> Vec<&WipeTarget> {
        self.targets.values().filter(|t| &t.state == state).collect()
    }

    /// Targets by reason.
    pub fn by_reason(&self, reason: &WipeReason) -> Vec<&WipeTarget> {
        self.targets.values().filter(|t| &t.reason == reason).collect()
    }

    /// Total bytes queued for wipe.
    pub fn total_queued_bytes(&self) -> u64 {
        self.targets.values()
            .filter(|t| t.state == WipeState::Queued)
            .map(|t| t.size_bytes)
            .sum()
    }

    /// Get a target.
    pub fn get(&self, id: &str) -> Option<&WipeTarget> {
        self.targets.get(id)
    }

    /// Total targets.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

impl Default for WipeQueue {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: &str, priority: WipePriority, reason: WipeReason) -> WipeTarget {
        WipeTarget {
            id: id.into(),
            path: PathBuf::from(format!("/files/{}", id)),
            size_bytes: 1024,
            priority,
            reason,
            state: WipeState::Queued,
            queued_at: Utc::now(),
            completed_at: None,
            passes: 3,
            error: None,
        }
    }

    #[test]
    fn test_enqueue() {
        let mut q = WipeQueue::new();
        q.enqueue(target("t1", WipePriority::Normal, WipeReason::Junk));
        assert_eq!(q.target_count(), 1);
    }

    #[test]
    fn test_priority_order() {
        let mut q = WipeQueue::new();
        q.enqueue(target("low", WipePriority::Low, WipeReason::Junk));
        q.enqueue(target("urgent", WipePriority::Urgent, WipeReason::Compromise));
        assert_eq!(q.next_queued().unwrap().id, "urgent");
    }

    #[test]
    fn test_start_and_complete() {
        let mut q = WipeQueue::new();
        q.enqueue(target("t1", WipePriority::Normal, WipeReason::Junk));
        assert!(q.start("t1"));
        assert!(q.complete("t1"));
        assert_eq!(q.get("t1").unwrap().state, WipeState::Completed);
    }

    #[test]
    fn test_fail() {
        let mut q = WipeQueue::new();
        q.enqueue(target("t1", WipePriority::Normal, WipeReason::Junk));
        q.fail("t1", "io error");
        assert_eq!(q.get("t1").unwrap().error.as_deref(), Some("io error"));
    }

    #[test]
    fn test_cancel_queued() {
        let mut q = WipeQueue::new();
        q.enqueue(target("t1", WipePriority::Normal, WipeReason::Junk));
        assert!(q.cancel("t1"));
        assert_eq!(q.get("t1").unwrap().state, WipeState::Cancelled);
    }

    #[test]
    fn test_cannot_cancel_in_progress() {
        let mut q = WipeQueue::new();
        q.enqueue(target("t1", WipePriority::Normal, WipeReason::Junk));
        q.start("t1");
        assert!(!q.cancel("t1"));
    }

    #[test]
    fn test_by_state() {
        let mut q = WipeQueue::new();
        q.enqueue(target("a", WipePriority::Normal, WipeReason::Junk));
        q.enqueue(target("b", WipePriority::Normal, WipeReason::Junk));
        q.start("a");
        assert_eq!(q.by_state(&WipeState::InProgress).len(), 1);
        assert_eq!(q.by_state(&WipeState::Queued).len(), 1);
    }

    #[test]
    fn test_by_reason() {
        let mut q = WipeQueue::new();
        q.enqueue(target("a", WipePriority::Normal, WipeReason::Junk));
        q.enqueue(target("b", WipePriority::Normal, WipeReason::Sensitive));
        assert_eq!(q.by_reason(&WipeReason::Sensitive).len(), 1);
    }

    #[test]
    fn test_total_queued_bytes() {
        let mut q = WipeQueue::new();
        let mut t = target("big", WipePriority::Normal, WipeReason::Junk);
        t.size_bytes = 10_000;
        q.enqueue(t);
        assert_eq!(q.total_queued_bytes(), 10_000);
    }
}
