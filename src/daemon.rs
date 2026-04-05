//! Scheduled cleanup daemon — runs browser, system, dedup, and privacy
//! tasks on configurable intervals and tracks results over time.
//!
//! The daemon itself is a pure state machine: callers decide *when* to tick
//! (via `next_action_due` / `overdue_actions`), so the struct is easy to
//! test without sleeping or spawning threads.

use chrono::{DateTime, Duration, Utc};
use std::fmt;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Categories of cleanup work the daemon can schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionKind {
    BrowserClean,
    SystemClean,
    DedupScan,
    PrivacyAudit,
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BrowserClean => write!(f, "Browser Clean"),
            Self::SystemClean => write!(f, "System Clean"),
            Self::DedupScan => write!(f, "Dedup Scan"),
            Self::PrivacyAudit => write!(f, "Privacy Audit"),
        }
    }
}

/// A completed cleanup action recorded in the daemon history.
#[derive(Debug, Clone)]
pub struct DaemonAction {
    pub kind: ActionKind,
    pub started_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub space_freed_bytes: u64,
}

/// Interval configuration for each task category.
pub struct DaemonConfig {
    pub browser_clean_interval_hours: u32,
    pub system_clean_interval_hours: u32,
    pub dedup_scan_interval_hours: u32,
    pub privacy_audit_interval_hours: u32,
    pub max_history: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            browser_clean_interval_hours: 24,
            system_clean_interval_hours: 72,
            dedup_scan_interval_hours: 168, // weekly
            privacy_audit_interval_hours: 168,
            max_history: 1000,
        }
    }
}

/// Background service state — tracks when each task last ran and keeps a
/// bounded history of completed actions.
pub struct PurgeDaemon {
    config: DaemonConfig,
    last_browser_clean: Option<DateTime<Utc>>,
    last_system_clean: Option<DateTime<Utc>>,
    last_dedup_scan: Option<DateTime<Utc>>,
    last_privacy_audit: Option<DateTime<Utc>>,
    history: Vec<DaemonAction>,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl PurgeDaemon {
    /// Create a new daemon with the given configuration.  All "last run"
    /// timestamps start as `None`, meaning every task is immediately due.
    pub fn new(config: DaemonConfig) -> Self {
        Self {
            config,
            last_browser_clean: None,
            last_system_clean: None,
            last_dedup_scan: None,
            last_privacy_audit: None,
            history: Vec::new(),
        }
    }

    /// Create a daemon with default intervals.
    pub fn with_defaults() -> Self {
        Self::new(DaemonConfig::default())
    }

    // -- scheduling --------------------------------------------------------

    /// Determine which action should run next (the one whose deadline is
    /// earliest).  Returns `None` only if the config has zero-hour intervals
    /// for every task, which is degenerate and not expected in practice.
    pub fn next_action_due(&self, _now: DateTime<Utc>) -> Option<(ActionKind, DateTime<Utc>)> {
        let candidates = [
            (ActionKind::BrowserClean, self.deadline(self.last_browser_clean, self.config.browser_clean_interval_hours)),
            (ActionKind::SystemClean, self.deadline(self.last_system_clean, self.config.system_clean_interval_hours)),
            (ActionKind::DedupScan, self.deadline(self.last_dedup_scan, self.config.dedup_scan_interval_hours)),
            (ActionKind::PrivacyAudit, self.deadline(self.last_privacy_audit, self.config.privacy_audit_interval_hours)),
        ];

        candidates
            .into_iter()
            .min_by_key(|(_, deadline)| *deadline)
    }

    /// Return every action whose deadline has already passed.
    pub fn overdue_actions(&self, now: DateTime<Utc>) -> Vec<ActionKind> {
        let mut overdue = Vec::new();
        if self.is_overdue(self.last_browser_clean, self.config.browser_clean_interval_hours, now) {
            overdue.push(ActionKind::BrowserClean);
        }
        if self.is_overdue(self.last_system_clean, self.config.system_clean_interval_hours, now) {
            overdue.push(ActionKind::SystemClean);
        }
        if self.is_overdue(self.last_dedup_scan, self.config.dedup_scan_interval_hours, now) {
            overdue.push(ActionKind::DedupScan);
        }
        if self.is_overdue(self.last_privacy_audit, self.config.privacy_audit_interval_hours, now) {
            overdue.push(ActionKind::PrivacyAudit);
        }
        overdue
    }

    // -- recording ---------------------------------------------------------

    /// Record a completed action.  Updates the "last run" timestamp and
    /// appends to the history ring, evicting the oldest entry if the
    /// configured maximum is reached.
    pub fn record_action(&mut self, kind: ActionKind, duration_ms: u64, space_freed_bytes: u64) {
        let action = DaemonAction {
            kind,
            started_at: Utc::now(),
            duration_ms,
            space_freed_bytes,
        };

        match kind {
            ActionKind::BrowserClean => self.last_browser_clean = Some(action.started_at),
            ActionKind::SystemClean => self.last_system_clean = Some(action.started_at),
            ActionKind::DedupScan => self.last_dedup_scan = Some(action.started_at),
            ActionKind::PrivacyAudit => self.last_privacy_audit = Some(action.started_at),
        }

        self.history.push(action);

        // Evict oldest entries when over capacity.
        if self.history.len() > self.config.max_history {
            let excess = self.history.len() - self.config.max_history;
            self.history.drain(..excess);
        }
    }

    // -- queries -----------------------------------------------------------

    /// Cumulative space freed across all recorded actions.
    pub fn total_space_freed(&self) -> u64 {
        self.history.iter().map(|a| a.space_freed_bytes).sum()
    }

    /// Read-only view of the action history (oldest first).
    pub fn history(&self) -> &[DaemonAction] {
        &self.history
    }

    // -- rendering ---------------------------------------------------------

    /// Produce a human-readable status dashboard.
    pub fn render_status(&self, now: DateTime<Utc>) -> String {
        let mut out = String::new();
        out.push_str("=== PlausiDen Purge Daemon ===\n\n");

        // Per-task status
        let tasks = [
            ("Browser Clean", self.last_browser_clean, self.config.browser_clean_interval_hours),
            ("System Clean", self.last_system_clean, self.config.system_clean_interval_hours),
            ("Dedup Scan", self.last_dedup_scan, self.config.dedup_scan_interval_hours),
            ("Privacy Audit", self.last_privacy_audit, self.config.privacy_audit_interval_hours),
        ];

        for (label, last, interval_h) in &tasks {
            let status = match last {
                Some(ts) => {
                    let deadline = *ts + Duration::hours(i64::from(*interval_h));
                    if now >= deadline {
                        "OVERDUE".to_string()
                    } else {
                        let remaining = deadline - now;
                        let hours = remaining.num_hours();
                        let mins = remaining.num_minutes() % 60;
                        format!("next in {hours}h {mins}m")
                    }
                }
                None => "never run".to_string(),
            };
            out.push_str(&format!("  {label:<16} [{status}]\n"));
        }

        // Summary
        out.push_str(&format!(
            "\nHistory: {} actions | Total freed: {}\n",
            self.history.len(),
            format_bytes(self.total_space_freed()),
        ));

        // Last 5 actions
        if !self.history.is_empty() {
            out.push_str("\nRecent actions:\n");
            let start = self.history.len().saturating_sub(5);
            for action in &self.history[start..] {
                out.push_str(&format!(
                    "  {} — {} ({} ms, freed {})\n",
                    action.started_at.format("%Y-%m-%d %H:%M"),
                    action.kind,
                    action.duration_ms,
                    format_bytes(action.space_freed_bytes),
                ));
            }
        }

        out
    }

    // -- internal helpers --------------------------------------------------

    fn deadline(&self, last: Option<DateTime<Utc>>, interval_hours: u32) -> DateTime<Utc> {
        match last {
            Some(ts) => ts + Duration::hours(i64::from(interval_hours)),
            // Never run => deadline was epoch (i.e. overdue since forever).
            None => DateTime::<Utc>::from(std::time::UNIX_EPOCH),
        }
    }

    fn is_overdue(&self, last: Option<DateTime<Utc>>, interval_hours: u32, now: DateTime<Utc>) -> bool {
        now >= self.deadline(last, interval_hours)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GiB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Fixed reference time used across most tests.
    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 5, 12, 0, 0).unwrap()
    }

    // -- test: fresh daemon reports all tasks overdue -----------------------
    #[test]
    fn test_fresh_daemon_all_overdue() {
        let daemon = PurgeDaemon::with_defaults();
        let overdue = daemon.overdue_actions(t0());
        assert_eq!(overdue.len(), 4, "All four tasks should be overdue on a fresh daemon");
        assert!(overdue.contains(&ActionKind::BrowserClean));
        assert!(overdue.contains(&ActionKind::SystemClean));
        assert!(overdue.contains(&ActionKind::DedupScan));
        assert!(overdue.contains(&ActionKind::PrivacyAudit));
    }

    // -- test: recording clears overdue status for that task ---------------
    #[test]
    fn test_record_clears_overdue() {
        let mut daemon = PurgeDaemon::with_defaults();
        daemon.record_action(ActionKind::BrowserClean, 150, 1_048_576);

        let overdue = daemon.overdue_actions(Utc::now());
        assert!(
            !overdue.contains(&ActionKind::BrowserClean),
            "BrowserClean should no longer be overdue after recording"
        );
        // The other three are still overdue.
        assert_eq!(overdue.len(), 3);
    }

    // -- test: next_action_due picks the earliest deadline -----------------
    #[test]
    fn test_next_action_due_picks_earliest() {
        let config = DaemonConfig {
            browser_clean_interval_hours: 1,
            system_clean_interval_hours: 100,
            dedup_scan_interval_hours: 100,
            privacy_audit_interval_hours: 100,
            max_history: 100,
        };
        let mut daemon = PurgeDaemon::new(config);

        // Record all four so none start at epoch.
        let base = t0();
        daemon.last_browser_clean = Some(base);
        daemon.last_system_clean = Some(base);
        daemon.last_dedup_scan = Some(base);
        daemon.last_privacy_audit = Some(base);

        let (kind, _deadline) = daemon
            .next_action_due(base + Duration::hours(2))
            .expect("should return an action");
        assert_eq!(kind, ActionKind::BrowserClean, "Browser has the shortest interval");
    }

    // -- test: total_space_freed accumulates across actions ----------------
    #[test]
    fn test_total_space_freed() {
        let mut daemon = PurgeDaemon::with_defaults();
        daemon.record_action(ActionKind::BrowserClean, 100, 500_000);
        daemon.record_action(ActionKind::SystemClean, 200, 1_500_000);
        daemon.record_action(ActionKind::DedupScan, 300, 3_000_000);

        assert_eq!(daemon.total_space_freed(), 5_000_000);
    }

    // -- test: history eviction respects max_history -----------------------
    #[test]
    fn test_history_eviction() {
        let config = DaemonConfig {
            max_history: 3,
            ..DaemonConfig::default()
        };
        let mut daemon = PurgeDaemon::new(config);

        daemon.record_action(ActionKind::BrowserClean, 10, 100);
        daemon.record_action(ActionKind::SystemClean, 20, 200);
        daemon.record_action(ActionKind::DedupScan, 30, 300);
        daemon.record_action(ActionKind::PrivacyAudit, 40, 400);

        assert_eq!(daemon.history().len(), 3, "Should cap at max_history=3");
        // Oldest (BrowserClean) should have been evicted.
        assert_eq!(daemon.history()[0].kind, ActionKind::SystemClean);
    }

    // -- test: render_status includes key information ----------------------
    #[test]
    fn test_render_status_content() {
        let mut daemon = PurgeDaemon::with_defaults();
        daemon.record_action(ActionKind::BrowserClean, 120, 2_097_152);

        let now = Utc::now() + Duration::minutes(5);
        let status = daemon.render_status(now);

        assert!(status.contains("PlausiDen Purge Daemon"), "Should have header");
        assert!(status.contains("Browser Clean"), "Should list browser task");
        assert!(status.contains("never run") || status.contains("OVERDUE") || status.contains("next in"),
            "Should have status labels");
        assert!(status.contains("1 actions"), "Should show action count");
        assert!(status.contains("2.0 MiB"), "Should show freed space");
    }

    // -- test: overdue_actions detects interval expiry ---------------------
    #[test]
    fn test_overdue_after_interval_expires() {
        let config = DaemonConfig {
            browser_clean_interval_hours: 2,
            system_clean_interval_hours: 200,
            dedup_scan_interval_hours: 200,
            privacy_audit_interval_hours: 200,
            max_history: 100,
        };
        let mut daemon = PurgeDaemon::new(config);

        let base = t0();
        daemon.last_browser_clean = Some(base);
        daemon.last_system_clean = Some(base);
        daemon.last_dedup_scan = Some(base);
        daemon.last_privacy_audit = Some(base);

        // 1 hour later: not yet overdue
        let overdue_1h = daemon.overdue_actions(base + Duration::hours(1));
        assert!(!overdue_1h.contains(&ActionKind::BrowserClean));

        // 3 hours later: overdue
        let overdue_3h = daemon.overdue_actions(base + Duration::hours(3));
        assert!(overdue_3h.contains(&ActionKind::BrowserClean));
        // System/dedup/privacy still have 200h, so not overdue
        assert_eq!(overdue_3h.len(), 1);
    }
}
