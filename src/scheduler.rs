//! Cron-like task scheduler — manages named cleanup tasks with configurable
//! intervals, tracks execution results, and provides a text status dashboard.
//!
//! Unlike [`crate::daemon`] which is a fixed four-task state machine, the
//! scheduler is fully dynamic: callers can add, remove, enable, and disable
//! arbitrary named tasks at runtime.

use chrono::{DateTime, Duration, Utc};
use std::fmt;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Top-level scheduler that owns a dynamic set of [`ScheduledTask`] entries.
pub struct TaskScheduler {
    tasks: Vec<ScheduledTask>,
}

/// A single scheduled cleanup task with interval tracking and result history.
pub struct ScheduledTask {
    /// Human-readable name (must be unique within the scheduler).
    pub name: String,
    /// What kind of cleanup this task performs.
    pub action: CleanupAction,
    /// How often to run (in hours).
    pub interval_hours: u32,
    /// When this task last ran, if ever.
    pub last_run: Option<DateTime<Utc>>,
    /// Whether the task is eligible to run.
    pub enabled: bool,
    /// Result of the most recent execution, if any.
    pub last_result: Option<TaskResult>,
}

/// Categories of cleanup work the scheduler can dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CleanupAction {
    BrowserClean,
    SystemClean,
    DuplicateScan,
    PrivacyAudit,
    MetadataStrip,
    TempClean,
}

impl fmt::Display for CleanupAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BrowserClean => write!(f, "Browser Clean"),
            Self::SystemClean => write!(f, "System Clean"),
            Self::DuplicateScan => write!(f, "Duplicate Scan"),
            Self::PrivacyAudit => write!(f, "Privacy Audit"),
            Self::MetadataStrip => write!(f, "Metadata Strip"),
            Self::TempClean => write!(f, "Temp Clean"),
        }
    }
}

/// Outcome of executing a single task.
#[derive(Debug, Clone)]
pub struct TaskResult {
    pub success: bool,
    pub files_cleaned: u64,
    pub bytes_freed: u64,
    pub duration_ms: u64,
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl TaskScheduler {
    /// Create an empty scheduler with no tasks.
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    // -- task management ---------------------------------------------------

    /// Add a new enabled task.  Returns `false` if a task with the same name
    /// already exists (the duplicate is **not** inserted).
    pub fn add_task(&mut self, name: &str, action: CleanupAction, interval_hours: u32) -> bool {
        if self.tasks.iter().any(|t| t.name == name) {
            return false;
        }
        self.tasks.push(ScheduledTask {
            name: name.to_string(),
            action,
            interval_hours,
            last_run: None,
            enabled: true,
            last_result: None,
        });
        true
    }

    /// Remove a task by name.  Returns `true` if the task existed.
    pub fn remove_task(&mut self, name: &str) -> bool {
        let before = self.tasks.len();
        self.tasks.retain(|t| t.name != name);
        self.tasks.len() < before
    }

    /// Enable a task by name.  Returns `true` if the task was found.
    pub fn enable_task(&mut self, name: &str) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.name == name) {
            task.enabled = true;
            true
        } else {
            false
        }
    }

    /// Disable a task by name.  Returns `true` if the task was found.
    pub fn disable_task(&mut self, name: &str) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.name == name) {
            task.enabled = false;
            true
        } else {
            false
        }
    }

    // -- scheduling --------------------------------------------------------

    /// Return every enabled task whose interval has elapsed since its last
    /// run.  Tasks that have never run are always considered due.
    pub fn due_tasks(&self, now: DateTime<Utc>) -> Vec<&ScheduledTask> {
        self.tasks
            .iter()
            .filter(|t| t.enabled && self.is_due(t, now))
            .collect()
    }

    /// Execute the most overdue enabled task by calling the provided closure,
    /// then record the result.  Returns a reference to the result, or `None`
    /// if no task is due.
    ///
    /// The closure receives the task's [`CleanupAction`] and must return a
    /// [`TaskResult`].
    pub fn run_next<F>(&mut self, now: DateTime<Utc>, executor: F) -> Option<&TaskResult>
    where
        F: FnOnce(CleanupAction) -> TaskResult,
    {
        // Find the index of the most overdue enabled task.
        let idx = self.most_overdue_index(now)?;

        let action = self.tasks[idx].action;
        let result = executor(action);

        self.tasks[idx].last_run = Some(now);
        self.tasks[idx].last_result = Some(result);

        self.tasks[idx].last_result.as_ref()
    }

    // -- queries -----------------------------------------------------------

    /// Read-only view of all tasks.
    pub fn tasks(&self) -> &[ScheduledTask] {
        &self.tasks
    }

    /// Collect the most recent [`TaskResult`] from every task that has one,
    /// ordered by task insertion order.
    pub fn task_history(&self) -> Vec<(&str, &TaskResult)> {
        self.tasks
            .iter()
            .filter_map(|t| t.last_result.as_ref().map(|r| (t.name.as_str(), r)))
            .collect()
    }

    // -- rendering ---------------------------------------------------------

    /// Produce a human-readable text dashboard showing each task's status,
    /// last result, and overall statistics.
    pub fn render_status(&self, now: DateTime<Utc>) -> String {
        let mut out = String::new();
        out.push_str("=== PlausiDen Purge Scheduler ===\n\n");

        if self.tasks.is_empty() {
            out.push_str("  (no tasks configured)\n");
            return out;
        }

        for task in &self.tasks {
            let enabled_tag = if task.enabled { "ON " } else { "OFF" };
            let status = match task.last_run {
                Some(ts) => {
                    let deadline = ts + Duration::hours(i64::from(task.interval_hours));
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

            out.push_str(&format!(
                "  [{enabled_tag}] {:<20} {:<14} [{status}]\n",
                task.name, task.action,
            ));

            if let Some(ref result) = task.last_result {
                let ok = if result.success { "OK" } else { "FAIL" };
                out.push_str(&format!(
                    "         last: {ok} | {} files | {} freed | {} ms",
                    result.files_cleaned,
                    format_bytes(result.bytes_freed),
                    result.duration_ms,
                ));
                if !result.errors.is_empty() {
                    out.push_str(&format!(" | {} error(s)", result.errors.len()));
                }
                out.push('\n');
            }
        }

        // Summary line.
        let total_freed: u64 = self
            .tasks
            .iter()
            .filter_map(|t| t.last_result.as_ref())
            .map(|r| r.bytes_freed)
            .sum();
        let total_files: u64 = self
            .tasks
            .iter()
            .filter_map(|t| t.last_result.as_ref())
            .map(|r| r.files_cleaned)
            .sum();
        let active = self.tasks.iter().filter(|t| t.enabled).count();
        let due_count = self.due_tasks(now).len();

        out.push_str(&format!(
            "\nTasks: {} total, {} active, {} due | Lifetime: {} files, {} freed\n",
            self.tasks.len(),
            active,
            due_count,
            total_files,
            format_bytes(total_freed),
        ));

        out
    }

    // -- internal helpers --------------------------------------------------

    fn is_due(&self, task: &ScheduledTask, now: DateTime<Utc>) -> bool {
        match task.last_run {
            Some(ts) => now >= ts + Duration::hours(i64::from(task.interval_hours)),
            None => true, // Never run => immediately due.
        }
    }

    fn most_overdue_index(&self, now: DateTime<Utc>) -> Option<usize> {
        self.tasks
            .iter()
            .enumerate()
            .filter(|(_, t)| t.enabled && self.is_due(t, now))
            .min_by_key(|(_, t)| {
                // Deadline: smaller means more overdue.
                match t.last_run {
                    Some(ts) => ts + Duration::hours(i64::from(t.interval_hours)),
                    None => DateTime::<Utc>::from(std::time::UNIX_EPOCH),
                }
            })
            .map(|(i, _)| i)
        }
}

impl Default for TaskScheduler {
    fn default() -> Self {
        Self::new()
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

    /// Fixed reference time shared across tests.
    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 5, 12, 0, 0).unwrap()
    }

    fn sample_result(success: bool, files: u64, bytes: u64) -> TaskResult {
        TaskResult {
            success,
            files_cleaned: files,
            bytes_freed: bytes,
            duration_ms: 42,
            errors: Vec::new(),
        }
    }

    // -- test: add_task and duplicate rejection --------------------------------
    #[test]
    fn test_add_task_and_reject_duplicate() {
        let mut sched = TaskScheduler::new();
        assert!(sched.add_task("browsers", CleanupAction::BrowserClean, 24));
        assert!(!sched.add_task("browsers", CleanupAction::SystemClean, 48),
            "Duplicate name should be rejected");
        assert_eq!(sched.tasks().len(), 1);
        assert_eq!(sched.tasks()[0].action, CleanupAction::BrowserClean,
            "Original action should be unchanged");
    }

    // -- test: remove_task removes the correct entry --------------------------
    #[test]
    fn test_remove_task() {
        let mut sched = TaskScheduler::new();
        sched.add_task("a", CleanupAction::BrowserClean, 1);
        sched.add_task("b", CleanupAction::SystemClean, 2);
        sched.add_task("c", CleanupAction::TempClean, 3);

        assert!(sched.remove_task("b"));
        assert!(!sched.remove_task("b"), "Second remove should return false");

        let names: Vec<&str> = sched.tasks().iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["a", "c"]);
    }

    // -- test: due_tasks returns only enabled overdue tasks --------------------
    #[test]
    fn test_due_tasks_filtering() {
        let mut sched = TaskScheduler::new();
        sched.add_task("hourly", CleanupAction::TempClean, 1);
        sched.add_task("daily", CleanupAction::BrowserClean, 24);
        sched.add_task("disabled", CleanupAction::PrivacyAudit, 1);
        sched.disable_task("disabled");

        let now = t0();

        // All never-run tasks should be due (except disabled).
        let due = sched.due_tasks(now);
        assert_eq!(due.len(), 2, "Only enabled never-run tasks should be due");

        // Simulate running hourly.
        sched.tasks[0].last_run = Some(now);
        // 30 min later: hourly not yet due, daily still due.
        let due_30m = sched.due_tasks(now + Duration::minutes(30));
        assert_eq!(due_30m.len(), 1);
        assert_eq!(due_30m[0].name, "daily");

        // 90 min later: hourly overdue again.
        let due_90m = sched.due_tasks(now + Duration::minutes(90));
        assert_eq!(due_90m.len(), 2);
    }

    // -- test: run_next executes the most overdue task ------------------------
    #[test]
    fn test_run_next_picks_most_overdue() {
        let mut sched = TaskScheduler::new();
        let now = t0();

        // "old" ran 10 hours ago with a 1-hour interval => 9 hours overdue.
        sched.add_task("old", CleanupAction::DuplicateScan, 1);
        sched.tasks[0].last_run = Some(now - Duration::hours(10));

        // "recent" ran 3 hours ago with a 1-hour interval => 2 hours overdue.
        sched.add_task("recent", CleanupAction::MetadataStrip, 1);
        sched.tasks[1].last_run = Some(now - Duration::hours(3));

        let result = sched.run_next(now, |action| {
            assert_eq!(action, CleanupAction::DuplicateScan,
                "Should pick the most overdue task");
            sample_result(true, 50, 1_048_576)
        });

        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.success);
        assert_eq!(r.files_cleaned, 50);
        assert_eq!(sched.tasks[0].last_run, Some(now));
    }

    // -- test: enable/disable toggles and affects scheduling ------------------
    #[test]
    fn test_enable_disable_task() {
        let mut sched = TaskScheduler::new();
        sched.add_task("audit", CleanupAction::PrivacyAudit, 12);

        assert!(sched.tasks()[0].enabled);
        assert!(sched.disable_task("audit"));
        assert!(!sched.tasks()[0].enabled);

        // Disabled tasks are not due.
        assert!(sched.due_tasks(t0()).is_empty());

        assert!(sched.enable_task("audit"));
        assert!(sched.tasks()[0].enabled);
        assert_eq!(sched.due_tasks(t0()).len(), 1);

        // Non-existent task returns false.
        assert!(!sched.enable_task("ghost"));
        assert!(!sched.disable_task("ghost"));
    }

    // -- test: task_history collects last results -----------------------------
    #[test]
    fn test_task_history() {
        let mut sched = TaskScheduler::new();
        let now = t0();

        sched.add_task("a", CleanupAction::BrowserClean, 1);
        sched.add_task("b", CleanupAction::SystemClean, 1);
        sched.add_task("c", CleanupAction::TempClean, 1);

        // Run "a" and "b" (both never-run, "a" is most overdue by insertion).
        sched.run_next(now, |_| sample_result(true, 10, 500));
        sched.run_next(now, |_| sample_result(false, 0, 0));

        let history = sched.task_history();
        assert_eq!(history.len(), 2, "Only tasks with results should appear");
        assert_eq!(history[0].0, "a");
        assert!(history[0].1.success);
        assert_eq!(history[1].0, "b");
        assert!(!history[1].1.success);
    }

    // -- test: render_status produces a meaningful dashboard -------------------
    #[test]
    fn test_render_status_content() {
        let mut sched = TaskScheduler::new();
        let now = t0();

        sched.add_task("browser-clean", CleanupAction::BrowserClean, 24);
        sched.add_task("temp-clean", CleanupAction::TempClean, 6);
        sched.disable_task("temp-clean");

        // Run browser-clean.
        sched.run_next(now, |_| TaskResult {
            success: true,
            files_cleaned: 142,
            bytes_freed: 2_097_152,
            duration_ms: 350,
            errors: Vec::new(),
        });

        let status = sched.render_status(now + Duration::hours(1));

        assert!(status.contains("PlausiDen Purge Scheduler"), "Should have header");
        assert!(status.contains("browser-clean"), "Should list task name");
        assert!(status.contains("Browser Clean"), "Should show action type");
        assert!(status.contains("next in"), "Should show time remaining");
        assert!(status.contains("OFF"), "Should show disabled tag");
        assert!(status.contains("142 files"), "Should show files cleaned");
        assert!(status.contains("2.0 MiB"), "Should show bytes freed");
        assert!(status.contains("1 active"), "Should show active count");
        // browser-clean just ran (23h left), temp-clean is disabled => 0 due.
        assert!(status.contains("0 due"), "Should show due count");
    }

    // -- test: run_next returns None when nothing is due ----------------------
    #[test]
    fn test_run_next_none_when_no_due() {
        let mut sched = TaskScheduler::new();
        let now = t0();

        sched.add_task("x", CleanupAction::SystemClean, 24);
        sched.tasks[0].last_run = Some(now); // Just ran.

        let result = sched.run_next(now + Duration::hours(1), |_| {
            panic!("Executor should not be called");
        });
        assert!(result.is_none());
    }
}
