//! Cron manager — schedule periodic purge tasks.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A scheduled purge task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeTask {
    pub name: String,
    pub task_type: TaskType,
    pub schedule: Schedule,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: DateTime<Utc>,
    pub enabled: bool,
    pub run_count: u64,
}

/// Type of purge task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskType {
    ClearTempFiles,
    ClearBrowserCache,
    ClearShellHistory,
    ClearLogs,
    ClearThumbnails,
    ClearTrash,
    WipeFreeSpace,
    StripMetadata,
    Custom { script: String },
}

/// Task schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Schedule {
    Daily { hour: u32 },
    Hourly,
    Interval { minutes: u32 },
    OnLogin,
    OnLogout,
    OnIdle { idle_secs: u32 },
}

/// Cron manager.
pub struct CronManager {
    tasks: HashMap<String, PurgeTask>,
}

impl CronManager {
    pub fn new() -> Self {
        Self { tasks: HashMap::new() }
    }

    /// Add a task.
    pub fn add(&mut self, task: PurgeTask) {
        self.tasks.insert(task.name.clone(), task);
    }

    /// Remove a task.
    pub fn remove(&mut self, name: &str) -> bool {
        self.tasks.remove(name).is_some()
    }

    /// Get tasks due to run now.
    pub fn due_tasks(&self) -> Vec<&PurgeTask> {
        let now = Utc::now();
        self.tasks.values()
            .filter(|t| t.enabled && t.next_run <= now)
            .collect()
    }

    /// Mark a task as completed and reschedule.
    pub fn mark_completed(&mut self, name: &str) {
        if let Some(task) = self.tasks.get_mut(name) {
            task.last_run = Some(Utc::now());
            task.run_count += 1;
            task.next_run = Self::calculate_next_run(&task.schedule);
        }
    }

    fn calculate_next_run(schedule: &Schedule) -> DateTime<Utc> {
        let now = Utc::now();
        match schedule {
            Schedule::Daily { hour } => {
                let mut next = now.date_naive().and_hms_opt(*hour, 0, 0).unwrap_or_default()
                    .and_utc();
                if next <= now {
                    next += Duration::days(1);
                }
                next
            }
            Schedule::Hourly => now + Duration::hours(1),
            Schedule::Interval { minutes } => now + Duration::minutes(*minutes as i64),
            Schedule::OnLogin | Schedule::OnLogout => now + Duration::days(365), // Triggered externally.
            Schedule::OnIdle { .. } => now + Duration::hours(1), // Check periodically.
        }
    }

    /// Enable/disable a task.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(task) = self.tasks.get_mut(name) {
            task.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Get all tasks.
    pub fn all_tasks(&self) -> Vec<&PurgeTask> {
        self.tasks.values().collect()
    }

    /// Get task by name.
    pub fn get(&self, name: &str) -> Option<&PurgeTask> {
        self.tasks.get(name)
    }

    /// Create default daily cleanup task.
    pub fn default_daily_tasks(&mut self) {
        let now = Utc::now();
        let tasks = vec![
            (TaskType::ClearTempFiles, "daily-temp-clear", 3),
            (TaskType::ClearThumbnails, "daily-thumbnail-clear", 4),
            (TaskType::ClearTrash, "daily-trash-clear", 4),
        ];
        for (task_type, name, hour) in tasks {
            self.add(PurgeTask {
                name: name.into(),
                task_type,
                schedule: Schedule::Daily { hour },
                last_run: None,
                next_run: now,
                enabled: true,
                run_count: 0,
            });
        }
    }

    pub fn task_count(&self) -> usize { self.tasks.len() }
}

impl Default for CronManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task(name: &str) -> PurgeTask {
        PurgeTask {
            name: name.into(),
            task_type: TaskType::ClearTempFiles,
            schedule: Schedule::Hourly,
            last_run: None,
            next_run: Utc::now(),
            enabled: true,
            run_count: 0,
        }
    }

    #[test]
    fn test_add_task() {
        let mut cron = CronManager::new();
        cron.add(make_task("test"));
        assert_eq!(cron.task_count(), 1);
    }

    #[test]
    fn test_due_tasks() {
        let mut cron = CronManager::new();
        cron.add(make_task("test"));
        assert_eq!(cron.due_tasks().len(), 1);
    }

    #[test]
    fn test_mark_completed() {
        let mut cron = CronManager::new();
        cron.add(make_task("test"));
        cron.mark_completed("test");
        let task = cron.get("test").unwrap();
        assert_eq!(task.run_count, 1);
        // Next run should be scheduled in the future.
        assert!(task.next_run > Utc::now());
    }

    #[test]
    fn test_disabled_task_not_due() {
        let mut cron = CronManager::new();
        cron.add(make_task("test"));
        cron.set_enabled("test", false);
        assert!(cron.due_tasks().is_empty());
    }

    #[test]
    fn test_remove() {
        let mut cron = CronManager::new();
        cron.add(make_task("test"));
        assert!(cron.remove("test"));
        assert_eq!(cron.task_count(), 0);
    }

    #[test]
    fn test_default_daily_tasks() {
        let mut cron = CronManager::new();
        cron.default_daily_tasks();
        assert!(cron.task_count() >= 3);
    }

    #[test]
    fn test_interval_schedule() {
        let mut task = make_task("test");
        task.schedule = Schedule::Interval { minutes: 30 };
        let next = CronManager::calculate_next_run(&task.schedule);
        let diff = (next - Utc::now()).num_minutes();
        assert!(diff >= 29 && diff <= 31);
    }
}
