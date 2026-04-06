//! Backup rotation — Grandfather-Father-Son retention for backup files.

use chrono::{DateTime, Datelike, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A backup file on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    pub path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub tier: BackupTier,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupTier {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

/// Retention counts per tier (GFS: Grandfather-Father-Son).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GfsPolicy {
    pub daily: usize,
    pub weekly: usize,
    pub monthly: usize,
    pub yearly: usize,
}

impl Default for GfsPolicy {
    fn default() -> Self {
        Self {
            daily: 7,
            weekly: 4,
            monthly: 12,
            yearly: 5,
        }
    }
}

/// Rotation plan — which backups to keep and which to delete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPlan {
    pub keep: Vec<PathBuf>,
    pub delete: Vec<PathBuf>,
    pub promote: Vec<(PathBuf, BackupTier)>,
}

/// Backup rotator.
pub struct BackupRotator {
    policy: GfsPolicy,
}

impl BackupRotator {
    pub fn new(policy: GfsPolicy) -> Self {
        Self { policy }
    }

    /// Promote a backup to the highest matching tier. The first daily of
    /// a week becomes weekly, the first weekly of a month becomes monthly,
    /// and the first monthly of a year becomes yearly.
    pub fn classify(&self, backup: &Backup, all: &[Backup]) -> BackupTier {
        let created = backup.created_at;

        // Is this the first backup of its year in the list?
        let is_first_in_year = all.iter()
            .filter(|b| b.created_at.year() == created.year())
            .min_by_key(|b| b.created_at)
            .map(|b| b.path == backup.path)
            .unwrap_or(false);

        // Is this the first backup of its month?
        let is_first_in_month = all.iter()
            .filter(|b| b.created_at.year() == created.year()
                && b.created_at.month() == created.month())
            .min_by_key(|b| b.created_at)
            .map(|b| b.path == backup.path)
            .unwrap_or(false);

        // Is this the first backup of its ISO week?
        let iso_week = created.iso_week();
        let is_first_in_week = all.iter()
            .filter(|b| {
                let iw = b.created_at.iso_week();
                iw.year() == iso_week.year() && iw.week() == iso_week.week()
            })
            .min_by_key(|b| b.created_at)
            .map(|b| b.path == backup.path)
            .unwrap_or(false);

        if is_first_in_year {
            BackupTier::Yearly
        } else if is_first_in_month {
            BackupTier::Monthly
        } else if is_first_in_week {
            BackupTier::Weekly
        } else {
            BackupTier::Daily
        }
    }

    /// Build a rotation plan for the given set of backups.
    pub fn plan(&self, backups: &[Backup]) -> RotationPlan {
        // Classify each backup.
        let classified: Vec<(Backup, BackupTier)> = backups.iter()
            .map(|b| {
                let tier = self.classify(b, backups);
                let mut b = b.clone();
                b.tier = tier.clone();
                (b, tier)
            })
            .collect();

        // Sort newest first per tier, keep the first N.
        let mut keep_paths = Vec::new();
        let mut promote = Vec::new();

        for tier in &[BackupTier::Yearly, BackupTier::Monthly, BackupTier::Weekly, BackupTier::Daily] {
            let limit = match tier {
                BackupTier::Yearly => self.policy.yearly,
                BackupTier::Monthly => self.policy.monthly,
                BackupTier::Weekly => self.policy.weekly,
                BackupTier::Daily => self.policy.daily,
            };
            let mut in_tier: Vec<&(Backup, BackupTier)> = classified.iter()
                .filter(|(_, t)| t == tier)
                .collect();
            in_tier.sort_by(|a, b| b.0.created_at.cmp(&a.0.created_at));
            for (b, t) in in_tier.iter().take(limit) {
                keep_paths.push(b.path.clone());
                if *t != BackupTier::Daily {
                    promote.push((b.path.clone(), t.clone()));
                }
            }
        }

        let delete: Vec<PathBuf> = backups.iter()
            .filter(|b| !keep_paths.contains(&b.path))
            .map(|b| b.path.clone())
            .collect();

        RotationPlan {
            keep: keep_paths,
            delete,
            promote,
        }
    }
}

/// How many days until this weekday from the given date.
pub fn days_until(target: Weekday, from: DateTime<Utc>) -> u32 {
    let current = from.weekday();
    let diff = (target.num_days_from_monday() + 7 - current.num_days_from_monday()) % 7;
    if diff == 0 { 7 } else { diff }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn backup(path: &str, year: i32, month: u32, day: u32) -> Backup {
        Backup {
            path: PathBuf::from(path),
            created_at: Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap(),
            size_bytes: 1024,
            tier: BackupTier::Daily,
        }
    }

    #[test]
    fn test_default_policy() {
        let p = GfsPolicy::default();
        assert_eq!(p.daily, 7);
        assert_eq!(p.weekly, 4);
        assert_eq!(p.monthly, 12);
        assert_eq!(p.yearly, 5);
    }

    #[test]
    fn test_first_of_year_is_yearly() {
        let backups = vec![
            backup("a", 2025, 1, 1),
            backup("b", 2025, 1, 2),
            backup("c", 2025, 2, 1),
        ];
        let r = BackupRotator::new(GfsPolicy::default());
        assert_eq!(r.classify(&backups[0], &backups), BackupTier::Yearly);
    }

    #[test]
    fn test_first_of_month_is_monthly() {
        let backups = vec![
            backup("a", 2025, 1, 1),
            backup("b", 2025, 2, 1),
            backup("c", 2025, 2, 15),
        ];
        let r = BackupRotator::new(GfsPolicy::default());
        assert_eq!(r.classify(&backups[1], &backups), BackupTier::Monthly);
    }

    #[test]
    fn test_plan_keeps_recent() {
        let backups = vec![
            backup("jan", 2025, 1, 10),
            backup("feb", 2025, 2, 10),
            backup("mar", 2025, 3, 10),
        ];
        let r = BackupRotator::new(GfsPolicy::default());
        let plan = r.plan(&backups);
        assert_eq!(plan.keep.len(), 3);
        assert!(plan.delete.is_empty());
    }

    #[test]
    fn test_plan_deletes_over_limit() {
        let policy = GfsPolicy { daily: 2, weekly: 0, monthly: 0, yearly: 0 };
        let r = BackupRotator::new(policy);
        let backups = vec![
            backup("day1", 2025, 1, 15),
            backup("day2", 2025, 1, 16),
            backup("day3", 2025, 1, 17),
            backup("day4", 2025, 1, 18),
        ];
        let plan = r.plan(&backups);
        assert!(plan.delete.len() >= 1);
    }

    #[test]
    fn test_promote_list() {
        let backups = vec![
            backup("a", 2025, 1, 1),
            backup("b", 2025, 1, 2),
        ];
        let r = BackupRotator::new(GfsPolicy::default());
        let plan = r.plan(&backups);
        assert!(!plan.promote.is_empty());
    }

    #[test]
    fn test_empty_backups() {
        let r = BackupRotator::new(GfsPolicy::default());
        let plan = r.plan(&[]);
        assert!(plan.keep.is_empty());
        assert!(plan.delete.is_empty());
    }

    #[test]
    fn test_days_until() {
        let sunday = Utc.with_ymd_and_hms(2025, 1, 5, 12, 0, 0).unwrap();
        let monday = days_until(Weekday::Mon, sunday);
        assert_eq!(monday, 1);
    }
}
