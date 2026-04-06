//! Disk watcher — trigger cleanup when usage thresholds are crossed.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Usage sample for a single mount point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSample {
    pub mount: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub sampled_at: DateTime<Utc>,
}

impl DiskSample {
    pub fn usage_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        self.used_bytes as f64 / self.total_bytes as f64
    }

    pub fn usage_percent(&self) -> u32 {
        (self.usage_ratio() * 100.0).round() as u32
    }
}

/// Severity level of a disk usage condition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DiskSeverity {
    Ok,
    Warn,
    Critical,
    Emergency,
}

/// Threshold configuration (percentages).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskThresholds {
    pub warn_at: u32,
    pub critical_at: u32,
    pub emergency_at: u32,
}

impl Default for DiskThresholds {
    fn default() -> Self {
        Self {
            warn_at: 75,
            critical_at: 90,
            emergency_at: 95,
        }
    }
}

/// Cleanup action recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanupAction {
    None,
    PurgeTempFiles,
    PurgeTempAndCache,
    PurgeAllJunk,
    EmergencyWipe,
}

/// Disk watcher.
pub struct DiskWatcher {
    thresholds: DiskThresholds,
    history: Vec<DiskSample>,
    history_limit: usize,
}

impl DiskWatcher {
    pub fn new(thresholds: DiskThresholds) -> Self {
        Self { thresholds, history: Vec::new(), history_limit: 1000 }
    }

    /// Classify a sample by severity.
    pub fn severity(&self, sample: &DiskSample) -> DiskSeverity {
        let pct = sample.usage_percent();
        if pct >= self.thresholds.emergency_at {
            DiskSeverity::Emergency
        } else if pct >= self.thresholds.critical_at {
            DiskSeverity::Critical
        } else if pct >= self.thresholds.warn_at {
            DiskSeverity::Warn
        } else {
            DiskSeverity::Ok
        }
    }

    /// Recommended cleanup action for a given severity.
    pub fn recommend(&self, severity: &DiskSeverity) -> CleanupAction {
        match severity {
            DiskSeverity::Ok => CleanupAction::None,
            DiskSeverity::Warn => CleanupAction::PurgeTempFiles,
            DiskSeverity::Critical => CleanupAction::PurgeTempAndCache,
            DiskSeverity::Emergency => CleanupAction::EmergencyWipe,
        }
    }

    /// Record a sample into history.
    pub fn observe(&mut self, sample: DiskSample) {
        self.history.push(sample);
        if self.history.len() > self.history_limit {
            self.history.remove(0);
        }
    }

    /// Most-recent sample for a given mount.
    pub fn latest_for(&self, mount: &str) -> Option<&DiskSample> {
        self.history.iter().rev().find(|s| s.mount == mount)
    }

    /// Rate of usage change for a mount (bytes per second) using most recent
    /// two samples.
    pub fn growth_rate(&self, mount: &str) -> Option<f64> {
        let samples: Vec<&DiskSample> = self.history.iter()
            .filter(|s| s.mount == mount).collect();
        if samples.len() < 2 {
            return None;
        }
        let last = samples[samples.len() - 1];
        let prev = samples[samples.len() - 2];
        let delta_bytes = last.used_bytes as i64 - prev.used_bytes as i64;
        let delta_secs = (last.sampled_at - prev.sampled_at).num_seconds();
        if delta_secs <= 0 {
            return None;
        }
        Some(delta_bytes as f64 / delta_secs as f64)
    }

    /// Estimate seconds until mount is full at current growth rate.
    pub fn estimated_time_to_full(&self, mount: &str) -> Option<i64> {
        let rate = self.growth_rate(mount)?;
        if rate <= 0.0 {
            return None; // shrinking or flat
        }
        let last = self.latest_for(mount)?;
        Some((last.available_bytes as f64 / rate) as i64)
    }

    /// All mounts currently in given severity or worse.
    pub fn mounts_at_or_above(&self, severity: DiskSeverity) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for sample in self.history.iter().rev() {
            if seen.insert(sample.mount.clone()) && self.severity(sample) >= severity {
                out.push(sample.mount.clone());
            }
        }
        out
    }

    pub fn sample_count(&self) -> usize {
        self.history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(mount: &str, used: u64, total: u64) -> DiskSample {
        DiskSample {
            mount: mount.into(),
            total_bytes: total,
            used_bytes: used,
            available_bytes: total - used,
            sampled_at: Utc::now(),
        }
    }

    #[test]
    fn test_usage_ratio() {
        let s = mk("/", 50, 100);
        assert_eq!(s.usage_ratio(), 0.5);
        assert_eq!(s.usage_percent(), 50);
    }

    #[test]
    fn test_severity_ok() {
        let w = DiskWatcher::new(DiskThresholds::default());
        let s = mk("/", 10, 100);
        assert_eq!(w.severity(&s), DiskSeverity::Ok);
    }

    #[test]
    fn test_severity_warn() {
        let w = DiskWatcher::new(DiskThresholds::default());
        let s = mk("/", 80, 100);
        assert_eq!(w.severity(&s), DiskSeverity::Warn);
    }

    #[test]
    fn test_severity_critical() {
        let w = DiskWatcher::new(DiskThresholds::default());
        let s = mk("/", 92, 100);
        assert_eq!(w.severity(&s), DiskSeverity::Critical);
    }

    #[test]
    fn test_severity_emergency() {
        let w = DiskWatcher::new(DiskThresholds::default());
        let s = mk("/", 96, 100);
        assert_eq!(w.severity(&s), DiskSeverity::Emergency);
    }

    #[test]
    fn test_recommend() {
        let w = DiskWatcher::new(DiskThresholds::default());
        assert_eq!(w.recommend(&DiskSeverity::Ok), CleanupAction::None);
        assert_eq!(w.recommend(&DiskSeverity::Emergency), CleanupAction::EmergencyWipe);
    }

    #[test]
    fn test_observe_and_latest() {
        let mut w = DiskWatcher::new(DiskThresholds::default());
        w.observe(mk("/", 10, 100));
        w.observe(mk("/", 20, 100));
        let latest = w.latest_for("/").unwrap();
        assert_eq!(latest.used_bytes, 20);
    }

    #[test]
    fn test_growth_rate() {
        let mut w = DiskWatcher::new(DiskThresholds::default());
        let mut s1 = mk("/", 10, 100);
        s1.sampled_at = Utc::now() - chrono::Duration::seconds(10);
        let s2 = mk("/", 20, 100);
        w.observe(s1);
        w.observe(s2);
        let rate = w.growth_rate("/").unwrap();
        assert!(rate > 0.0);
    }

    #[test]
    fn test_mounts_at_or_above() {
        let mut w = DiskWatcher::new(DiskThresholds::default());
        w.observe(mk("/", 96, 100));
        w.observe(mk("/home", 50, 100));
        let critical = w.mounts_at_or_above(DiskSeverity::Critical);
        assert!(critical.contains(&"/".to_string()));
        assert!(!critical.contains(&"/home".to_string()));
    }
}
