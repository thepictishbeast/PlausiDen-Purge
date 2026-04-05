//! Purge configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeConfig {
    pub unused_threshold_days: u64,
    pub default_algorithm: String,
    pub verify_deletion: bool,
    pub backfill_after_delete: bool,
    pub max_scan_depth: u32,
}

impl Default for PurgeConfig {
    fn default() -> Self {
        Self { unused_threshold_days: 90, default_algorithm: "nist".into(), verify_deletion: true, backfill_after_delete: false, max_scan_depth: 10 }
    }
}

impl PurgeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.unused_threshold_days == 0 { return Err("threshold must be > 0".into()); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_valid() { assert!(PurgeConfig::default().validate().is_ok()); }
    #[test]
    fn test_zero_threshold_invalid() { let mut c = PurgeConfig::default(); c.unused_threshold_days = 0; assert!(c.validate().is_err()); }
}
