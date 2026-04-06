//! Swap cleaner — securely clear swap partition data.
//!
//! Swap can contain sensitive data from any process that was swapped out.
//! This module handles swap disabling, overwriting, and re-enabling.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Swap partition/file info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapInfo {
    pub path: PathBuf,
    pub swap_type: SwapType,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub priority: i32,
}

/// Type of swap device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapType {
    Partition,
    File,
}

/// Status of swap cleaning operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanStatus {
    Pending,
    Disabling,
    Overwriting,
    ReEnabling,
    Complete,
    Failed { reason: String },
}

/// Swap cleaning plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapCleanPlan {
    pub swap_devices: Vec<SwapInfo>,
    pub total_swap_bytes: u64,
    pub estimated_time_secs: u64,
    pub requires_root: bool,
}

/// Swap cleaner engine.
pub struct SwapCleaner {
    status: CleanStatus,
}

impl SwapCleaner {
    pub fn new() -> Self {
        Self { status: CleanStatus::Pending }
    }

    /// Parse /proc/swaps to find active swap devices.
    pub fn detect_swaps() -> Vec<SwapInfo> {
        let mut swaps = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/swaps") {
                for line in content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let path = PathBuf::from(parts[0]);
                        let swap_type = if parts[1] == "partition" { SwapType::Partition } else { SwapType::File };
                        let size_kb: u64 = parts[2].parse().unwrap_or(0);
                        let used_kb: u64 = parts[3].parse().unwrap_or(0);
                        let priority: i32 = parts[4].parse().unwrap_or(0);

                        swaps.push(SwapInfo {
                            path,
                            swap_type,
                            size_bytes: size_kb * 1024,
                            used_bytes: used_kb * 1024,
                            priority,
                        });
                    }
                }
            }
        }

        swaps
    }

    /// Create a cleaning plan.
    pub fn plan() -> SwapCleanPlan {
        let swaps = Self::detect_swaps();
        let total: u64 = swaps.iter().map(|s| s.size_bytes).sum();
        // Estimate: ~100 MB/s write speed for overwriting.
        let est_secs = total / (100 * 1024 * 1024) + 1;

        SwapCleanPlan {
            swap_devices: swaps,
            total_swap_bytes: total,
            estimated_time_secs: est_secs,
            requires_root: true,
        }
    }

    /// Generate the shell commands needed to clean swap.
    /// Does NOT execute them — caller must review and run.
    pub fn generate_commands(swap: &SwapInfo) -> Vec<String> {
        let path = swap.path.to_string_lossy();
        vec![
            format!("swapoff {path}"),
            format!("dd if=/dev/urandom of={path} bs=1M status=progress"),
            format!("mkswap {path}"),
            format!("swapon -p {} {path}", swap.priority),
        ]
    }

    /// Get current status.
    pub fn status(&self) -> &CleanStatus {
        &self.status
    }
}

impl Default for SwapCleaner {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_swaps() {
        let swaps = SwapCleaner::detect_swaps();
        // On a real system, should find at least one swap.
        // On CI, might find none — that's OK.
        for swap in &swaps {
            assert!(swap.size_bytes > 0 || swap.used_bytes == 0);
        }
    }

    #[test]
    fn test_plan() {
        let plan = SwapCleaner::plan();
        assert!(plan.requires_root);
    }

    #[test]
    fn test_generate_commands() {
        let swap = SwapInfo {
            path: PathBuf::from("/dev/sda2"),
            swap_type: SwapType::Partition,
            size_bytes: 4_000_000_000,
            used_bytes: 1_000_000,
            priority: -2,
        };
        let cmds = SwapCleaner::generate_commands(&swap);
        assert_eq!(cmds.len(), 4);
        assert!(cmds[0].contains("swapoff"));
        assert!(cmds[1].contains("urandom"));
        assert!(cmds[2].contains("mkswap"));
        assert!(cmds[3].contains("swapon"));
    }

    #[test]
    fn test_swap_type() {
        let partition = SwapInfo {
            path: PathBuf::from("/dev/sda2"),
            swap_type: SwapType::Partition,
            size_bytes: 4_000_000_000,
            used_bytes: 0,
            priority: -2,
        };
        let file = SwapInfo {
            path: PathBuf::from("/swapfile"),
            swap_type: SwapType::File,
            size_bytes: 2_000_000_000,
            used_bytes: 0,
            priority: -1,
        };
        assert_eq!(partition.swap_type, SwapType::Partition);
        assert_eq!(file.swap_type, SwapType::File);
    }

    #[test]
    fn test_status_default() {
        let cleaner = SwapCleaner::new();
        assert_eq!(*cleaner.status(), CleanStatus::Pending);
    }
}
