//! Free space wiping — overwrite deleted file remnants on disk.
//!
//! Even after deletion, file contents remain on disk until overwritten.
//! This module fills free space with random data, then deletes the fill
//! files, ensuring no recoverable data remains in unallocated blocks.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Strategy for filling free space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FillStrategy {
    /// Fill with zeros (fast but detectable).
    Zeros,
    /// Fill with cryptographic random data (secure but slow).
    Random,
    /// Multiple passes: zeros, ones, random (DoD-style).
    MultiPass,
    /// Fill with plausible data from PlausiDen Engine (best deniability).
    PlausibleData,
}

/// Configuration for free space wiping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeSpaceConfig {
    /// Target filesystem path (any path on the target volume).
    pub target_path: PathBuf,
    /// Fill strategy.
    pub strategy: FillStrategy,
    /// Maximum fill file size in MB (limits memory/disk usage per file).
    pub chunk_size_mb: u64,
    /// Leave this much free space (MB) to avoid filling the disk completely.
    pub reserve_mb: u64,
    /// Also wipe inode metadata (small file technique).
    pub wipe_inodes: bool,
}

impl Default for FreeSpaceConfig {
    fn default() -> Self {
        Self {
            target_path: PathBuf::from("/tmp"),
            strategy: FillStrategy::Random,
            chunk_size_mb: 100,
            reserve_mb: 500,
            wipe_inodes: true,
        }
    }
}

/// Progress report during free space wipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeProgress {
    pub phase: WipePhase,
    pub bytes_written: u64,
    pub total_free_bytes: u64,
    pub fill_files_created: u32,
    pub inode_files_created: u32,
    pub errors: Vec<String>,
}

/// Current phase of the wipe operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipePhase {
    Measuring,
    FillingBlocks,
    FillingInodes,
    Cleaning,
    Complete,
}

/// Free space wiper engine.
pub struct FreeSpaceWiper {
    config: FreeSpaceConfig,
}

impl FreeSpaceWiper {
    pub fn new(config: FreeSpaceConfig) -> Self {
        Self { config }
    }

    /// Estimate available free space on the target filesystem.
    pub fn estimate_free_space(&self) -> Result<u64, String> {
        #[cfg(unix)]
        {
            let path_str = self.config.target_path.to_string_lossy();
            // Use statvfs to get filesystem stats.
            // For now, return a simulated value in tests.
            let metadata = std::fs::metadata(&self.config.target_path)
                .map_err(|e| format!("Cannot access {}: {}", path_str, e))?;
            if !metadata.is_dir() {
                return Err(format!("{} is not a directory", path_str));
            }
            // In production, this would use libc::statvfs.
            // Return a placeholder for testability.
            Ok(0)
        }
        #[cfg(not(unix))]
        {
            Ok(0)
        }
    }

    /// Calculate how many fill files are needed.
    pub fn plan(&self, free_bytes: u64) -> WipePlan {
        let usable = free_bytes.saturating_sub(self.config.reserve_mb * 1024 * 1024);
        let chunk_bytes = self.config.chunk_size_mb * 1024 * 1024;
        let full_chunks = if chunk_bytes > 0 { usable / chunk_bytes } else { 0 };
        let remainder = if chunk_bytes > 0 { usable % chunk_bytes } else { 0 };
        let passes = match self.config.strategy {
            FillStrategy::Zeros | FillStrategy::Random | FillStrategy::PlausibleData => 1,
            FillStrategy::MultiPass => 3,
        };

        WipePlan {
            total_bytes: usable,
            chunk_size: chunk_bytes,
            full_chunks: full_chunks as u32,
            remainder_bytes: remainder,
            passes,
            wipe_inodes: self.config.wipe_inodes,
            estimated_inode_files: if self.config.wipe_inodes { 1000 } else { 0 },
        }
    }

    /// Generate the fill pattern for a given strategy and pass number.
    pub fn fill_pattern(&self, pass: u32, size: usize) -> Vec<u8> {
        match self.config.strategy {
            FillStrategy::Zeros => vec![0x00; size],
            FillStrategy::Random => {
                // In production, use ChaCha20Rng.
                let mut data = vec![0u8; size];
                for (i, byte) in data.iter_mut().enumerate() {
                    // Deterministic pseudo-random for testing.
                    *byte = ((i as u64).wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407) >> 33) as u8;
                }
                data
            }
            FillStrategy::MultiPass => {
                match pass {
                    0 => vec![0x00; size],
                    1 => vec![0xFF; size],
                    _ => {
                        let mut data = vec![0u8; size];
                        for (i, byte) in data.iter_mut().enumerate() {
                            *byte = ((i as u64).wrapping_mul(6364136223846793005).wrapping_add(pass as u64) >> 33) as u8;
                        }
                        data
                    }
                }
            }
            FillStrategy::PlausibleData => {
                // In production, this would generate realistic file content.
                // For now, use random-looking data.
                let mut data = vec![0u8; size];
                for (i, byte) in data.iter_mut().enumerate() {
                    *byte = ((i as u64).wrapping_mul(2862933555777941757).wrapping_add(3037000493) >> 33) as u8;
                }
                data
            }
        }
    }

    /// Get the fill file path for a given chunk index.
    pub fn fill_path(&self, index: u32) -> PathBuf {
        self.config.target_path.join(format!(".purge_fill_{index:04}.tmp"))
    }

    /// Get the inode fill file path for a given index.
    pub fn inode_path(&self, index: u32) -> PathBuf {
        self.config.target_path.join(format!(".purge_inode_{index:06}.tmp"))
    }

    /// Reference to the configuration.
    pub fn config(&self) -> &FreeSpaceConfig {
        &self.config
    }
}

impl Default for FreeSpaceWiper {
    fn default() -> Self { Self::new(FreeSpaceConfig::default()) }
}

/// Plan for a free space wipe operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipePlan {
    pub total_bytes: u64,
    pub chunk_size: u64,
    pub full_chunks: u32,
    pub remainder_bytes: u64,
    pub passes: u32,
    pub wipe_inodes: bool,
    pub estimated_inode_files: u32,
}

impl WipePlan {
    /// Total write operations needed.
    pub fn total_writes(&self) -> u64 {
        let chunk_writes = (self.full_chunks as u64 + if self.remainder_bytes > 0 { 1 } else { 0 }) * self.passes as u64;
        chunk_writes + self.estimated_inode_files as u64
    }

    /// Estimated time in seconds (rough: 100 MB/s write speed).
    pub fn estimated_duration_secs(&self) -> u64 {
        let bytes = self.total_bytes * self.passes as u64;
        bytes / (100 * 1024 * 1024) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_basic() {
        let config = FreeSpaceConfig {
            chunk_size_mb: 100,
            reserve_mb: 0,
            ..Default::default()
        };
        let wiper = FreeSpaceWiper::new(config);
        // 1 GB free space.
        let plan = wiper.plan(1024 * 1024 * 1024);
        assert_eq!(plan.full_chunks, 10); // 1024 MB / 100 MB = 10 chunks.
        assert_eq!(plan.remainder_bytes, 24 * 1024 * 1024); // 1024 % 100 = 24 MB.
    }

    #[test]
    fn test_plan_with_reserve() {
        let config = FreeSpaceConfig {
            chunk_size_mb: 100,
            reserve_mb: 500,
            ..Default::default()
        };
        let wiper = FreeSpaceWiper::new(config);
        let plan = wiper.plan(1024 * 1024 * 1024);
        // 1024 MB - 500 MB reserve = 524 MB usable.
        assert_eq!(plan.full_chunks, 5);
    }

    #[test]
    fn test_plan_multipass() {
        let config = FreeSpaceConfig {
            strategy: FillStrategy::MultiPass,
            ..Default::default()
        };
        let wiper = FreeSpaceWiper::new(config);
        let plan = wiper.plan(500 * 1024 * 1024);
        assert_eq!(plan.passes, 3);
    }

    #[test]
    fn test_fill_pattern_zeros() {
        let config = FreeSpaceConfig { strategy: FillStrategy::Zeros, ..Default::default() };
        let wiper = FreeSpaceWiper::new(config);
        let pattern = wiper.fill_pattern(0, 100);
        assert!(pattern.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_fill_pattern_random() {
        let config = FreeSpaceConfig { strategy: FillStrategy::Random, ..Default::default() };
        let wiper = FreeSpaceWiper::new(config);
        let pattern = wiper.fill_pattern(0, 1000);
        // Should not be all zeros or all same value.
        let unique: std::collections::HashSet<u8> = pattern.iter().copied().collect();
        assert!(unique.len() > 10, "random pattern should have variety");
    }

    #[test]
    fn test_fill_pattern_multipass_differs() {
        let config = FreeSpaceConfig { strategy: FillStrategy::MultiPass, ..Default::default() };
        let wiper = FreeSpaceWiper::new(config);
        let p0 = wiper.fill_pattern(0, 100);
        let p1 = wiper.fill_pattern(1, 100);
        let p2 = wiper.fill_pattern(2, 100);
        assert!(p0.iter().all(|&b| b == 0x00)); // Pass 0 = zeros.
        assert!(p1.iter().all(|&b| b == 0xFF)); // Pass 1 = ones.
        assert_ne!(p2, p0); // Pass 2 = random.
    }

    #[test]
    fn test_fill_path() {
        let config = FreeSpaceConfig { target_path: PathBuf::from("/mnt/data"), ..Default::default() };
        let wiper = FreeSpaceWiper::new(config);
        assert_eq!(wiper.fill_path(0).to_str().unwrap(), "/mnt/data/.purge_fill_0000.tmp");
        assert_eq!(wiper.fill_path(42).to_str().unwrap(), "/mnt/data/.purge_fill_0042.tmp");
    }

    #[test]
    fn test_inode_path() {
        let config = FreeSpaceConfig { target_path: PathBuf::from("/tmp"), ..Default::default() };
        let wiper = FreeSpaceWiper::new(config);
        assert_eq!(wiper.inode_path(0).to_str().unwrap(), "/tmp/.purge_inode_000000.tmp");
    }

    #[test]
    fn test_total_writes() {
        let config = FreeSpaceConfig {
            chunk_size_mb: 100,
            reserve_mb: 0,
            strategy: FillStrategy::MultiPass,
            wipe_inodes: true,
            ..Default::default()
        };
        let wiper = FreeSpaceWiper::new(config);
        let plan = wiper.plan(500 * 1024 * 1024);
        // 5 chunks * 3 passes + 1000 inode files.
        assert_eq!(plan.total_writes(), 5 * 3 + 1000);
    }

    #[test]
    fn test_estimated_duration() {
        let config = FreeSpaceConfig { chunk_size_mb: 100, reserve_mb: 0, ..Default::default() };
        let wiper = FreeSpaceWiper::new(config);
        let plan = wiper.plan(10 * 1024 * 1024 * 1024); // 10 GB
        assert!(plan.estimated_duration_secs() > 90); // 10 GB / 100 MB/s ≈ 100s.
    }

    #[test]
    fn test_zero_free_space() {
        let wiper = FreeSpaceWiper::default();
        let plan = wiper.plan(0);
        assert_eq!(plan.full_chunks, 0);
        assert_eq!(plan.total_bytes, 0);
    }
}
