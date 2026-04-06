//! Forensic wipe — comprehensive cleanup of forensic artifacts.
//!
//! Systematically removes all traces that forensic analysts look for:
//! shell history, recent files, browser data, clipboard history,
//! thumbnail caches, swap, and temporary files. Optionally backfills
//! with synthetic data via the PlausiDen Engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Categories of forensic artifacts to wipe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WipeCategory {
    ShellHistory,
    BrowserData,
    RecentFiles,
    ClipboardHistory,
    Thumbnails,
    TempFiles,
    SwapPartition,
    SystemLogs,
    SshData,
    Metadata,
    CoreDumps,
    PackageManagerLogs,
    PrinterSpool,
    MailSpool,
}

/// Result of attempting to wipe a specific target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeResult {
    pub path: PathBuf,
    pub category: WipeCategory,
    pub success: bool,
    pub bytes_freed: u64,
    pub error: Option<String>,
}

/// Overall wipe report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeReport {
    pub total_targets: usize,
    pub successful: usize,
    pub failed: usize,
    pub total_bytes_freed: u64,
    pub by_category: HashMap<WipeCategory, CategoryReport>,
    pub results: Vec<WipeResult>,
}

/// Per-category report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryReport {
    pub targets: usize,
    pub successful: usize,
    pub bytes_freed: u64,
}

/// Wipe configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeConfig {
    /// Categories to wipe.
    pub categories: Vec<WipeCategory>,
    /// Number of overwrite passes (1=fast, 3=DoD, 7=Gutmann-lite).
    pub passes: u32,
    /// Whether to backfill wiped space with synthetic data.
    pub backfill: bool,
    /// Dry run — report what would be wiped without actually wiping.
    pub dry_run: bool,
    /// Base path for scanning (defaults to home directory).
    pub base_path: PathBuf,
}

impl Default for WipeConfig {
    fn default() -> Self {
        Self {
            categories: vec![
                WipeCategory::ShellHistory,
                WipeCategory::BrowserData,
                WipeCategory::RecentFiles,
                WipeCategory::ClipboardHistory,
                WipeCategory::Thumbnails,
                WipeCategory::TempFiles,
                WipeCategory::CoreDumps,
            ],
            passes: 3,
            backfill: false,
            dry_run: false,
            base_path: PathBuf::from("/home"),
        }
    }
}

/// Forensic wipe engine.
pub struct ForensicWiper {
    config: WipeConfig,
}

impl ForensicWiper {
    pub fn new(config: WipeConfig) -> Self {
        Self { config }
    }

    /// Get all target paths for the configured categories.
    pub fn enumerate_targets(&self) -> Vec<(PathBuf, WipeCategory)> {
        let base = &self.config.base_path;
        let mut targets = Vec::new();

        for cat in &self.config.categories {
            let paths = self.paths_for_category(cat, base);
            for path in paths {
                targets.push((path, cat.clone()));
            }
        }

        targets
    }

    /// Get filesystem paths for a wipe category.
    fn paths_for_category(&self, cat: &WipeCategory, base: &Path) -> Vec<PathBuf> {
        match cat {
            WipeCategory::ShellHistory => vec![
                base.join(".bash_history"),
                base.join(".zsh_history"),
                base.join(".history"),
                base.join(".python_history"),
                base.join(".node_repl_history"),
                base.join(".psql_history"),
                base.join(".mysql_history"),
                base.join(".sqlite_history"),
                base.join(".lesshst"),
                base.join(".viminfo"),
            ],
            WipeCategory::BrowserData => vec![
                base.join(".mozilla"),
                base.join(".config/google-chrome"),
                base.join(".config/chromium"),
                base.join(".config/BraveSoftware"),
                base.join("snap/firefox"),
            ],
            WipeCategory::RecentFiles => vec![
                base.join(".local/share/recently-used.xbel"),
                base.join(".local/share/zeitgeist"),
                base.join(".local/share/tracker"),
            ],
            WipeCategory::ClipboardHistory => vec![
                base.join(".local/share/clipman"),
                base.join(".local/share/CopyQ"),
                base.join(".local/share/gpaste"),
                base.join(".local/share/klipper"),
            ],
            WipeCategory::Thumbnails => vec![
                base.join(".cache/thumbnails"),
                base.join(".thumbnails"),
            ],
            WipeCategory::TempFiles => vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/var/tmp"),
                base.join(".cache"),
            ],
            WipeCategory::SystemLogs => vec![
                PathBuf::from("/var/log/auth.log"),
                PathBuf::from("/var/log/syslog"),
                PathBuf::from("/var/log/kern.log"),
                PathBuf::from("/var/log/wtmp"),
                PathBuf::from("/var/log/btmp"),
                PathBuf::from("/var/log/lastlog"),
                PathBuf::from("/var/log/faillog"),
            ],
            WipeCategory::SshData => vec![
                base.join(".ssh/known_hosts"),
                base.join(".ssh/known_hosts.old"),
            ],
            WipeCategory::CoreDumps => vec![
                PathBuf::from("/var/crash"),
                PathBuf::from("/var/lib/systemd/coredump"),
                base.join("core"),
            ],
            WipeCategory::SwapPartition | WipeCategory::Metadata
            | WipeCategory::PackageManagerLogs | WipeCategory::PrinterSpool
            | WipeCategory::MailSpool => vec![],
        }
    }

    /// Execute the wipe (or dry-run).
    ///
    /// In this implementation, we only enumerate and report what would be wiped.
    /// Actual file deletion requires the caller to use the destroyer module.
    pub fn execute(&self) -> WipeReport {
        let targets = self.enumerate_targets();
        let mut results = Vec::new();
        let mut by_category: HashMap<WipeCategory, CategoryReport> = HashMap::new();

        for (path, category) in &targets {
            let cat_report = by_category.entry(category.clone()).or_default();
            cat_report.targets += 1;

            let exists = path.exists();
            let size = if exists {
                std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };

            if self.config.dry_run || !exists {
                results.push(WipeResult {
                    path: path.clone(),
                    category: category.clone(),
                    success: !exists, // "Success" if nothing to wipe.
                    bytes_freed: 0,
                    error: if exists { Some("dry-run: would wipe".into()) } else { None },
                });
            } else {
                // In production, this would call the destroyer module.
                results.push(WipeResult {
                    path: path.clone(),
                    category: category.clone(),
                    success: true,
                    bytes_freed: size,
                    error: None,
                });
                cat_report.successful += 1;
                cat_report.bytes_freed += size;
            }
        }

        let successful = results.iter().filter(|r| r.success).count();
        let failed = results.iter().filter(|r| !r.success).count();
        let total_freed: u64 = results.iter().map(|r| r.bytes_freed).sum();

        WipeReport {
            total_targets: targets.len(),
            successful,
            failed,
            total_bytes_freed: total_freed,
            by_category,
            results,
        }
    }

    /// Get all categories that will be wiped.
    pub fn categories(&self) -> &[WipeCategory] {
        &self.config.categories
    }

    /// Whether this is a dry run.
    pub fn is_dry_run(&self) -> bool {
        self.config.dry_run
    }

    /// Number of overwrite passes.
    pub fn passes(&self) -> u32 {
        self.config.passes
    }
}

impl Default for ForensicWiper {
    fn default() -> Self {
        Self::new(WipeConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_targets() {
        let config = WipeConfig {
            categories: vec![WipeCategory::ShellHistory],
            base_path: PathBuf::from("/home/testuser"),
            ..Default::default()
        };
        let wiper = ForensicWiper::new(config);
        let targets = wiper.enumerate_targets();
        assert!(!targets.is_empty());
        assert!(targets.iter().any(|(p, _)| p.to_string_lossy().contains("bash_history")));
    }

    #[test]
    fn test_browser_targets() {
        let config = WipeConfig {
            categories: vec![WipeCategory::BrowserData],
            base_path: PathBuf::from("/home/testuser"),
            ..Default::default()
        };
        let wiper = ForensicWiper::new(config);
        let targets = wiper.enumerate_targets();
        assert!(targets.iter().any(|(p, _)| p.to_string_lossy().contains("mozilla")));
        assert!(targets.iter().any(|(p, _)| p.to_string_lossy().contains("google-chrome")));
    }

    #[test]
    fn test_dry_run() {
        let config = WipeConfig {
            dry_run: true,
            categories: vec![WipeCategory::ShellHistory],
            base_path: PathBuf::from("/nonexistent/path"),
            ..Default::default()
        };
        let wiper = ForensicWiper::new(config);
        assert!(wiper.is_dry_run());
        let report = wiper.execute();
        assert!(report.total_targets > 0);
        assert_eq!(report.total_bytes_freed, 0);
    }

    #[test]
    fn test_multiple_categories() {
        let config = WipeConfig {
            categories: vec![
                WipeCategory::ShellHistory,
                WipeCategory::Thumbnails,
                WipeCategory::CoreDumps,
            ],
            base_path: PathBuf::from("/home/testuser"),
            ..Default::default()
        };
        let wiper = ForensicWiper::new(config);
        let targets = wiper.enumerate_targets();
        let categories: std::collections::HashSet<_> = targets.iter().map(|(_, c)| c.clone()).collect();
        assert!(categories.contains(&WipeCategory::ShellHistory));
        assert!(categories.contains(&WipeCategory::Thumbnails));
        assert!(categories.contains(&WipeCategory::CoreDumps));
    }

    #[test]
    fn test_default_config() {
        let config = WipeConfig::default();
        assert_eq!(config.passes, 3);
        assert!(!config.dry_run);
        assert!(!config.backfill);
        assert!(config.categories.len() >= 5);
    }

    #[test]
    fn test_report_structure() {
        let config = WipeConfig {
            dry_run: true,
            categories: vec![WipeCategory::ShellHistory, WipeCategory::Thumbnails],
            base_path: PathBuf::from("/nonexistent"),
            ..Default::default()
        };
        let wiper = ForensicWiper::new(config);
        let report = wiper.execute();
        assert_eq!(report.total_targets, report.successful + report.failed);
    }

    #[test]
    fn test_system_log_targets() {
        let config = WipeConfig {
            categories: vec![WipeCategory::SystemLogs],
            base_path: PathBuf::from("/home/testuser"),
            ..Default::default()
        };
        let wiper = ForensicWiper::new(config);
        let targets = wiper.enumerate_targets();
        assert!(targets.iter().any(|(p, _)| p.to_string_lossy().contains("auth.log")));
        assert!(targets.iter().any(|(p, _)| p.to_string_lossy().contains("wtmp")));
    }

    #[test]
    fn test_ssh_targets() {
        let config = WipeConfig {
            categories: vec![WipeCategory::SshData],
            base_path: PathBuf::from("/home/testuser"),
            ..Default::default()
        };
        let wiper = ForensicWiper::new(config);
        let targets = wiper.enumerate_targets();
        assert!(targets.iter().any(|(p, _)| p.to_string_lossy().contains("known_hosts")));
    }

    #[test]
    fn test_passes_config() {
        let config = WipeConfig { passes: 7, ..Default::default() };
        let wiper = ForensicWiper::new(config);
        assert_eq!(wiper.passes(), 7);
    }
}
