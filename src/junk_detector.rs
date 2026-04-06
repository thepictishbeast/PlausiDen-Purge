//! Junk file detector — identify files safe to delete.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Junk file category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JunkCategory {
    BackupFile,       // *.bak, *~
    SwapFile,         // .swp, .swo
    TempFile,         // *.tmp, *.temp
    LogRotation,      // *.log.1, *.log.gz
    ThumbnailCache,   // thumbnail cache
    CrashDump,        // core dumps
    BuildArtifact,    // *.o, *.pyc, target/
    PackageCache,     // apt/pip/npm cache
    BrowserCache,     // browser cache
    EmptyDirectory,   // empty dirs
}

/// Junk file detector.
pub struct JunkDetector;

impl JunkDetector {
    pub fn new() -> Self { Self }

    /// Classify a file as junk or not.
    pub fn classify(&self, path: &Path) -> Option<JunkCategory> {
        let path_str = path.to_string_lossy().to_lowercase();
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Backup files.
        if filename.ends_with(".bak") || filename.ends_with("~") || filename.ends_with(".orig") {
            return Some(JunkCategory::BackupFile);
        }

        // Swap files.
        if filename.ends_with(".swp") || filename.ends_with(".swo") {
            return Some(JunkCategory::SwapFile);
        }

        // Temp files.
        if filename.ends_with(".tmp") || filename.ends_with(".temp") {
            return Some(JunkCategory::TempFile);
        }

        // Log rotation. Matches foo.log.1, foo.log.gz, and numeric-suffixed
        // files under /var/log/ (e.g. syslog.1, auth.log.2.gz).
        if filename.contains(".log.") || filename.ends_with(".log.gz") {
            return Some(JunkCategory::LogRotation);
        }
        if path_str.contains("/var/log/") {
            // Strip trailing .gz for the numeric-suffix check.
            let stem = filename.strip_suffix(".gz").unwrap_or(&filename);
            if let Some(last_dot) = stem.rfind('.') {
                let suffix = &stem[last_dot + 1..];
                if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                    return Some(JunkCategory::LogRotation);
                }
            }
        }

        // Thumbnail cache.
        if path_str.contains("/thumbnails/") || path_str.contains("/.cache/thumbnails/") {
            return Some(JunkCategory::ThumbnailCache);
        }

        // Crash dumps.
        if filename.starts_with("core.") || path_str.contains("/var/crash/") {
            return Some(JunkCategory::CrashDump);
        }

        // Build artifacts.
        if filename.ends_with(".o") || filename.ends_with(".pyc") || filename.ends_with(".pyo")
            || path_str.contains("/target/debug/") || path_str.contains("/target/release/")
            || path_str.contains("/__pycache__/") || path_str.contains("/node_modules/.cache/")
        {
            return Some(JunkCategory::BuildArtifact);
        }

        // Package cache.
        if path_str.contains("/var/cache/apt/") || path_str.contains("/.npm/_cacache/")
            || path_str.contains("/.cargo/registry/cache/") || path_str.contains("/pip/cache/")
        {
            return Some(JunkCategory::PackageCache);
        }

        // Browser cache.
        if path_str.contains("/.cache/mozilla/")
            || path_str.contains("/.cache/google-chrome/")
            || path_str.contains("/.cache/chromium/")
        {
            return Some(JunkCategory::BrowserCache);
        }

        None
    }

    /// Quick check if a path is junk.
    pub fn is_junk(&self, path: &Path) -> bool {
        self.classify(path).is_some()
    }
}

impl Default for JunkDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_backup_file() {
        let d = JunkDetector::new();
        assert_eq!(d.classify(&PathBuf::from("/home/user/doc.txt.bak")), Some(JunkCategory::BackupFile));
        assert_eq!(d.classify(&PathBuf::from("/home/user/config~")), Some(JunkCategory::BackupFile));
    }

    #[test]
    fn test_swap_file() {
        let d = JunkDetector::new();
        assert_eq!(d.classify(&PathBuf::from("/tmp/.file.swp")), Some(JunkCategory::SwapFile));
    }

    #[test]
    fn test_temp_file() {
        let d = JunkDetector::new();
        assert_eq!(d.classify(&PathBuf::from("/tmp/scratch.tmp")), Some(JunkCategory::TempFile));
    }

    #[test]
    fn test_log_rotation() {
        let d = JunkDetector::new();
        assert_eq!(d.classify(&PathBuf::from("/var/log/syslog.1")), Some(JunkCategory::LogRotation));
        assert_eq!(d.classify(&PathBuf::from("/var/log/auth.log.gz")), Some(JunkCategory::LogRotation));
    }

    #[test]
    fn test_thumbnail_cache() {
        let d = JunkDetector::new();
        assert_eq!(
            d.classify(&PathBuf::from("/home/user/.cache/thumbnails/normal/abc.png")),
            Some(JunkCategory::ThumbnailCache)
        );
    }

    #[test]
    fn test_crash_dump() {
        let d = JunkDetector::new();
        assert_eq!(d.classify(&PathBuf::from("/home/user/core.1234")), Some(JunkCategory::CrashDump));
    }

    #[test]
    fn test_build_artifact() {
        let d = JunkDetector::new();
        assert_eq!(d.classify(&PathBuf::from("/home/user/proj/main.o")), Some(JunkCategory::BuildArtifact));
        assert_eq!(d.classify(&PathBuf::from("/home/user/__pycache__/mod.pyc")), Some(JunkCategory::BuildArtifact));
    }

    #[test]
    fn test_package_cache() {
        let d = JunkDetector::new();
        assert_eq!(d.classify(&PathBuf::from("/var/cache/apt/archives/pkg.deb")), Some(JunkCategory::PackageCache));
    }

    #[test]
    fn test_not_junk() {
        let d = JunkDetector::new();
        assert_eq!(d.classify(&PathBuf::from("/home/user/document.pdf")), None);
    }

    #[test]
    fn test_is_junk() {
        let d = JunkDetector::new();
        assert!(d.is_junk(&PathBuf::from("/tmp/test.tmp")));
        assert!(!d.is_junk(&PathBuf::from("/home/user/photo.jpg")));
    }
}
