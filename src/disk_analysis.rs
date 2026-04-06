//! Disk analysis — identify space consumers and cleanup opportunities.
//!
//! Scans directories to find large files, duplicate content, old caches,
//! and provides prioritized cleanup recommendations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A file entry with size and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub last_accessed: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub file_type: FileCategory,
}

/// Category of file for cleanup prioritization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileCategory {
    Cache,
    Log,
    Temporary,
    PackageCache,
    Thumbnail,
    Trash,
    CoreDump,
    OldKernel,
    BuildArtifact,
    UserDocument,
    Media,
    SystemFile,
    Unknown,
}

/// A cleanup recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupRecommendation {
    pub category: FileCategory,
    pub paths: Vec<PathBuf>,
    pub total_bytes: u64,
    pub risk: CleanupRisk,
    pub description: String,
}

/// Risk level for cleanup operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CleanupRisk {
    /// Safe to delete — regenerated automatically.
    Safe,
    /// Low risk — cached/temporary data.
    Low,
    /// Medium — user should review.
    Medium,
    /// High — potential data loss.
    High,
}

/// Disk usage summary for a scanned directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsageSummary {
    pub root_path: PathBuf,
    pub total_bytes: u64,
    pub file_count: u64,
    pub dir_count: u64,
    pub by_category: HashMap<FileCategory, CategoryStats>,
    pub largest_files: Vec<FileEntry>,
    pub reclaimable_bytes: u64,
}

/// Stats for a file category.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryStats {
    pub count: u64,
    pub total_bytes: u64,
}

/// Disk analyzer that scans and categorizes files.
pub struct DiskAnalyzer {
    /// Directories considered safe to clean.
    cache_dirs: Vec<PathBuf>,
    /// File extensions and their categories.
    extension_map: HashMap<String, FileCategory>,
    /// Maximum number of largest files to track.
    max_largest: usize,
}

impl DiskAnalyzer {
    pub fn new() -> Self {
        let mut ext_map = HashMap::new();
        // Logs
        for ext in &["log", "log.1", "log.gz", "log.old"] {
            ext_map.insert(ext.to_string(), FileCategory::Log);
        }
        // Temp
        for ext in &["tmp", "temp", "swp", "swo", "bak", "~"] {
            ext_map.insert(ext.to_string(), FileCategory::Temporary);
        }
        // Build artifacts
        for ext in &["o", "obj", "pyc", "pyo", "class"] {
            ext_map.insert(ext.to_string(), FileCategory::BuildArtifact);
        }
        // Core dumps
        ext_map.insert("core".into(), FileCategory::CoreDump);
        // Media
        for ext in &["mp4", "mkv", "avi", "mp3", "flac", "wav", "jpg", "png", "gif"] {
            ext_map.insert(ext.to_string(), FileCategory::Media);
        }

        Self {
            cache_dirs: vec![
                PathBuf::from(".cache"),
                PathBuf::from("__pycache__"),
                PathBuf::from("node_modules/.cache"),
                PathBuf::from(".npm/_cacache"),
                PathBuf::from("target/debug"),
                PathBuf::from("target/release"),
            ],
            extension_map: ext_map,
            max_largest: 20,
        }
    }

    /// Categorize a file based on its path and extension.
    pub fn categorize(&self, path: &Path) -> FileCategory {
        let path_str = path.to_string_lossy().to_lowercase();

        // Check path-based categories (order matters — more specific first).
        if path_str.contains("/thumbnails/") {
            return FileCategory::Thumbnail;
        }
        if path_str.contains("/.local/share/trash/") || path_str.contains("/trash/") {
            return FileCategory::Trash;
        }
        if path_str.contains("/.cache/") || path_str.contains("/cache/") {
            return FileCategory::Cache;
        }
        if path_str.contains("/log/") || path_str.ends_with(".log") {
            return FileCategory::Log;
        }
        if path_str.contains("/tmp/") || path_str.contains("/temp/") {
            return FileCategory::Temporary;
        }
        for cache_dir in &self.cache_dirs {
            if path_str.contains(&cache_dir.to_string_lossy().to_lowercase()) {
                return FileCategory::Cache;
            }
        }

        // Extension-based.
        if let Some(ext) = path.extension() {
            if let Some(cat) = self.extension_map.get(&ext.to_string_lossy().to_lowercase()) {
                return cat.clone();
            }
        }

        // Filename-based.
        if let Some(name) = path.file_name() {
            let name_str = name.to_string_lossy().to_lowercase();
            if name_str.starts_with("core.") {
                return FileCategory::CoreDump;
            }
        }

        FileCategory::Unknown
    }

    /// Analyze a set of file entries and produce a summary.
    pub fn analyze(&self, entries: &[FileEntry]) -> DiskUsageSummary {
        let mut by_category: HashMap<FileCategory, CategoryStats> = HashMap::new();
        let mut total_bytes = 0u64;
        let mut largest: Vec<FileEntry> = Vec::new();

        for entry in entries {
            total_bytes += entry.size_bytes;
            let stats = by_category.entry(entry.file_type.clone()).or_default();
            stats.count += 1;
            stats.total_bytes += entry.size_bytes;

            // Track largest files.
            largest.push(entry.clone());
            largest.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
            largest.truncate(self.max_largest);
        }

        let reclaimable = self.estimate_reclaimable(&by_category);

        DiskUsageSummary {
            root_path: PathBuf::from("/"),
            total_bytes,
            file_count: entries.len() as u64,
            dir_count: 0,
            by_category,
            largest_files: largest,
            reclaimable_bytes: reclaimable,
        }
    }

    /// Generate cleanup recommendations from a summary.
    pub fn recommend(&self, summary: &DiskUsageSummary) -> Vec<CleanupRecommendation> {
        let mut recs = Vec::new();

        let category_info: Vec<(FileCategory, CleanupRisk, &str)> = vec![
            (FileCategory::Cache, CleanupRisk::Safe, "Application caches — regenerated automatically"),
            (FileCategory::Thumbnail, CleanupRisk::Safe, "Thumbnail caches — regenerated on demand"),
            (FileCategory::Trash, CleanupRisk::Low, "Trash/recycle bin contents"),
            (FileCategory::Temporary, CleanupRisk::Low, "Temporary files — safe if no app is using them"),
            (FileCategory::Log, CleanupRisk::Low, "Log files — can be rotated or compressed"),
            (FileCategory::CoreDump, CleanupRisk::Low, "Core dumps — only needed for debugging"),
            (FileCategory::BuildArtifact, CleanupRisk::Safe, "Build artifacts — regenerated by build system"),
            (FileCategory::PackageCache, CleanupRisk::Safe, "Package manager caches — re-downloaded on demand"),
        ];

        for (category, risk, desc) in category_info {
            if let Some(stats) = summary.by_category.get(&category) {
                if stats.total_bytes > 0 {
                    recs.push(CleanupRecommendation {
                        category: category.clone(),
                        paths: Vec::new(), // Filled by caller with actual paths.
                        total_bytes: stats.total_bytes,
                        risk,
                        description: desc.into(),
                    });
                }
            }
        }

        // Sort by reclaimable size descending.
        recs.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
        recs
    }

    /// Estimate total reclaimable bytes from safe/low-risk categories.
    fn estimate_reclaimable(&self, by_category: &HashMap<FileCategory, CategoryStats>) -> u64 {
        let safe_cats = [
            FileCategory::Cache, FileCategory::Thumbnail, FileCategory::Trash,
            FileCategory::Temporary, FileCategory::Log, FileCategory::CoreDump,
            FileCategory::BuildArtifact, FileCategory::PackageCache,
        ];
        safe_cats.iter().filter_map(|c| by_category.get(c)).map(|s| s.total_bytes).sum()
    }

    /// Format bytes into human-readable string.
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        const TB: u64 = GB * 1024;
        if bytes >= TB { format!("{:.1} TB", bytes as f64 / TB as f64) }
        else if bytes >= GB { format!("{:.1} GB", bytes as f64 / GB as f64) }
        else if bytes >= MB { format!("{:.1} MB", bytes as f64 / MB as f64) }
        else if bytes >= KB { format!("{:.1} KB", bytes as f64 / KB as f64) }
        else { format!("{bytes} B") }
    }
}

impl Default for DiskAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_entry(path: &str, size: u64, category: FileCategory) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size_bytes: size,
            last_accessed: Utc::now(),
            last_modified: Utc::now() - Duration::days(30),
            file_type: category,
        }
    }

    #[test]
    fn test_categorize_cache() {
        let analyzer = DiskAnalyzer::new();
        assert_eq!(analyzer.categorize(Path::new("/home/user/.cache/mozilla/data")), FileCategory::Cache);
        assert_eq!(analyzer.categorize(Path::new("/var/cache/apt/archives/pkg.deb")), FileCategory::Cache);
    }

    #[test]
    fn test_categorize_log() {
        let analyzer = DiskAnalyzer::new();
        assert_eq!(analyzer.categorize(Path::new("/var/log/syslog")), FileCategory::Log);
        assert_eq!(analyzer.categorize(Path::new("/home/user/app.log")), FileCategory::Log);
    }

    #[test]
    fn test_categorize_trash() {
        let analyzer = DiskAnalyzer::new();
        assert_eq!(analyzer.categorize(Path::new("/home/user/.local/share/trash/files/old.txt")), FileCategory::Trash);
    }

    #[test]
    fn test_categorize_thumbnail() {
        let analyzer = DiskAnalyzer::new();
        assert_eq!(analyzer.categorize(Path::new("/home/user/.cache/thumbnails/normal/abc.png")), FileCategory::Thumbnail);
    }

    #[test]
    fn test_categorize_build_artifact() {
        let analyzer = DiskAnalyzer::new();
        assert_eq!(analyzer.categorize(Path::new("/home/user/project/src/main.o")), FileCategory::BuildArtifact);
        assert_eq!(analyzer.categorize(Path::new("/home/user/app/__pycache__/mod.pyc")), FileCategory::Cache);
    }

    #[test]
    fn test_categorize_media() {
        let analyzer = DiskAnalyzer::new();
        assert_eq!(analyzer.categorize(Path::new("/home/user/video.mp4")), FileCategory::Media);
        assert_eq!(analyzer.categorize(Path::new("/home/user/photo.jpg")), FileCategory::Media);
    }

    #[test]
    fn test_categorize_unknown() {
        let analyzer = DiskAnalyzer::new();
        assert_eq!(analyzer.categorize(Path::new("/home/user/document.odt")), FileCategory::Unknown);
    }

    #[test]
    fn test_analyze_summary() {
        let analyzer = DiskAnalyzer::new();
        let entries = vec![
            make_entry("/home/user/.cache/big", 1_000_000, FileCategory::Cache),
            make_entry("/var/log/syslog", 500_000, FileCategory::Log),
            make_entry("/tmp/junk", 100_000, FileCategory::Temporary),
            make_entry("/home/user/doc.pdf", 200_000, FileCategory::UserDocument),
        ];
        let summary = analyzer.analyze(&entries);
        assert_eq!(summary.file_count, 4);
        assert_eq!(summary.total_bytes, 1_800_000);
        // Cache + Log + Temporary are reclaimable.
        assert_eq!(summary.reclaimable_bytes, 1_600_000);
    }

    #[test]
    fn test_largest_files_tracked() {
        let analyzer = DiskAnalyzer::new();
        let entries: Vec<FileEntry> = (0..30)
            .map(|i| make_entry(&format!("/file{i}"), (i + 1) * 1000, FileCategory::Unknown))
            .collect();
        let summary = analyzer.analyze(&entries);
        assert_eq!(summary.largest_files.len(), 20); // max_largest = 20
        assert_eq!(summary.largest_files[0].size_bytes, 30_000); // Largest first.
    }

    #[test]
    fn test_recommendations() {
        let analyzer = DiskAnalyzer::new();
        let entries = vec![
            make_entry("/cache/a", 5_000_000, FileCategory::Cache),
            make_entry("/tmp/b", 1_000_000, FileCategory::Temporary),
            make_entry("/trash/c", 2_000_000, FileCategory::Trash),
        ];
        let summary = analyzer.analyze(&entries);
        let recs = analyzer.recommend(&summary);
        assert!(!recs.is_empty());
        // Largest reclaimable first.
        assert_eq!(recs[0].category, FileCategory::Cache);
        assert_eq!(recs[0].total_bytes, 5_000_000);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(DiskAnalyzer::format_bytes(500), "500 B");
        assert_eq!(DiskAnalyzer::format_bytes(1536), "1.5 KB");
        assert_eq!(DiskAnalyzer::format_bytes(1_048_576), "1.0 MB");
        assert_eq!(DiskAnalyzer::format_bytes(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn test_empty_analysis() {
        let analyzer = DiskAnalyzer::new();
        let summary = analyzer.analyze(&[]);
        assert_eq!(summary.file_count, 0);
        assert_eq!(summary.total_bytes, 0);
        assert_eq!(summary.reclaimable_bytes, 0);
        assert!(analyzer.recommend(&summary).is_empty());
    }
}
