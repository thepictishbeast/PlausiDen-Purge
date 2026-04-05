//! Cleanup report generation — comprehensive summary of what was cleaned.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupReport {
    pub generated_at: DateTime<Utc>,
    pub total_files_deleted: u64,
    pub total_bytes_freed: u64,
    pub categories: Vec<CategoryReport>,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryReport {
    pub name: String,
    pub files_deleted: u64,
    pub bytes_freed: u64,
}

impl CleanupReport {
    pub fn new() -> Self {
        Self { generated_at: Utc::now(), total_files_deleted: 0, total_bytes_freed: 0, categories: Vec::new(), errors: Vec::new(), duration_ms: 0 }
    }

    pub fn add_category(&mut self, name: &str, files: u64, bytes: u64) {
        self.total_files_deleted += files;
        self.total_bytes_freed += bytes;
        self.categories.push(CategoryReport { name: name.into(), files_deleted: files, bytes_freed: bytes });
    }

    pub fn add_error(&mut self, error: String) { self.errors.push(error); }

    pub fn render_text(&self) -> String {
        let mut lines = vec![
            format!("=== Cleanup Report ==="),
            format!("Generated: {}", self.generated_at.format("%Y-%m-%d %H:%M:%S")),
            format!("Duration: {}ms", self.duration_ms),
            format!("Total files: {}", self.total_files_deleted),
            format!("Total freed: {} MB", self.total_bytes_freed / 1_000_000),
            String::new(),
        ];
        for cat in &self.categories {
            lines.push(format!("  {}: {} files, {} MB", cat.name, cat.files_deleted, cat.bytes_freed / 1_000_000));
        }
        if !self.errors.is_empty() {
            lines.push(String::new());
            lines.push("Errors:".into());
            for e in &self.errors { lines.push(format!("  - {e}")); }
        }
        lines.join("\n")
    }

    pub fn render_json(&self) -> String { serde_json::to_string_pretty(self).unwrap_or_default() }

    pub fn success(&self) -> bool { self.errors.is_empty() }
}

impl Default for CleanupReport { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_aggregation() {
        let mut report = CleanupReport::new();
        report.add_category("browser", 100, 50_000_000);
        report.add_category("system", 50, 200_000_000);
        assert_eq!(report.total_files_deleted, 150);
        assert_eq!(report.total_bytes_freed, 250_000_000);
        assert!(report.success());
    }

    #[test]
    fn test_text_rendering() {
        let mut report = CleanupReport::new();
        report.add_category("test", 10, 1_000_000);
        let text = report.render_text();
        assert!(text.contains("test"));
        assert!(text.contains("10"));
    }

    #[test]
    fn test_json_roundtrip() {
        let mut report = CleanupReport::new();
        report.add_category("cache", 5, 500);
        let json = report.render_json();
        let parsed: CleanupReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_files_deleted, 5);
    }

    #[test]
    fn test_errors_mark_failure() {
        let mut report = CleanupReport::new();
        report.add_error("permission denied".into());
        assert!(!report.success());
    }
}
