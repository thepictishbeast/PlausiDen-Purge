//! Storage analyzer — categorizes disk usage by type.

use std::collections::HashMap;
use std::path::Path;

pub struct StorageAnalysis {
    pub by_category: HashMap<String, u64>,
    pub total_bytes: u64,
}

pub fn analyze_directory(path: &Path) -> StorageAnalysis {
    let mut by_category: HashMap<String, u64> = HashMap::new();
    let mut total = 0u64;

    for entry in walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()).take(10000) {
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let ext = entry.path().extension().and_then(|e| e.to_str()).unwrap_or("none").to_lowercase();
        *by_category.entry(ext).or_default() += size;
        total += size;
    }

    StorageAnalysis { by_category, total_bytes: total }
}
