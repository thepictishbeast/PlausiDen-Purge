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

    if let Ok(entries) = walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()).map(|e| { let s = e.metadata().map(|m| m.len()).unwrap_or(0); let ext = e.path().extension().and_then(|e| e.to_str()).unwrap_or("none").to_lowercase(); (ext, s) }).collect::<Vec<_>>().into_iter().take(10000) {
        *by_category.entry(entries.0).or_default() += entries.1;
        total += entries.1;
    }

    StorageAnalysis { by_category, total_bytes: total }
}
