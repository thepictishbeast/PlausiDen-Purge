//! Duplicate file finder — identifies content-identical files via BLAKE3.
//!
//! Uses a two-pass algorithm: first groups files by size (cheap), then
//! hashes only the size-colliding files (avoids hashing everything).
//! Excludes symlinks, empty files, and files below a configurable minimum size.

use plausiden_purge::error::{PurgeError, Result};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Finds duplicate files by content hash.
pub struct DuplicateFinder {
    /// Skip files smaller than this threshold.
    min_size_bytes: u64,
}

/// A group of files that share identical content.
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    /// BLAKE3 content hash (hex-encoded).
    pub hash: String,
    /// File size in bytes (all files in the group share this size).
    pub size: u64,
    /// All paths with this exact content.
    pub paths: Vec<PathBuf>,
    /// Wasted bytes: `(count - 1) * size`.
    pub wasted_bytes: u64,
}

/// Summary of a duplicate scan.
#[derive(Debug, Clone)]
pub struct DuplicateReport {
    /// Total regular files examined.
    pub total_files_scanned: u64,
    /// Total bytes across all scanned files.
    pub total_bytes_scanned: u64,
    /// Groups where two or more files share content.
    pub duplicate_groups: Vec<DuplicateGroup>,
    /// Sum of `wasted_bytes` across all groups.
    pub total_wasted_bytes: u64,
    /// Wall-clock scan time in milliseconds.
    pub scan_duration_ms: u64,
}

impl DuplicateFinder {
    /// Create a finder that skips files below `min_size_bytes`.
    pub fn new(min_size_bytes: u64) -> Self {
        Self { min_size_bytes }
    }

    /// Scan one or more root paths for duplicate files.
    pub fn scan(&self, roots: &[&Path]) -> Result<DuplicateReport> {
        let start = std::time::Instant::now();

        // ---- Pass 1: group by file size ----
        let mut size_map: HashMap<u64, Vec<PathBuf>> = HashMap::new();
        let mut total_files_scanned = 0u64;
        let mut total_bytes_scanned = 0u64;

        for root in roots {
            if !root.exists() {
                return Err(PurgeError::PathNotFound(
                    root.to_string_lossy().to_string(),
                ));
            }

            for entry in WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                // Skip directories, symlinks, and empty / too-small files.
                if !meta.is_file() || meta.len() == 0 || meta.len() < self.min_size_bytes {
                    continue;
                }

                total_files_scanned += 1;
                total_bytes_scanned += meta.len();

                size_map
                    .entry(meta.len())
                    .or_default()
                    .push(entry.into_path());
            }
        }

        // ---- Pass 2: hash files that share a size ----
        let mut duplicate_groups: Vec<DuplicateGroup> = Vec::new();
        let mut total_wasted_bytes = 0u64;

        for (size, paths) in &size_map {
            if paths.len() < 2 {
                continue; // unique size — no possible duplicate
            }

            let mut hash_map: HashMap<String, Vec<PathBuf>> = HashMap::new();
            for path in paths {
                match blake3_hash(path) {
                    Ok(h) => hash_map.entry(h).or_default().push(path.clone()),
                    Err(_) => continue, // unreadable file — skip
                }
            }

            for (hash, group_paths) in hash_map {
                if group_paths.len() < 2 {
                    continue;
                }
                let wasted = (group_paths.len() as u64 - 1) * size;
                total_wasted_bytes += wasted;
                duplicate_groups.push(DuplicateGroup {
                    hash,
                    size: *size,
                    paths: group_paths,
                    wasted_bytes: wasted,
                });
            }
        }

        // Biggest waste first.
        duplicate_groups.sort_by(|a, b| b.wasted_bytes.cmp(&a.wasted_bytes));

        Ok(DuplicateReport {
            total_files_scanned,
            total_bytes_scanned,
            duplicate_groups,
            total_wasted_bytes,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Compute the BLAKE3 hash of a file, returned as a hex string.
fn blake3_hash(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).map_err(|e| PurgeError::Io(e.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 16384];
    loop {
        let n = file.read(&mut buf).map_err(|e| PurgeError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs as unix_fs;
    use tempfile::TempDir;

    /// Helper: write `n` files with the same content.
    fn write_copies(dir: &Path, prefix: &str, content: &[u8], count: usize) {
        for i in 0..count {
            fs::write(dir.join(format!("{prefix}_{i}.dat")), content).unwrap();
        }
    }

    #[test]
    fn test_no_duplicates() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), "alpha").unwrap();
        fs::write(dir.path().join("b.txt"), "bravo").unwrap();
        fs::write(dir.path().join("c.txt"), "charlie").unwrap();

        let finder = DuplicateFinder::new(1);
        let report = finder.scan(&[dir.path()]).unwrap();

        assert_eq!(report.total_files_scanned, 3);
        assert!(report.duplicate_groups.is_empty());
        assert_eq!(report.total_wasted_bytes, 0);
    }

    #[test]
    fn test_finds_exact_duplicates() {
        let dir = TempDir::new().unwrap();
        let content = b"duplicate payload here";
        write_copies(dir.path(), "dup", content, 3);
        // one unique file
        fs::write(dir.path().join("unique.txt"), "something else").unwrap();

        let finder = DuplicateFinder::new(1);
        let report = finder.scan(&[dir.path()]).unwrap();

        assert_eq!(report.duplicate_groups.len(), 1);
        let group = &report.duplicate_groups[0];
        assert_eq!(group.paths.len(), 3);
        assert_eq!(group.size, content.len() as u64);
        assert_eq!(group.wasted_bytes, 2 * content.len() as u64);
        assert_eq!(report.total_wasted_bytes, group.wasted_bytes);
    }

    #[test]
    fn test_skips_symlinks_and_empty_files() {
        let dir = TempDir::new().unwrap();
        let content = b"real content";
        // Two identical regular files.
        fs::write(dir.path().join("real_a.dat"), content).unwrap();
        fs::write(dir.path().join("real_b.dat"), content).unwrap();
        // Empty file (must be skipped).
        fs::write(dir.path().join("empty.dat"), b"").unwrap();
        // Symlink (must be skipped because follow_links=false).
        unix_fs::symlink(
            dir.path().join("real_a.dat"),
            dir.path().join("link.dat"),
        )
        .unwrap();

        let finder = DuplicateFinder::new(1);
        let report = finder.scan(&[dir.path()]).unwrap();

        // Only the two real files should be scanned.
        assert_eq!(report.total_files_scanned, 2);
        assert_eq!(report.duplicate_groups.len(), 1);
        assert_eq!(report.duplicate_groups[0].paths.len(), 2);
    }

    #[test]
    fn test_min_size_filter() {
        let dir = TempDir::new().unwrap();
        let small = b"hi"; // 2 bytes
        let big = b"this is a larger payload for dedup testing";
        // Duplicates below threshold.
        write_copies(dir.path(), "small", small, 3);
        // Duplicates above threshold.
        write_copies(dir.path(), "big", big, 2);

        let finder = DuplicateFinder::new(10); // threshold: 10 bytes
        let report = finder.scan(&[dir.path()]).unwrap();

        // Small files should be entirely ignored.
        assert_eq!(report.total_files_scanned, 2);
        assert_eq!(report.duplicate_groups.len(), 1);
        assert_eq!(report.duplicate_groups[0].size, big.len() as u64);
    }

    #[test]
    fn test_same_size_different_content() {
        let dir = TempDir::new().unwrap();
        // Two files with the same length but different content.
        fs::write(dir.path().join("a.dat"), "aaaa").unwrap();
        fs::write(dir.path().join("b.dat"), "bbbb").unwrap();
        // And a true duplicate pair.
        fs::write(dir.path().join("c.dat"), "cccc").unwrap();
        fs::write(dir.path().join("d.dat"), "cccc").unwrap();

        let finder = DuplicateFinder::new(1);
        let report = finder.scan(&[dir.path()]).unwrap();

        // All four are scanned (same size, pass 2 needed for all).
        assert_eq!(report.total_files_scanned, 4);
        // Only c/d are actual duplicates.
        assert_eq!(report.duplicate_groups.len(), 1);
        assert_eq!(report.duplicate_groups[0].paths.len(), 2);
    }

    #[test]
    fn test_multiple_duplicate_groups_sorted() {
        let dir = TempDir::new().unwrap();
        let small_content = b"smol"; // 4 bytes, 2 copies => 4 wasted
        let large_content = b"this is much larger content that wastes more"; // 2 copies => 44 wasted

        write_copies(dir.path(), "sm", small_content, 2);
        write_copies(dir.path(), "lg", large_content, 2);

        let finder = DuplicateFinder::new(1);
        let report = finder.scan(&[dir.path()]).unwrap();

        assert_eq!(report.duplicate_groups.len(), 2);
        // Sorted by wasted_bytes descending — large group first.
        assert!(
            report.duplicate_groups[0].wasted_bytes
                >= report.duplicate_groups[1].wasted_bytes
        );
    }

    #[test]
    fn test_nonexistent_root_returns_error() {
        let finder = DuplicateFinder::new(1);
        let result = finder.scan(&[Path::new("/nonexistent/dedup/path/42")]);
        assert!(result.is_err());
    }
}
