//! High-level secure file deletion API.
//!
//! Integrates all erasure algorithms from [`algorithms`] into a polished
//! interface with storage-type detection, progress reporting, deletion
//! verification, optional synthetic-data backfill, and audit logging.

use crate::algorithms::{self, ErasureAlgorithm, PassPattern};
use crate::error::{PurgeError, Result};
use crate::safety::{safe_open_rw, safe_symlink_metadata};

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Display for ErasureAlgorithm (needed by ShredResult formatting)
// ---------------------------------------------------------------------------

impl fmt::Display for ErasureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroFill => write!(f, "ZeroFill"),
            Self::Nist80088 => write!(f, "NIST 800-88"),
            Self::Dod522022M => write!(f, "DoD 5220.22-M"),
            Self::Gutmann35 => write!(f, "Gutmann 35-pass"),
            Self::CryptographicErasure => write!(f, "Cryptographic Erasure"),
            Self::RandomPasses(n) => write!(f, "Random ({n} passes)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Storage detection
// ---------------------------------------------------------------------------

/// Detected storage medium type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    Ssd,
    Hdd,
    Unknown,
}

impl fmt::Display for StorageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssd => write!(f, "SSD/NVMe"),
            Self::Hdd => write!(f, "HDD"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detect whether `path` resides on an SSD or HDD.
pub fn detect_storage_type(path: &Path) -> StorageType {
    #[cfg(target_os = "linux")]
    {
        if let Some(device) = linux_block_device(path) {
            let rotational = format!("/sys/block/{device}/queue/rotational");
            if let Ok(val) = fs::read_to_string(&rotational) {
                return match val.trim() {
                    "0" => StorageType::Ssd,
                    "1" => StorageType::Hdd,
                    _ => StorageType::Unknown,
                };
            }
        }
    }
    let _ = path; // suppress unused-variable warning on non-Linux
    StorageType::Unknown
}

/// Extract the base block device name for a path (Linux only).
#[cfg(target_os = "linux")]
fn linux_block_device(path: &Path) -> Option<String> {
    use std::process::Command;
    let output = Command::new("df")
        .arg("--output=source")
        .arg(path)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let device = text.lines().nth(1)?.trim();
    let dev_name = device.strip_prefix("/dev/")?;
    let base = dev_name.trim_end_matches(|c: char| c.is_ascii_digit());
    let base = base.trim_end_matches('p');
    Some(base.to_string())
}

// ---------------------------------------------------------------------------
// Progress callback
// ---------------------------------------------------------------------------

/// Progress update delivered to the caller during multi-pass operations.
#[derive(Debug, Clone)]
pub struct ShredProgress {
    /// Current pass (1-based).
    pub current_pass: u32,
    /// Total passes for the chosen algorithm.
    pub total_passes: u32,
    /// Bytes written so far in the current pass.
    pub bytes_written: u64,
    /// Total bytes per pass (i.e. file size).
    pub bytes_total: u64,
    /// File currently being processed.
    pub current_file: PathBuf,
}

impl ShredProgress {
    /// Overall percentage across all passes (0.0 .. 100.0).
    pub fn overall_percent(&self) -> f64 {
        if self.total_passes == 0 || self.bytes_total == 0 {
            return 0.0;
        }
        let pass_frac = self.bytes_written as f64 / self.bytes_total as f64;
        let completed = (self.current_pass - 1) as f64 + pass_frac;
        (completed / self.total_passes as f64) * 100.0
    }
}

// ---------------------------------------------------------------------------
// Dry-run result
// ---------------------------------------------------------------------------

/// Describes what *would* happen without actually deleting anything.
#[derive(Debug, Clone)]
pub struct DryRunResult {
    /// Files that would be deleted.
    pub files: Vec<PathBuf>,
    /// Total bytes that would be freed.
    pub total_bytes: u64,
    /// Algorithm that would be used.
    pub algorithm: ErasureAlgorithm,
    /// Detected storage type.
    pub storage_type: StorageType,
    /// Estimated wall-clock milliseconds (rough heuristic).
    pub estimated_ms: u64,
}

// ---------------------------------------------------------------------------
// Audit log entry
// ---------------------------------------------------------------------------

/// A single audit record emitted for every shred operation.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub path: PathBuf,
    pub algorithm: ErasureAlgorithm,
    pub bytes: u64,
    pub verification_passed: bool,
    pub duration_ms: u64,
}

impl fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] SHRED {} | algo={} bytes={} verified={} duration={}ms",
            self.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
            self.path.display(),
            self.algorithm,
            self.bytes,
            self.verification_passed,
            self.duration_ms,
        )
    }
}

// ---------------------------------------------------------------------------
// ShredResult
// ---------------------------------------------------------------------------

/// Outcome of a shred operation.
#[derive(Debug, Clone)]
pub struct ShredResult {
    pub files_deleted: u32,
    pub bytes_freed: u64,
    pub algorithm_used: ErasureAlgorithm,
    pub verification_passed: bool,
    pub duration_ms: u64,
    pub audit_log: Vec<AuditEntry>,
}

// ---------------------------------------------------------------------------
// Shredder
// ---------------------------------------------------------------------------

/// High-level secure file deletion engine.
///
/// Combines storage detection, algorithm selection, progress callbacks,
/// post-deletion verification, optional backfill, and audit logging.
pub struct Shredder {
    /// Erasure algorithm override. `None` means auto-detect per storage type.
    algorithm: Option<ErasureAlgorithm>,
    /// Whether to read-back and verify after each pass.
    verify: bool,
    /// Whether to backfill freed space with synthetic data.
    backfill: bool,
}

impl Shredder {
    /// Create a new `Shredder` that auto-detects algorithm, verifies, and
    /// does not backfill.
    pub fn new() -> Self {
        Self {
            algorithm: None,
            verify: true,
            backfill: false,
        }
    }

    /// Force a specific erasure algorithm instead of auto-detecting.
    pub fn with_algorithm(mut self, algo: ErasureAlgorithm) -> Self {
        self.algorithm = Some(algo);
        self
    }

    /// Enable or disable post-write verification.
    pub fn with_verify(mut self, yes: bool) -> Self {
        self.verify = yes;
        self
    }

    /// Enable or disable synthetic-data backfill of freed space.
    pub fn with_backfill(mut self, yes: bool) -> Self {
        self.backfill = yes;
        self
    }

    // -- public API --------------------------------------------------------

    /// Securely shred a single file.
    pub fn shred_file(&self, path: &Path) -> Result<ShredResult> {
        self.shred_with_progress(path, |_| {})
    }

    /// Securely shred all files inside a directory (recursively).
    pub fn shred_directory(&self, path: &Path) -> Result<ShredResult> {
        if !path.exists() {
            return Err(PurgeError::PathNotFound(path.display().to_string()));
        }
        if !path.is_dir() {
            return self.shred_file(path);
        }

        let start = Instant::now();
        let mut total_files = 0u32;
        let mut total_bytes = 0u64;
        let mut all_verified = true;
        let mut audit_log = Vec::new();

        let algo = self.pick_algorithm(path);

        // Walk depth-first so children are deleted before parents.
        for entry in walkdir::WalkDir::new(path)
            .contents_first(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let res = self.shred_single_file(entry.path(), algo, |_| {})?;
                total_files += 1;
                total_bytes += res.bytes_freed;
                if !res.verification_passed {
                    all_verified = false;
                }
                audit_log.extend(res.audit_log);
            } else if entry.file_type().is_dir() && entry.path() != path {
                fs::remove_dir(entry.path())
                    .map_err(|e| PurgeError::Io(e.to_string()))?;
            }
        }

        fs::remove_dir(path).map_err(|e| PurgeError::Io(e.to_string()))?;

        Ok(ShredResult {
            files_deleted: total_files,
            bytes_freed: total_bytes,
            algorithm_used: algo,
            verification_passed: all_verified,
            duration_ms: start.elapsed().as_millis() as u64,
            audit_log,
        })
    }

    /// Shred a file (or directory) with a progress callback invoked after
    /// each 64 KiB chunk.
    pub fn shred_with_progress<F>(&self, path: &Path, progress: F) -> Result<ShredResult>
    where
        F: Fn(&ShredProgress),
    {
        if !path.exists() {
            return Err(PurgeError::PathNotFound(path.display().to_string()));
        }
        if path.is_dir() {
            // For directories we still go through shred_directory (progress
            // is per-file in that case).
            return self.shred_directory(path);
        }

        let algo = self.pick_algorithm(path);
        self.shred_single_file(path, algo, progress)
    }

    /// Preview what would happen without touching anything.
    pub fn dry_run(&self, path: &Path) -> Result<DryRunResult> {
        if !path.exists() {
            return Err(PurgeError::PathNotFound(path.display().to_string()));
        }

        let storage_type = detect_storage_type(path);
        let algo = self.pick_algorithm(path);

        let mut files = Vec::new();
        let mut total_bytes = 0u64;

        if path.is_dir() {
            for entry in walkdir::WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    if let Ok(meta) = entry.metadata() {
                        total_bytes += meta.len();
                    }
                    files.push(entry.into_path());
                }
            }
        } else {
            let meta = fs::metadata(path).map_err(|e| PurgeError::Io(e.to_string()))?;
            total_bytes = meta.len();
            files.push(path.to_path_buf());
        }

        // Rough estimate: 200 MB/s sequential write speed.
        let write_speed_bytes_per_sec: f64 = 200.0 * 1024.0 * 1024.0;
        let raw_ms =
            (total_bytes as f64 / write_speed_bytes_per_sec) * algo.time_multiplier() * 1000.0;

        Ok(DryRunResult {
            files,
            total_bytes,
            algorithm: algo,
            storage_type,
            estimated_ms: raw_ms as u64,
        })
    }

    // -- internals ---------------------------------------------------------

    /// Choose algorithm: explicit override, or auto-detect from storage type.
    fn pick_algorithm(&self, path: &Path) -> ErasureAlgorithm {
        if let Some(algo) = self.algorithm {
            return algo;
        }
        algorithms::recommend_algorithm(path)
    }

    /// Shred a single regular file with progress callback.
    fn shred_single_file<F>(
        &self,
        path: &Path,
        algo: ErasureAlgorithm,
        progress: F,
    ) -> Result<ShredResult>
    where
        F: Fn(&ShredProgress),
    {
        let start = Instant::now();
        // SECURITY: reject symlinks/devices/fifos/sockets up front
        // via the shared safe_symlink_metadata helper. The earlier
        // version used fs::metadata which follows symlinks and had
        // no file-type check.
        let meta = safe_symlink_metadata(path)?;
        let file_size = meta.len();

        let patterns = algo.patterns();
        let total_passes = patterns.len() as u32;

        // SECURITY: open with O_NOFOLLOW + fstat + exclusive flock
        // via the shared safe_open_rw helper so the TOCTOU window
        // between check and open cannot be exploited.
        let mut file = safe_open_rw(path)?;

        let mut verified = true;

        for (idx, pattern) in patterns.iter().enumerate() {
            let pass_num = idx as u32 + 1;

            // Execute the pass through algorithms::execute_pass.
            algorithms::execute_pass(&mut file, file_size, pattern)?;

            // Verification for verifiable patterns when requested.
            if self.verify {
                if let PassPattern::FixedVerified(byte) = pattern {
                    file.seek(SeekFrom::Start(0))
                        .map_err(|e| PurgeError::Io(e.to_string()))?;
                    if let Err(_) = verify_byte(&mut file, file_size, *byte) {
                        verified = false;
                    }
                }
                if let PassPattern::Fixed(byte) = pattern {
                    file.seek(SeekFrom::Start(0))
                        .map_err(|e| PurgeError::Io(e.to_string()))?;
                    if let Err(_) = verify_byte(&mut file, file_size, *byte) {
                        verified = false;
                    }
                }
            }

            // Report progress after each complete pass.
            progress(&ShredProgress {
                current_pass: pass_num,
                total_passes,
                bytes_written: file_size,
                bytes_total: file_size,
                current_file: path.to_path_buf(),
            });
        }

        drop(file);

        // Truncate, random-rename, unlink (same as destroyer.rs).
        // Truncation reuses safe_open_rw for the same AVP-2 safety
        // gates; any race between the final pass's drop and this
        // reopen is caught by O_NOFOLLOW + fstat.
        let trunc = safe_open_rw(path)?;
        trunc.set_len(0).map_err(|e| PurgeError::Io(e.to_string()))?;
        drop(trunc);

        let parent = path.parent().unwrap_or(Path::new("."));
        let random_name = {
            use rand::RngCore;
            let val = rand::rngs::OsRng.next_u64();
            format!(".purge_{val:016x}")
        };
        let renamed = parent.join(&random_name);
        fs::rename(path, &renamed).map_err(|e| PurgeError::Io(e.to_string()))?;
        fs::remove_file(&renamed).map_err(|e| PurgeError::Io(e.to_string()))?;

        // Backfill freed space with synthetic data if requested.
        if self.backfill {
            backfill_synthetic(parent, file_size)?;
        }

        // Verify the original path is truly gone.
        if path.exists() {
            verified = false;
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        let audit = AuditEntry {
            timestamp: chrono::Utc::now(),
            path: path.to_path_buf(),
            algorithm: algo,
            bytes: file_size,
            verification_passed: verified,
            duration_ms,
        };
        tracing::info!("{audit}");

        Ok(ShredResult {
            files_deleted: 1,
            bytes_freed: file_size,
            algorithm_used: algo,
            verification_passed: verified,
            duration_ms,
            audit_log: vec![audit],
        })
    }
}

impl Default for Shredder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read-back verification: every byte must equal `expected`.
fn verify_byte(file: &mut File, size: u64, expected: u8) -> Result<()> {
    use std::io::Read;
    let chunk_size = 65536usize;
    let mut buf = vec![0u8; chunk_size];
    let mut read_total = 0u64;

    file.seek(SeekFrom::Start(0))
        .map_err(|e| PurgeError::Io(e.to_string()))?;

    while read_total < size {
        let to_read = chunk_size.min((size - read_total) as usize);
        file.read_exact(&mut buf[..to_read])
            .map_err(|e| PurgeError::Io(e.to_string()))?;
        for (i, &b) in buf[..to_read].iter().enumerate() {
            if b != expected {
                return Err(PurgeError::VerificationFailed {
                    offset: read_total + i as u64,
                    expected,
                    found: b,
                });
            }
        }
        read_total += to_read as u64;
    }
    Ok(())
}

/// Write a synthetic placeholder file into `dir` so the freed sectors are not
/// left zeroed. The file is named `.backfill_<random>` and filled with
/// pseudorandom bytes derived from blake3.
fn backfill_synthetic(dir: &Path, size: u64) -> Result<()> {
    use rand::RngCore;

    let name = {
        let val = rand::rngs::OsRng.next_u64();
        format!(".backfill_{val:016x}")
    };
    let fill_path = dir.join(name);

    let mut file = File::create(&fill_path).map_err(|e| PurgeError::Io(e.to_string()))?;
    let chunk_size = 65536usize;
    let mut buf = vec![0u8; chunk_size];
    let mut written = 0u64;

    // Use blake3 keyed output as a fast PRNG stream.
    let seed = {
        let mut s = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut s);
        s
    };

    while written < size {
        let to_write = chunk_size.min((size - written) as usize);
        let hash_input = [seed.as_slice(), &written.to_le_bytes()].concat();
        let hash = blake3::hash(&hash_input);
        for (i, byte) in buf[..to_write].iter_mut().enumerate() {
            *byte = hash.as_bytes()[i % 32];
        }
        std::io::Write::write_all(&mut file, &buf[..to_write])
            .map_err(|e| PurgeError::Io(e.to_string()))?;
        written += to_write as u64;
    }

    file.sync_all().map_err(|e| PurgeError::Io(e.to_string()))?;
    tracing::debug!("Backfill written: {}", fill_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: create a temp directory with a single file of known content.
    fn temp_file(content: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("target.bin");
        fs::write(&file_path, content).unwrap();
        (dir, file_path)
    }

    /// Helper: create a temp directory tree with several files.
    fn temp_tree() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();
        fs::write(dir.path().join("a.txt"), "alpha").unwrap();
        fs::write(dir.path().join("b.txt"), "bravo").unwrap();
        fs::write(sub.join("c.txt"), "charlie").unwrap();
        // Return a new path to a sub-tree so TempDir itself is not deleted.
        let target = dir.path().join("tree");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("x.txt"), "x-data-content").unwrap();
        fs::write(target.join("y.txt"), "y-data-content").unwrap();
        let inner = target.join("inner");
        fs::create_dir(&inner).unwrap();
        fs::write(inner.join("z.txt"), "z-data-content").unwrap();
        (dir, target)
    }

    // -- 1. shred_file with ZeroFill algorithm ----------------------------

    #[test]
    fn test_shred_file_zero_fill() {
        let (_dir, path) = temp_file(b"sensitive data that must be destroyed completely");

        let shredder = Shredder::new().with_algorithm(ErasureAlgorithm::ZeroFill);
        let result = shredder.shred_file(&path).unwrap();

        assert_eq!(result.files_deleted, 1);
        assert!(result.bytes_freed > 0);
        assert_eq!(result.algorithm_used, ErasureAlgorithm::ZeroFill);
        assert!(result.verification_passed);
        assert!(!path.exists(), "file must be gone after shred");
    }

    // -- 2. shred_directory recursively -----------------------------------

    #[test]
    fn test_shred_directory() {
        let (_dir, tree) = temp_tree();

        let shredder = Shredder::new()
            .with_algorithm(ErasureAlgorithm::ZeroFill)
            .with_verify(false);
        let result = shredder.shred_directory(&tree).unwrap();

        assert_eq!(result.files_deleted, 3); // x.txt, y.txt, inner/z.txt
        assert!(result.bytes_freed > 0);
        assert!(!tree.exists(), "directory must be gone after shred");
    }

    // -- 3. shred_with_progress callback fires ----------------------------

    #[test]
    fn test_shred_with_progress() {
        let (_dir, path) = temp_file(b"progress callback test data");

        let progress_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = progress_count.clone();

        let shredder = Shredder::new().with_algorithm(ErasureAlgorithm::Nist80088);
        let result = shredder
            .shred_with_progress(&path, move |p| {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert!(p.current_pass <= p.total_passes);
                assert!(p.overall_percent() >= 0.0);
                assert!(p.overall_percent() <= 100.0);
            })
            .unwrap();

        // NIST 800-88 has 3 passes, so callback should fire 3 times.
        assert_eq!(progress_count.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(result.algorithm_used, ErasureAlgorithm::Nist80088);
        assert!(result.verification_passed);
    }

    // -- 4. dry_run returns correct metadata without deleting -------------

    #[test]
    fn test_dry_run_does_not_delete() {
        let (_dir, path) = temp_file(b"dry run test data that must survive");

        let shredder = Shredder::new().with_algorithm(ErasureAlgorithm::Gutmann35);
        let preview = shredder.dry_run(&path).unwrap();

        assert_eq!(preview.files.len(), 1);
        assert_eq!(preview.total_bytes, 35); // len of content above
        assert_eq!(preview.algorithm, ErasureAlgorithm::Gutmann35);
        // Tiny file: estimate may round to 0 ms, so just check it's non-negative (always true for u64).
        assert!(path.exists(), "dry_run must NOT delete the file");
    }

    // -- 5. backfill writes synthetic data into the parent directory ------

    #[test]
    fn test_shred_with_backfill() {
        let (dir, path) = temp_file(b"backfill me with synthetic data please");

        let shredder = Shredder::new()
            .with_algorithm(ErasureAlgorithm::ZeroFill)
            .with_backfill(true);
        let result = shredder.shred_file(&path).unwrap();

        assert!(result.verification_passed);
        assert!(!path.exists());

        // Verify a backfill file was created in the same directory.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(".backfill_"))
            })
            .collect();

        assert_eq!(entries.len(), 1, "exactly one backfill file expected");
        let bf_size = entries[0].metadata().unwrap().len();
        assert_eq!(bf_size, result.bytes_freed, "backfill size must match freed bytes");
    }

    // -- 6. shred_file on nonexistent path returns error ------------------

    #[test]
    fn test_shred_nonexistent_path() {
        let shredder = Shredder::new();
        let result = shredder.shred_file(Path::new("/tmp/_purge_nonexistent_42"));
        assert!(result.is_err());
    }

    // -- 7. audit log entries are populated -------------------------------

    #[test]
    fn test_audit_log_populated() {
        let (_dir, path) = temp_file(b"audit this deletion");

        let shredder = Shredder::new().with_algorithm(ErasureAlgorithm::Nist80088);
        let result = shredder.shred_file(&path).unwrap();

        assert_eq!(result.audit_log.len(), 1);
        let entry = &result.audit_log[0];
        assert_eq!(entry.algorithm, ErasureAlgorithm::Nist80088);
        assert_eq!(entry.bytes, 19);
        assert!(entry.verification_passed);
        assert!(entry.duration_ms < 30_000); // sanity: under 30 s
    }
}
