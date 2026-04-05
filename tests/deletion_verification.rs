//! Secure deletion verification tests.
//!
//! These tests verify that data is ACTUALLY unrecoverable after erasure.
//! Each test writes known data, applies an erasure algorithm, then reads
//! back to confirm the original content is destroyed.

use plausiden_purge::algorithms::{
    ErasureAlgorithm, PassPattern, execute_pass, recommend_algorithm, scrub_ram,
};
use plausiden_purge::shredder::Shredder;

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a temp directory with a file of known content, return (dir, path, size).
fn make_file(content: &[u8]) -> (TempDir, std::path::PathBuf, u64) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("target.bin");
    fs::write(&path, content).expect("write target file");
    let size = content.len() as u64;
    (dir, path, size)
}

/// Create a temp directory with a file filled with a repeating byte pattern.
fn make_patterned_file(byte: u8, size: usize) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("pattern.bin");
    let data = vec![byte; size];
    fs::write(&path, &data).expect("write patterned file");
    (dir, path)
}

// ---------------------------------------------------------------------------
// 1. Zero fill verification
// ---------------------------------------------------------------------------

/// Write known data, zero-fill, read back, verify no original bytes remain.
#[test]
fn test_zero_fill_verification() {
    let known_data = b"TOP SECRET: launch codes alpha-7 bravo-9 charlie-3";
    let (_dir, path, size) = make_file(known_data);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open file");

    execute_pass(&mut file, size, &PassPattern::Fixed(0x00)).expect("zero fill");

    // Read back entire file.
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = vec![0u8; size as usize];
    file.read_exact(&mut readback).expect("read back");

    // Every byte must be zero.
    assert!(
        readback.iter().all(|&b| b == 0x00),
        "all bytes must be zero after zero-fill"
    );

    // No original byte should survive.
    for &original_byte in known_data {
        if original_byte != 0x00 {
            assert!(
                !readback.contains(&original_byte),
                "original byte 0x{original_byte:02X} must not appear in zeroed file"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Random overwrite verification
// ---------------------------------------------------------------------------

/// Write a recognizable pattern, random overwrite, verify pattern is gone.
#[test]
fn test_random_overwrite_verification() {
    // Fill with 0xAA so we can detect if any survive.
    let pattern_byte = 0xAA;
    let file_size = 4096usize;
    let (_dir, path) = make_patterned_file(pattern_byte, file_size);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open file");

    execute_pass(&mut file, file_size as u64, &PassPattern::Random).expect("random overwrite");

    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = vec![0u8; file_size];
    file.read_exact(&mut readback).expect("read back");

    // The file should NOT be all 0xAA anymore.
    let aa_count = readback.iter().filter(|&&b| b == pattern_byte).count();
    // Statistically, ~1/256 bytes could be 0xAA by chance. For 4096 bytes
    // that's ~16. If more than 5% survived, something is wrong.
    let threshold = file_size / 20;
    assert!(
        aa_count < threshold,
        "too many original 0xAA bytes survived: {aa_count}/{file_size} (threshold {threshold})"
    );

    // Also confirm the data actually changed.
    let original = vec![pattern_byte; file_size];
    assert_ne!(readback, original, "file content must differ after random overwrite");
}

// ---------------------------------------------------------------------------
// 3. Crypto erase verification
// ---------------------------------------------------------------------------

/// Write data, crypto-erase, verify only zeros remain (crypto erase ends
/// with a zero pass for defense in depth).
#[test]
fn test_crypto_erase_verification() {
    let sensitive = b"encryption key: 0xDEADBEEF_CAFEBABE_1337_FEED";
    let (_dir, path, size) = make_file(sensitive);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open file");

    execute_pass(&mut file, size, &PassPattern::CryptoErase).expect("crypto erase");

    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = vec![0u8; size as usize];
    file.read_exact(&mut readback).expect("read back");

    // After crypto erase + final zero pass, everything must be 0x00.
    assert!(
        readback.iter().all(|&b| b == 0x00),
        "all bytes must be zero after crypto erasure (which includes a final zero pass)"
    );

    // The original plaintext must not survive.
    let window_size = 8; // check 8-byte windows from original
    for window in sensitive.windows(window_size) {
        for file_window in readback.windows(window_size) {
            assert_ne!(
                window, file_window,
                "original data window found in erased file"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Multi-pass verification (3-pass NIST)
// ---------------------------------------------------------------------------

/// NIST 800-88: 3 passes (zeros, ones, random). Verify each pass changed data.
#[test]
fn test_multi_pass_nist_verification() {
    let original_data = vec![0x42u8; 2048];
    let (_dir, path, size) = make_file(&original_data);

    let patterns = ErasureAlgorithm::Nist80088.patterns();
    assert_eq!(patterns.len(), 3, "NIST 800-88 must have exactly 3 passes");

    let mut previous_content = original_data.clone();

    for (pass_idx, pattern) in patterns.iter().enumerate() {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open file");

        execute_pass(&mut file, size, pattern).expect("execute pass");

        file.seek(SeekFrom::Start(0)).expect("seek");
        let mut current_content = vec![0u8; size as usize];
        file.read_exact(&mut current_content).expect("read back");

        assert_ne!(
            current_content, previous_content,
            "pass {} must change the file content",
            pass_idx + 1
        );

        // Pass 1 (index 0): should be all zeros.
        if pass_idx == 0 {
            assert!(
                current_content.iter().all(|&b| b == 0x00),
                "pass 1 must write all zeros"
            );
        }
        // Pass 2 (index 1): should be all 0xFF.
        if pass_idx == 1 {
            assert!(
                current_content.iter().all(|&b| b == 0xFF),
                "pass 2 must write all 0xFF"
            );
        }
        // Pass 3 (index 2): random — just verify it's not all 0xFF.
        if pass_idx == 2 {
            let all_ff = current_content.iter().all(|&b| b == 0xFF);
            assert!(!all_ff, "pass 3 (random) should not be identical to pass 2");
        }

        previous_content = current_content;
    }
}

// ---------------------------------------------------------------------------
// 5. File metadata cleared
// ---------------------------------------------------------------------------

/// After shredding, verify the original filename is gone from directory listing.
#[test]
fn test_file_metadata_cleared() {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("classified_document.txt");
    fs::write(&path, "CLASSIFIED: eyes only").expect("write file");

    assert!(path.exists(), "file must exist before shred");

    let shredder = Shredder::new().with_algorithm(ErasureAlgorithm::ZeroFill);
    shredder.shred_file(&path).expect("shred file");

    // The original filename must not appear in the directory listing.
    assert!(!path.exists(), "original path must be gone");

    let entries: Vec<String> = fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    for entry in &entries {
        assert!(
            !entry.contains("classified_document"),
            "original filename must not appear in directory listing, found: {entry}"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Large file shredding
// ---------------------------------------------------------------------------

/// 10 MB file, shred with NIST, verify correct pass count executed via progress.
#[test]
fn test_large_file_shredding() {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("large_file.bin");

    // Write 10 MB of 0x55.
    let ten_mb = 10 * 1024 * 1024;
    let data = vec![0x55u8; ten_mb];
    fs::write(&path, &data).expect("write 10 MB file");

    let pass_counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let counter = pass_counter.clone();

    let shredder = Shredder::new()
        .with_algorithm(ErasureAlgorithm::Nist80088)
        .with_verify(false); // skip verify for speed on large file

    let result = shredder
        .shred_with_progress(&path, move |p| {
            // Track the highest pass number seen.
            counter.fetch_max(p.current_pass, std::sync::atomic::Ordering::SeqCst);
        })
        .expect("shred 10 MB file");

    // NIST = 3 passes.
    let max_pass = pass_counter.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(max_pass, 3, "NIST 800-88 must execute exactly 3 passes");

    assert_eq!(result.files_deleted, 1);
    assert_eq!(result.bytes_freed, ten_mb as u64);
    assert!(!path.exists(), "10 MB file must be deleted");
}

// ---------------------------------------------------------------------------
// 7. Concurrent shredding
// ---------------------------------------------------------------------------

/// Shred 5 files simultaneously, verify all are deleted.
#[test]
fn test_concurrent_shredding() {
    let dir = TempDir::new().expect("create temp dir");
    let file_count = 5;
    let mut paths = Vec::with_capacity(file_count);

    for i in 0..file_count {
        let p = dir.path().join(format!("concurrent_{i}.bin"));
        fs::write(&p, format!("concurrent test data file number {i}")).expect("write file");
        paths.push(p);
    }

    // Shred all files in parallel using std threads.
    let handles: Vec<_> = paths
        .iter()
        .map(|p| {
            let path = p.clone();
            std::thread::spawn(move || {
                let shredder = Shredder::new()
                    .with_algorithm(ErasureAlgorithm::ZeroFill)
                    .with_verify(false);
                shredder.shred_file(&path).expect("shred file in thread");
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread must not panic");
    }

    // Verify all files are gone.
    for p in &paths {
        assert!(!p.exists(), "file {} must be deleted", p.display());
    }

    // Verify no original filenames remain in the directory.
    let remaining: Vec<String> = fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    for entry in &remaining {
        assert!(
            !entry.starts_with("concurrent_"),
            "original filename should not remain: {entry}"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. Backfill verification
// ---------------------------------------------------------------------------

/// Shred with backfill enabled, verify a new backfill file exists with
/// different content than the original.
#[test]
fn test_backfill_verification() {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("backfill_target.bin");
    let original = b"data to be replaced by synthetic backfill content";
    fs::write(&path, original).expect("write original");

    let shredder = Shredder::new()
        .with_algorithm(ErasureAlgorithm::ZeroFill)
        .with_backfill(true);

    let result = shredder.shred_file(&path).expect("shred with backfill");

    assert!(!path.exists(), "original file must be gone");
    assert!(result.verification_passed);

    // Find the backfill file.
    let backfill_entries: Vec<_> = fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(".backfill_"))
        })
        .collect();

    assert_eq!(
        backfill_entries.len(),
        1,
        "exactly one backfill file expected"
    );

    // Verify the backfill file exists and has the same size.
    let bf_meta = backfill_entries[0].metadata().expect("backfill metadata");
    assert_eq!(
        bf_meta.len(),
        original.len() as u64,
        "backfill size must match original"
    );

    // Verify backfill content differs from original.
    let bf_content = fs::read(backfill_entries[0].path()).expect("read backfill");
    assert_ne!(
        bf_content,
        original.to_vec(),
        "backfill content must differ from original"
    );
}

// ---------------------------------------------------------------------------
// 9. Algorithm recommendation
// ---------------------------------------------------------------------------

/// SSD path should recommend crypto erasure; HDD/unknown should recommend NIST.
/// Since we can't control the underlying storage in CI, we test the function
/// returns valid algorithms and verify tmpdir defaults to NIST (no rotational
/// sysfs entry for tmpfs/overlayfs).
#[test]
fn test_algorithm_recommendation() {
    // /tmp is typically tmpfs — no rotational info available, so default = NIST.
    let algo = recommend_algorithm(Path::new("/tmp"));
    let patterns = algo.patterns();
    assert!(!patterns.is_empty(), "recommended algorithm must have passes");

    // On a machine where /tmp is not on a real disk (tmpfs), we expect NIST
    // (the default for unknown storage). On an SSD it would be CryptoErasure.
    // Both are valid — the key property is that SSDs should never get a
    // multi-pass overwrite-only algorithm.
    match algo {
        ErasureAlgorithm::Nist80088 => {
            // Expected for tmpfs/unknown storage.
            assert_eq!(patterns.len(), 3);
        }
        ErasureAlgorithm::CryptographicErasure => {
            // Expected if /tmp is on an SSD.
            assert_eq!(patterns.len(), 1);
        }
        other => {
            panic!("unexpected recommendation for /tmp: {other}");
        }
    }

    // Verify that the algorithm enum includes both the SSD and HDD options.
    let ssd_patterns = ErasureAlgorithm::CryptographicErasure.patterns();
    assert_eq!(ssd_patterns.len(), 1, "CryptoErasure must have 1 pass");
    assert!(
        matches!(ssd_patterns[0], PassPattern::CryptoErase),
        "CryptoErasure pass must be CryptoErase"
    );

    let hdd_patterns = ErasureAlgorithm::Nist80088.patterns();
    assert_eq!(hdd_patterns.len(), 3, "NIST must have 3 passes");
}

// ---------------------------------------------------------------------------
// 10. RAM scrub doesn't crash
// ---------------------------------------------------------------------------

/// Scrub 10 MB of RAM, verify the function completes without panicking.
#[test]
fn test_ram_scrub_completes() {
    // scrub_ram allocates and overwrites the specified MB count.
    // 10 MB is small enough to be fast, large enough to be meaningful.
    let result = scrub_ram(10);
    assert!(result.is_ok(), "scrub_ram(10) must succeed: {:?}", result.err());
}
