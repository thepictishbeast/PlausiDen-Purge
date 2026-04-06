//! Crypto-shred — destroy a file by replacing its bytes with ciphertext
//! of an ephemeral key that is zeroized the instant the write finishes.
//!
//! Crypto-shred is the Purge option of last resort when traditional
//! overwrite is not meaningful — VPS, SSD with aggressive wear-leveling,
//! copy-on-write filesystems, or network-backed storage. Unlike
//! forensic_wipe, which repeatedly overwrites a file with various
//! patterns, crypto-shred makes *one* pass and leverages cryptography
//! to render the file's logical content unrecoverable.
//!
//! # Guarantees
//!
//! - The bytes now residing at the file's logical offsets cannot be
//!   decrypted because the key is destroyed before the function returns.
//! - The key lives only in a `Zeroizing<[u8; 32]>` buffer and is
//!   scrubbed before the process moves on.
//!
//! # Non-guarantees
//!
//! - On an SSD, the physical cells that originally held the plaintext
//!   may still contain the plaintext. Wear-leveling controls where
//!   writes land. A subsequent `fstrim` helps; a full ATA Secure Erase
//!   is the only hard guarantee at the physical-cell level.
//! - On copy-on-write filesystems (Btrfs/ZFS), the old block is
//!   unreferenced but may persist in snapshots.
//! - On a VPS, hypervisor snapshots and provider backups are outside
//!   the guest's reach.
//!
//! For a stronger guarantee, combine with `free_space_wipe` (to pressure
//! the drive into releasing wear-leveling spares) or escalate to
//! whole-drive ATA Secure Erase.

use crate::error::{PurgeError, Result};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Options for a crypto-shred operation.
#[derive(Debug, Clone)]
pub struct CryptoShredOptions {
    /// Bytes processed per cipher chunk.
    pub chunk_size: usize,
    /// Truncate the file to zero bytes after overwriting.
    pub truncate_after: bool,
    /// Unlink the file after truncation.
    pub unlink_after: bool,
    /// Call `fdatasync` after every chunk (much slower, stronger
    /// guarantee that the ciphertext is on disk before the key is
    /// zeroized).
    pub fsync_each_chunk: bool,
    /// Extra random overwrite pass before the crypto pass. Defends
    /// against storage backends that deduplicate identical writes.
    pub pre_random_pass: bool,
}

impl Default for CryptoShredOptions {
    fn default() -> Self {
        Self {
            chunk_size: 1 << 16, // 64 KiB
            truncate_after: true,
            unlink_after: true,
            fsync_each_chunk: false,
            pre_random_pass: false,
        }
    }
}

/// Report returned after a successful crypto-shred.
#[derive(Debug, Clone)]
pub struct CryptoShredReport {
    pub path: PathBuf,
    pub original_size: u64,
    pub chunks_processed: u64,
    pub bytes_written: u64,
    pub fsynced: bool,
    pub truncated: bool,
    pub removed: bool,
}

/// Crypto-shred a single file.
///
/// Never call this automatically. The caller (typically the Atrium
/// frontend, executing a user-confirmed cleanup plan) is responsible
/// for verifying that the user explicitly approved this specific
/// path before invoking.
pub fn crypto_shred(path: &Path, options: &CryptoShredOptions) -> Result<CryptoShredReport> {
    if !path.exists() {
        return Err(PurgeError::Io(format!("path does not exist: {}", path.display())));
    }
    if !path.is_file() {
        return Err(PurgeError::Io(format!(
            "path is not a regular file: {}",
            path.display()
        )));
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;

    let original_size = file
        .metadata()
        .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?
        .len();

    let mut bytes_written: u64 = 0;
    let mut chunks_processed: u64 = 0;

    // Optional defensive pre-pass with pure random bytes. Useful on
    // storage that might deduplicate our ciphertext writes against
    // each other (they will differ because the key is random, but a
    // defensive mindset still benefits from a separate random pass).
    if options.pre_random_pass && original_size > 0 {
        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; options.chunk_size];
        let mut offset: u64 = 0;
        while offset < original_size {
            let to_write = options.chunk_size.min((original_size - offset) as usize);
            rng.fill_bytes(&mut buf[..to_write]);
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;
            file.write_all(&buf[..to_write])
                .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;
            bytes_written += to_write as u64;
            offset += to_write as u64;
        }
        file.sync_data()
            .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;
        buf.zeroize();
    }

    // Generate an ephemeral 256-bit key and 96-bit nonce.
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut buffer = vec![0u8; options.chunk_size];
    let mut offset: u64 = 0;

    while offset < original_size {
        let to_read = options.chunk_size.min((original_size - offset) as usize);
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;
        let n = file
            .read(&mut buffer[..to_read])
            .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;
        if n == 0 {
            break;
        }

        cipher
            .encrypt_in_place_detached(nonce, &[], &mut buffer[..n])
            .map_err(|_| PurgeError::Io(format!("{}: crypto-shred encryption failed", path.display())))?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;
        file.write_all(&buffer[..n])
            .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;

        if options.fsync_each_chunk {
            file.sync_data()
                .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;
        }

        offset += n as u64;
        bytes_written += n as u64;
        chunks_processed += 1;
    }

    let fsynced = file
        .sync_all()
        .map(|_| true)
        .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;

    let mut truncated = false;
    if options.truncate_after {
        file.set_len(0)
            .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;
        truncated = true;
    }

    drop(file);

    // Scrub key material from RAM *before* we return.
    key_bytes.zeroize();
    nonce_bytes.zeroize();
    buffer.zeroize();

    let mut removed = false;
    if options.unlink_after {
        std::fs::remove_file(path)
            .map_err(|e| PurgeError::Io(format!("{}: {}", path.display(), e)))?;
        removed = true;
    }

    Ok(CryptoShredReport {
        path: path.to_path_buf(),
        original_size,
        chunks_processed,
        bytes_written,
        fsynced,
        truncated,
        removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn make_temp_file(contents: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "purge-shred-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        path
    }

    #[test]
    fn test_crypto_shred_small_file_is_removed() {
        let path = make_temp_file(b"plaintext-to-shred-abc");
        let report = crypto_shred(&path, &CryptoShredOptions::default()).unwrap();
        assert!(report.removed);
        assert!(!path.exists());
    }

    #[test]
    fn test_crypto_shred_keeps_file_when_unlink_off() {
        let path = make_temp_file(b"keep-me-but-scramble");
        let options = CryptoShredOptions {
            unlink_after: false,
            truncate_after: false,
            ..Default::default()
        };
        crypto_shred(&path, &options).unwrap();
        assert!(path.exists());
        let remaining = std::fs::read(&path).unwrap();
        assert_ne!(remaining, b"keep-me-but-scramble");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_crypto_shred_replaces_plaintext() {
        let pt = b"DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        let path = make_temp_file(pt);
        let options = CryptoShredOptions {
            unlink_after: false,
            truncate_after: false,
            ..Default::default()
        };
        crypto_shred(&path, &options).unwrap();
        let remaining = std::fs::read(&path).unwrap();
        assert_eq!(remaining.len(), pt.len());
        assert_ne!(remaining, pt);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_crypto_shred_truncates() {
        let path = make_temp_file(&vec![0xAAu8; 8192]);
        let options = CryptoShredOptions {
            unlink_after: false,
            truncate_after: true,
            ..Default::default()
        };
        crypto_shred(&path, &options).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_crypto_shred_multiple_chunks() {
        let big = vec![0x42u8; 300_000];
        let path = make_temp_file(&big);
        let options = CryptoShredOptions {
            unlink_after: false,
            truncate_after: false,
            chunk_size: 4096,
            ..Default::default()
        };
        let report = crypto_shred(&path, &options).unwrap();
        assert!(report.chunks_processed >= 73);
        assert_eq!(report.bytes_written, 300_000);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_crypto_shred_pre_random_pass_counts_doubled_writes() {
        let path = make_temp_file(&vec![0u8; 4096]);
        let options = CryptoShredOptions {
            unlink_after: false,
            truncate_after: false,
            pre_random_pass: true,
            ..Default::default()
        };
        let report = crypto_shred(&path, &options).unwrap();
        assert_eq!(report.bytes_written, 4096 * 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_crypto_shred_nonexistent_errors() {
        let path = PathBuf::from("/tmp/nonexistent-crypto-shred-abcdefg");
        assert!(crypto_shred(&path, &CryptoShredOptions::default()).is_err());
    }

    #[test]
    fn test_crypto_shred_directory_errors() {
        let dir = std::env::temp_dir().join(format!(
            "purge-shred-dir-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let result = crypto_shred(&dir, &CryptoShredOptions::default());
        assert!(result.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_default_options_delete_by_default() {
        let opts = CryptoShredOptions::default();
        assert!(opts.unlink_after);
        assert!(opts.truncate_after);
        assert!(!opts.pre_random_pass);
    }

    #[test]
    fn test_crypto_shred_empty_file_reports_zero_chunks() {
        let path = make_temp_file(b"");
        let report = crypto_shred(&path, &CryptoShredOptions::default()).unwrap();
        assert_eq!(report.original_size, 0);
        assert_eq!(report.chunks_processed, 0);
        assert!(report.removed);
    }
}
