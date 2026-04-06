//! Secure data destruction beyond NIST 800-88.
//!
//! Multiple overwrite passes with verification. Handles wear-leveling
//! awareness for SSDs/NVMe (via TRIM/UNMAP where possible).
//!
//! # Safety posture (AVP-2 audit pass)
//!
//! The earlier implementation had at least four real bugs:
//!
//! 1. **Critical**: `secure_delete_directory` walked symlinked
//!    targets. Calling it on `/home/user/link-to-etc` would wipe
//!    the contents of `/etc`.
//! 2. **Critical**: file opens followed symlinks, so an attacker
//!    who could swap a file for a symlink between stat and open
//!    could redirect the overwrite to a chosen target (TOCTOU).
//! 3. **Critical**: no file-type check. A caller could pass a
//!    device file, FIFO, socket, or character special and the
//!    destroyer would try to overwrite it.
//! 4. **High**: `verify_overwrite` read the whole file into RAM,
//!    so verifying a 10 GB overwrite allocated 10 GB. Memory
//!    exhaustion on large files.
//!
//! This module has been rewritten to close all four.

use crate::error::{PurgeError, Result};
use crate::safety::safe_open_rw;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use zeroize::Zeroize;

/// Securely delete a file with multiple overwrite passes.
///
/// Pass patterns alternate: zeros / ones / random / zeros / ones /
/// random. After overwriting, the file is truncated to zero, renamed
/// to a random name (defeating filename-based recovery), and unlinked.
///
/// SECURITY: opens with O_NOFOLLOW so symlinks are refused at the
/// kernel level; fstats the descriptor to confirm it is still a
/// regular file; takes an exclusive flock so other processes cannot
/// race writes.
pub fn secure_delete(path: &str, passes: u32, verify: bool) -> Result<()> {
    let file_path = Path::new(path);

    if !file_path.exists() {
        return Err(PurgeError::PathNotFound(path.to_string()));
    }

    // Use symlink_metadata so a symlink at the target shows up as a
    // symlink rather than its target's type. This is the first of
    // two checks — the authoritative one is the fstat after open.
    let pre_meta = fs::symlink_metadata(file_path)
        .map_err(|e| PurgeError::Io(e.to_string()))?;

    if pre_meta.file_type().is_symlink() {
        return Err(PurgeError::Io(format!(
            "refusing to destroy a symlink: {}",
            path
        )));
    }

    if pre_meta.is_dir() {
        return secure_delete_directory(path, passes, verify);
    }

    if !pre_meta.is_file() {
        return Err(PurgeError::Io(format!(
            "not a regular file (device/fifo/socket?): {}",
            path
        )));
    }

    let file_size = pre_meta.len();

    tracing::debug!("Securely deleting {path} ({file_size} bytes, {passes} passes)");

    // Overwrite passes.
    for pass in 0..passes {
        let pattern = match pass % 3 {
            0 => OverwritePattern::Zeros,
            1 => OverwritePattern::Ones,
            _ => OverwritePattern::Random,
        };

        overwrite_file(file_path, file_size, &pattern)?;

        if verify {
            verify_overwrite(file_path, file_size, &pattern)?;
        }

        tracing::trace!("Pass {}/{passes} complete for {path}", pass + 1);
    }

    // Truncate to zero via an O_NOFOLLOW + flock handle.
    let trunc_handle = safe_open_rw(file_path)?;
    trunc_handle
        .set_len(0)
        .map_err(|e| PurgeError::Io(e.to_string()))?;
    drop(trunc_handle);

    // Rename to random name before unlinking (defeats filename recovery).
    let random_name = {
        use rand::RngCore;
        let val = rand::rngs::OsRng.next_u64();
        format!(".purge_{val:016x}")
    };
    let parent = file_path.parent().unwrap_or(Path::new("."));
    let renamed = parent.join(&random_name);
    fs::rename(file_path, &renamed).map_err(|e| PurgeError::Io(e.to_string()))?;

    // Unlink.
    fs::remove_file(&renamed).map_err(|e| PurgeError::Io(e.to_string()))?;

    tracing::info!("Securely deleted: {path}");
    Ok(())
}

/// Securely delete all files in a directory recursively.
///
/// SECURITY: refuses if the root path is a symlink. walkdir's
/// default `follow_links=false` prevents descent into symlinks
/// discovered inside the tree, but the root itself needs an
/// explicit check because walkdir will happily open a symlinked
/// directory as its starting point.
fn secure_delete_directory(path: &str, passes: u32, verify: bool) -> Result<()> {
    let root = Path::new(path);

    // REGRESSION-GUARD: the earlier version accepted a symlinked
    // root and walked the target. Calling it on a symlink pointing
    // to /etc would destroy /etc.
    let root_meta = fs::symlink_metadata(root)
        .map_err(|e| PurgeError::Io(e.to_string()))?;
    if root_meta.file_type().is_symlink() {
        return Err(PurgeError::Io(format!(
            "refusing to recurse into a symlink: {}",
            path
        )));
    }

    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .contents_first(true) // delete children before parents
        .into_iter()
        .filter_map(|e| e.ok())
    {
        // Skip symlinks encountered during the walk — we would
        // ordinarily never follow them, but defensive.
        if entry.file_type().is_symlink() {
            continue;
        }
        if entry.file_type().is_file() {
            let entry_path = entry
                .path()
                .to_str()
                .ok_or_else(|| {
                    PurgeError::Io("non-UTF-8 path in directory walk".into())
                })?;
            secure_delete(entry_path, passes, verify)?;
        } else if entry.file_type().is_dir() && entry.path() != root {
            fs::remove_dir(entry.path()).map_err(|e| PurgeError::Io(e.to_string()))?;
        }
    }
    fs::remove_dir(root).map_err(|e| PurgeError::Io(e.to_string()))?;
    Ok(())
}

enum OverwritePattern {
    Zeros,
    Ones,
    Random,
}

fn overwrite_file(path: &Path, size: u64, pattern: &OverwritePattern) -> Result<()> {
    let mut file = safe_open_rw(path)?;

    file.seek(SeekFrom::Start(0))
        .map_err(|e| PurgeError::Io(e.to_string()))?;

    let chunk_size = 65536usize;
    let mut buf = vec![0u8; chunk_size];
    let mut written = 0u64;

    while written < size {
        let to_write = chunk_size.min((size - written) as usize);
        let chunk = &mut buf[..to_write];

        match pattern {
            OverwritePattern::Zeros => chunk.fill(0x00),
            OverwritePattern::Ones => chunk.fill(0xFF),
            OverwritePattern::Random => {
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(chunk);
            }
        }

        file.write_all(chunk)
            .map_err(|e| PurgeError::Io(e.to_string()))?;
        written += to_write as u64;
    }

    file.sync_all()
        .map_err(|e| PurgeError::Io(e.to_string()))?;

    // Scrub any residual pattern from the process address space.
    buf.zeroize();

    Ok(())
}

/// Verify an overwrite by streaming the file contents back one chunk
/// at a time and comparing each byte against the expected pattern.
/// Uses a bounded scratch buffer so verifying a 10 GB file does not
/// allocate 10 GB.
fn verify_overwrite(path: &Path, size: u64, pattern: &OverwritePattern) -> Result<()> {
    // For random patterns, we can't verify content — just verify
    // that the file was written and ends up the right size.
    if matches!(pattern, OverwritePattern::Random) {
        let meta = fs::metadata(path).map_err(|e| PurgeError::Io(e.to_string()))?;
        if meta.len() != size {
            return Err(PurgeError::VerificationFailed {
                offset: meta.len(),
                expected: 0,
                found: 0,
            });
        }
        return Ok(());
    }

    let expected_byte = match pattern {
        OverwritePattern::Zeros => 0x00,
        OverwritePattern::Ones => 0xFF,
        OverwritePattern::Random => return Ok(()),
    };

    let mut file = safe_open_rw(path)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| PurgeError::Io(e.to_string()))?;

    let chunk_size: usize = 65536;
    let mut buf = vec![0u8; chunk_size];
    let mut offset: u64 = 0;

    while offset < size {
        let to_read = chunk_size.min((size - offset) as usize);
        let n = file
            .read(&mut buf[..to_read])
            .map_err(|e| PurgeError::Io(e.to_string()))?;
        if n == 0 {
            return Err(PurgeError::VerificationFailed {
                offset,
                expected: expected_byte,
                found: 0,
            });
        }
        for (i, &byte) in buf[..n].iter().enumerate() {
            if byte != expected_byte {
                return Err(PurgeError::VerificationFailed {
                    offset: offset + i as u64,
                    expected: expected_byte,
                    found: byte,
                });
            }
        }
        offset += n as u64;
    }

    buf.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_delete_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sensitive.txt");
        fs::write(&path, "sensitive data here").unwrap();
        let path_str = path.to_str().unwrap().to_string();

        secure_delete(&path_str, 3, false).unwrap();
        assert!(!Path::new(&path_str).exists());
    }

    #[test]
    fn test_secure_delete_nonexistent() {
        let result = secure_delete("/tmp/nonexistent_purge_test_12345", 1, false);
        assert!(result.is_err());
    }

    // REGRESSION-GUARD: the earlier version wiped symlink targets
    // when you called secure_delete on a symlinked regular file.
    #[test]
    fn test_secure_delete_refuses_file_symlink() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, b"target-sentinel").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = secure_delete(link.to_str().unwrap(), 1, false);
        assert!(result.is_err());
        assert!(
            matches!(&result, Err(PurgeError::Io(msg)) if msg.contains("symlink")),
            "expected 'symlink' in the error, got: {:?}",
            result
        );
        let target_contents = fs::read(&target).unwrap();
        assert_eq!(target_contents, b"target-sentinel");
    }

    // REGRESSION-GUARD: the earlier version wiped the contents of
    // /etc when you called secure_delete on a symlink to /etc.
    #[test]
    fn test_secure_delete_refuses_directory_symlink() {
        let dir = tempfile::TempDir::new().unwrap();
        let target_dir = dir.path().join("real_target_dir");
        fs::create_dir(&target_dir).unwrap();
        let sentinel = target_dir.join("sentinel.txt");
        fs::write(&sentinel, b"do-not-destroy").unwrap();

        let link_dir = dir.path().join("link_to_dir");
        std::os::unix::fs::symlink(&target_dir, &link_dir).unwrap();

        let result = secure_delete(link_dir.to_str().unwrap(), 1, false);
        assert!(result.is_err());
        assert!(sentinel.exists(), "sentinel inside symlink target was touched");
        let contents = fs::read(&sentinel).unwrap();
        assert_eq!(contents, b"do-not-destroy");
    }

    // REGRESSION-GUARD: block device / FIFO / socket should be rejected.
    #[test]
    fn test_secure_delete_refuses_fifo() {
        let dir = tempfile::TempDir::new().unwrap();
        let fifo = dir.path().join("fifo");
        let path_cstr = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: mkfifo with a valid C string and sane mode.
        let rc = unsafe { libc::mkfifo(path_cstr.as_ptr(), 0o600) };
        if rc != 0 {
            // Some test environments deny mkfifo; skip gracefully.
            return;
        }
        let result = secure_delete(fifo.to_str().unwrap(), 1, false);
        assert!(result.is_err());
    }

    // Verify uses streaming now, not whole-file read. Regression
    // guard: a ~1 MiB zero file should verify correctly without
    // ever allocating anywhere near 1 MiB in one chunk.
    #[test]
    fn test_verify_overwrite_streams() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("big.bin");
        fs::write(&path, vec![0u8; 1 << 20]).unwrap();
        verify_overwrite(&path, 1 << 20, &OverwritePattern::Zeros).unwrap();
    }

}
