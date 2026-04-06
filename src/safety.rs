//! Shared safety primitives for every Purge destruction code path.
//!
//! Every module in Purge that opens a file for writing should go
//! through [`safe_open_rw`] instead of calling `OpenOptions::open`
//! directly. The helper:
//!
//! 1. Refuses symlinks at the kernel level via `O_NOFOLLOW`.
//! 2. `fstat`s the resulting file descriptor and refuses any fd
//!    that is not a regular file (catches the stat-to-open TOCTOU
//!    window where an attacker swapped the target).
//! 3. Takes an exclusive non-blocking `flock(2)` so concurrent
//!    writers cannot race the destruction.
//!
//! The pre-check [`safe_symlink_metadata`] rejects symlinks, devices,
//! FIFOs, sockets, and directories up front with clear error messages,
//! so callers don't have to duplicate the same refusals.

use crate::error::{PurgeError, Result};
use std::fs::{File, Metadata, OpenOptions};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Stat a path with `symlink_metadata` (does NOT follow symlinks),
/// reject every file type that isn't a regular file, and return
/// the metadata on success.
pub fn safe_symlink_metadata(path: &Path) -> Result<Metadata> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| PurgeError::Io(format!("symlink_metadata {}: {}", path.display(), e)))?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(PurgeError::Io(format!(
            "refusing to destroy a symlink: {}",
            path.display()
        )));
    }
    if ft.is_dir() {
        return Err(PurgeError::Io(format!(
            "refusing to destroy a directory via the file path: {}",
            path.display()
        )));
    }
    if ft.is_block_device()
        || ft.is_char_device()
        || ft.is_fifo()
        || ft.is_socket()
    {
        return Err(PurgeError::Io(format!(
            "refusing to destroy a non-regular file (device/fifo/socket): {}",
            path.display()
        )));
    }
    if !ft.is_file() {
        return Err(PurgeError::Io(format!(
            "not a regular file: {}",
            path.display()
        )));
    }
    Ok(meta)
}

/// Open a regular file for read+write with every AVP-2 safety
/// gate engaged:
///
/// - `O_NOFOLLOW` so the kernel refuses the open if the path became
///   a symlink between an earlier stat and this call (TOCTOU race).
/// - `fstat` on the returned fd verifies the descriptor still points
///   at a regular file. If someone replaced the regular file with a
///   different file type in the race window, this catches it.
/// - Exclusive non-blocking `flock(2)` so no other process can write
///   concurrently. The lock is released when the returned `File` is
///   dropped.
pub fn safe_open_rw(path: &Path) -> Result<File> {
    let open_result = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path);
    let file = match open_result {
        Ok(f) => f,
        Err(e) => {
            if e.raw_os_error() == Some(libc::ELOOP) {
                return Err(PurgeError::Io(format!(
                    "path became a symlink between check and open (TOCTOU): {}",
                    path.display()
                )));
            }
            return Err(PurgeError::Io(format!(
                "open {}: {}",
                path.display(),
                e
            )));
        }
    };

    // fstat-verify the open fd.
    let fd = file.as_raw_fd();
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat with a valid fd and a zeroed stat buffer is the
    // documented invocation. The fd is owned by `file` and outlives
    // this call.
    let rc = unsafe { libc::fstat(fd, &mut stat_buf) };
    if rc != 0 {
        return Err(PurgeError::Io("fstat failed after open".into()));
    }
    if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(PurgeError::Io(
            "fstat reports non-regular file after open".into(),
        ));
    }

    // Take an exclusive non-blocking flock with a brief retry loop.
    // A short retry handles transient kernel state when a prior
    // File was just dropped; genuine contention from another writer
    // still fails after the retries are exhausted.
    //
    // SAFETY: flock with a valid fd is the documented invocation.
    let mut last_err = None;
    for attempt in 0..5 {
        let flock_rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if flock_rc == 0 {
            return Ok(file);
        }
        let err = std::io::Error::last_os_error();
        // EWOULDBLOCK / EAGAIN means someone has the lock. Back off
        // and retry; every other errno is fatal.
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(PurgeError::Io(format!(
                "flock on {}: {}",
                path.display(),
                err
            )));
        }
        last_err = Some(err);
        // Exponential-ish backoff: 1ms, 2ms, 4ms, 8ms, 16ms.
        std::thread::sleep(std::time::Duration::from_millis(1u64 << attempt));
    }
    let err = last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::WouldBlock, "flock timeout")
    });
    Err(PurgeError::Io(format!(
        "another process holds a lock on {} (flock: {})",
        path.display(),
        err
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(contents: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "purge-safety-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        path
    }

    #[test]
    fn test_safe_symlink_metadata_accepts_regular_file() {
        let path = temp_file(b"x");
        assert!(safe_symlink_metadata(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_safe_symlink_metadata_refuses_symlink() {
        let target = temp_file(b"target");
        let link = std::env::temp_dir().join(format!(
            "purge-safety-link-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = safe_symlink_metadata(&link).unwrap_err();
        if let PurgeError::Io(msg) = err {
            assert!(msg.contains("symlink"));
        }
        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&target).ok();
    }

    #[test]
    fn test_safe_symlink_metadata_refuses_fifo() {
        let fifo = std::env::temp_dir().join(format!(
            "purge-safety-fifo-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&fifo);
        let cstr =
            std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: mkfifo with a valid C string and sane mode.
        let rc = unsafe { libc::mkfifo(cstr.as_ptr(), 0o600) };
        if rc != 0 {
            // Sandbox denied mkfifo; skip.
            return;
        }
        let err = safe_symlink_metadata(&fifo).unwrap_err();
        if let PurgeError::Io(msg) = err {
            assert!(msg.contains("fifo") || msg.contains("non-regular"));
        }
        std::fs::remove_file(&fifo).ok();
    }

    #[test]
    fn test_safe_symlink_metadata_refuses_directory() {
        let dir = std::env::temp_dir().join(format!(
            "purge-safety-dir-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let err = safe_symlink_metadata(&dir).unwrap_err();
        if let PurgeError::Io(msg) = err {
            assert!(msg.contains("directory"));
        }
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn test_safe_open_rw_opens_regular_file() {
        let path = temp_file(b"regular");
        assert!(safe_open_rw(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_safe_open_rw_refuses_symlink() {
        let target = temp_file(b"target");
        let link = std::env::temp_dir().join(format!(
            "purge-safety-open-link-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(safe_open_rw(&link).is_err());
        // Target untouched.
        let contents = std::fs::read(&target).unwrap();
        assert_eq!(contents, b"target");
        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&target).ok();
    }

    #[test]
    fn test_safe_open_rw_contention_refused() {
        let path = temp_file(b"contested");
        // Hold the lock for longer than the retry window so the
        // second attempt is guaranteed to fail even after retries.
        let holder = safe_open_rw(&path).unwrap();
        let path_clone = path.clone();
        let handle = std::thread::spawn(move || {
            // Hold the lock well past the retry window (31 ms total).
            std::thread::sleep(std::time::Duration::from_millis(150));
            drop(holder);
        });
        let second = safe_open_rw(&path_clone);
        assert!(
            second.is_err(),
            "expected contention error after retry exhaustion"
        );
        handle.join().unwrap();
        // After the holder thread drops, we can take it again.
        assert!(safe_open_rw(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }
}
