//! File-carving blocker — scrubs recognizable file signatures from byte buffers.
//!
//! Forensic carvers like Foremost and Scalpel recover deleted files by
//! scanning raw disk sectors for known magic numbers (e.g. `FFD8FFE0` for
//! JPEG, `89 50 4E 47` for PNG). Even after a file is unlinked, if its
//! header survives in slack space or unallocated blocks, a carver can
//! reconstruct the file.
//!
//! This module walks a byte buffer (typically a chunk read from
//! unallocated space) and overwrites any detected file-signature regions
//! with a configurable pattern. It is the low-level primitive used by
//! `free_space_wipe` to blind a carver after the primary overwrite pass.
//!
//! This module performs *defensive* signature scrubbing only. It neither
//! reads from nor writes to physical disks; it operates on buffers
//! supplied by the caller.

use serde::{Deserialize, Serialize};

/// A known file-type signature that a carver would recognize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub name: &'static str,
    pub magic: &'static [u8],
}

/// Default set of signatures covering the high-value formats carvers target.
pub fn default_signatures() -> Vec<Signature> {
    vec![
        Signature { name: "jpeg",    magic: &[0xFF, 0xD8, 0xFF, 0xE0] },
        Signature { name: "jpeg-ex", magic: &[0xFF, 0xD8, 0xFF, 0xE1] },
        Signature { name: "png",     magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
        Signature { name: "gif87a",  magic: b"GIF87a" },
        Signature { name: "gif89a",  magic: b"GIF89a" },
        Signature { name: "pdf",     magic: b"%PDF-" },
        Signature { name: "zip",     magic: &[0x50, 0x4B, 0x03, 0x04] },
        Signature { name: "rar",     magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] },
        Signature { name: "7z",      magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
        Signature { name: "ogg",     magic: b"OggS" },
        Signature { name: "mp3-id3", magic: b"ID3" },
        Signature { name: "mp4",     magic: b"ftyp" },
        Signature { name: "sqlite",  magic: b"SQLite format 3\0" },
        Signature { name: "elf",     magic: &[0x7F, 0x45, 0x4C, 0x46] },
        Signature { name: "pe",      magic: &[0x4D, 0x5A] },
        Signature { name: "bzip2",   magic: b"BZh" },
        Signature { name: "gzip",    magic: &[0x1F, 0x8B] },
    ]
}

/// How to fill over a detected signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FillMode {
    /// Overwrite with zeroes.
    Zero,
    /// Overwrite with a single repeating byte.
    Byte(u8),
    /// Overwrite with deterministic pseudo-random bytes (LCG).
    PseudoRandom(u64),
}

/// Report returned after scrubbing a buffer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScrubReport {
    pub scanned_bytes: usize,
    pub signatures_found: usize,
    pub bytes_scrubbed: usize,
    pub by_type: std::collections::HashMap<String, usize>,
}

/// File carving blocker.
pub struct FileCarvingBlocker {
    signatures: Vec<Signature>,
    fill: FillMode,
}

impl FileCarvingBlocker {
    pub fn new() -> Self {
        Self {
            signatures: default_signatures(),
            fill: FillMode::PseudoRandom(0xDEAD_BEEF),
        }
    }

    pub fn with_fill(fill: FillMode) -> Self {
        Self {
            signatures: default_signatures(),
            fill,
        }
    }

    pub fn with_signatures(signatures: Vec<Signature>, fill: FillMode) -> Self {
        Self { signatures, fill }
    }

    pub fn add_signature(&mut self, sig: Signature) {
        self.signatures.push(sig);
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Scan `buf` for signature hits and overwrite them in place.
    pub fn scrub(&self, buf: &mut [u8]) -> ScrubReport {
        let mut report = ScrubReport {
            scanned_bytes: buf.len(),
            ..Default::default()
        };

        // Collect hits first; otherwise scrubbing the first match could
        // invalidate an overlapping second match.
        let mut hits: Vec<(usize, usize, &'static str)> = Vec::new();
        for sig in &self.signatures {
            let m = sig.magic;
            if m.is_empty() || m.len() > buf.len() {
                continue;
            }
            let mut i = 0;
            while i + m.len() <= buf.len() {
                if buf[i..i + m.len()] == *m {
                    hits.push((i, m.len(), sig.name));
                    i += m.len();
                } else {
                    i += 1;
                }
            }
        }

        for (offset, len, name) in &hits {
            fill_range(buf, *offset, *len, self.fill);
            report.signatures_found += 1;
            report.bytes_scrubbed += *len;
            *report.by_type.entry((*name).to_string()).or_insert(0) += 1;
        }

        report
    }

    /// Returns true if a scan of `buf` would find any known signatures.
    pub fn contains_signature(&self, buf: &[u8]) -> bool {
        self.signatures.iter().any(|sig| {
            let m = sig.magic;
            !m.is_empty() && buf.windows(m.len()).any(|w| w == m)
        })
    }
}

impl Default for FileCarvingBlocker {
    fn default() -> Self {
        Self::new()
    }
}

fn fill_range(buf: &mut [u8], offset: usize, len: usize, mode: FillMode) {
    let end = (offset + len).min(buf.len());
    match mode {
        FillMode::Zero => {
            for b in &mut buf[offset..end] {
                *b = 0;
            }
        }
        FillMode::Byte(b) => {
            for x in &mut buf[offset..end] {
                *x = b;
            }
        }
        FillMode::PseudoRandom(seed) => {
            // Simple LCG for deterministic, testable scrubbing.
            let mut state = seed.wrapping_add(offset as u64).max(1);
            for x in &mut buf[offset..end] {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *x = (state >> 33) as u8;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_jpeg_header() {
        let blocker = FileCarvingBlocker::new();
        let mut buf = vec![0u8; 32];
        buf[4..8].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        assert!(blocker.contains_signature(&buf));
    }

    #[test]
    fn test_scrub_jpeg_removes_signature() {
        let blocker = FileCarvingBlocker::with_fill(FillMode::Zero);
        let mut buf = vec![0u8; 32];
        buf[4..8].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        let report = blocker.scrub(&mut buf);
        assert_eq!(report.signatures_found, 1);
        assert_eq!(report.bytes_scrubbed, 4);
        assert!(!blocker.contains_signature(&buf));
    }

    #[test]
    fn test_scrub_png_removes_signature() {
        let blocker = FileCarvingBlocker::with_fill(FillMode::Zero);
        let mut buf = vec![0u8; 32];
        buf[8..16].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        let report = blocker.scrub(&mut buf);
        assert_eq!(report.signatures_found, 1);
        assert!(!blocker.contains_signature(&buf));
    }

    #[test]
    fn test_scrub_pdf() {
        let blocker = FileCarvingBlocker::with_fill(FillMode::Zero);
        let mut buf = b"xxx%PDF-1.4 yyy".to_vec();
        let report = blocker.scrub(&mut buf);
        assert_eq!(report.signatures_found, 1);
        assert!(!blocker.contains_signature(&buf));
    }

    #[test]
    fn test_multiple_signatures() {
        let blocker = FileCarvingBlocker::with_fill(FillMode::Zero);
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        buf[32..40].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        let report = blocker.scrub(&mut buf);
        assert_eq!(report.signatures_found, 2);
    }

    #[test]
    fn test_empty_buffer() {
        let blocker = FileCarvingBlocker::new();
        let mut buf = Vec::new();
        let report = blocker.scrub(&mut buf);
        assert_eq!(report.signatures_found, 0);
    }

    #[test]
    fn test_no_signatures_means_clean() {
        let blocker = FileCarvingBlocker::new();
        let buf = vec![0xAAu8; 32];
        assert!(!blocker.contains_signature(&buf));
    }

    #[test]
    fn test_byte_fill_overwrites() {
        let blocker = FileCarvingBlocker::with_fill(FillMode::Byte(0x55));
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        blocker.scrub(&mut buf);
        assert!(buf[0..4].iter().all(|&b| b == 0x55));
    }

    #[test]
    fn test_pseudo_random_fill() {
        let blocker = FileCarvingBlocker::with_fill(FillMode::PseudoRandom(42));
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        blocker.scrub(&mut buf);
        assert_ne!(&buf[0..4], &[0xFF, 0xD8, 0xFF, 0xE0]);
    }

    #[test]
    fn test_report_by_type() {
        let blocker = FileCarvingBlocker::with_fill(FillMode::Zero);
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        buf[32..40].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        let report = blocker.scrub(&mut buf);
        assert_eq!(report.by_type.get("jpeg").copied().unwrap_or(0), 1);
        assert_eq!(report.by_type.get("png").copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_add_custom_signature() {
        let mut blocker = FileCarvingBlocker::with_fill(FillMode::Zero);
        blocker.add_signature(Signature {
            name: "custom",
            magic: b"CUSTOM",
        });
        let mut buf = b"xxxCUSTOMyyy".to_vec();
        let report = blocker.scrub(&mut buf);
        assert_eq!(report.signatures_found, 1);
    }

    #[test]
    fn test_default_signature_count() {
        let blocker = FileCarvingBlocker::new();
        assert!(blocker.signature_count() >= 15);
    }
}
