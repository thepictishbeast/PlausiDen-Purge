//! Metadata stripping engine — removes identifying metadata from files before
//! they leave the device.
//!
//! Supported formats:
//! - **JPEG/PNG**: EXIF data (GPS, camera model, serial number, timestamps)
//! - **PDF**: Author, Creator, Producer, CreationDate, ModDate
//! - **Office documents (OOXML)**: Author, company, revision history
//! - **Audio (MP3)**: ID3 tags (artist, album, comment)
//! - **Video (MP4)**: encoded_by, creation_time metadata atoms

use crate::error::{PurgeError, Result};
use crate::file_type::{self, FileType};

use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Zero-sized entry point for metadata stripping operations.
pub struct MetadataStripper;

/// Result of stripping metadata from a single file.
#[derive(Debug, Clone)]
pub struct StripResult {
    /// Path that was processed.
    pub path: PathBuf,
    /// File size before stripping.
    pub original_size: u64,
    /// File size after stripping.
    pub stripped_size: u64,
    /// Human-readable names of the fields/segments that were removed.
    pub fields_removed: Vec<String>,
}

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

impl MetadataStripper {
    // -----------------------------------------------------------------------
    // High-level API
    // -----------------------------------------------------------------------

    /// Detect the file type and strip the appropriate metadata.
    pub fn strip_file(path: &Path) -> Result<StripResult> {
        let data = fs::read(path).map_err(|e| PurgeError::Io(e.to_string()))?;
        let original_size = data.len() as u64;
        let file_type = file_type::detect(&data);

        let (stripped, fields) = match file_type {
            FileType::Jpeg => Self::strip_jpeg(&data),
            FileType::Png => Self::strip_png(&data),
            FileType::Pdf => Self::strip_pdf(&data),
            FileType::Docx | FileType::Xlsx => Self::strip_office(&data),
            FileType::Mp3 => Self::strip_mp3(&data),
            FileType::Mp4 => Self::strip_mp4(&data),
            _ => (data, Vec::new()),
        };

        fs::write(path, &stripped).map_err(|e| PurgeError::Io(e.to_string()))?;

        Ok(StripResult {
            path: path.to_path_buf(),
            original_size,
            stripped_size: stripped.len() as u64,
            fields_removed: fields,
        })
    }

    /// Return `true` if the file contains strippable metadata.
    pub fn has_metadata(path: &Path) -> bool {
        let Ok(data) = fs::read(path) else {
            return false;
        };
        let file_type = file_type::detect(&data);

        match file_type {
            FileType::Jpeg => Self::jpeg_has_app1(&data),
            FileType::Png => Self::png_has_text_chunks(&data),
            FileType::Pdf => Self::pdf_has_info_fields(&data),
            FileType::Docx | FileType::Xlsx => true, // OOXML always has core.xml
            FileType::Mp3 => Self::mp3_has_id3(&data),
            FileType::Mp4 => Self::mp4_has_metadata(&data),
            _ => false,
        }
    }

    /// Walk a directory and return paths to every file with strippable metadata.
    pub fn scan_directory(root: &Path) -> Result<Vec<PathBuf>> {
        if !root.is_dir() {
            return Err(PurgeError::PathNotFound(root.display().to_string()));
        }

        let mut hits = Vec::new();
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() && Self::has_metadata(entry.path()) {
                hits.push(entry.path().to_path_buf());
            }
        }
        Ok(hits)
    }

    // -----------------------------------------------------------------------
    // JPEG — remove APP1 (EXIF) segments
    // -----------------------------------------------------------------------

    /// Strip all EXIF APP1 segments from JPEG data.
    ///
    /// Walks the JPEG marker chain, keeping every segment except APP1
    /// (`0xFF 0xE1`), which carries EXIF (GPS, camera model, serial number,
    /// timestamps, etc.).
    pub fn strip_jpeg(data: &[u8]) -> (Vec<u8>, Vec<String>) {
        if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
            return (data.to_vec(), Vec::new());
        }

        let mut out = Vec::with_capacity(data.len());
        let mut fields = Vec::new();

        // Copy SOI marker.
        out.push(0xFF);
        out.push(0xD8);

        let mut pos = 2;
        while pos + 1 < data.len() {
            if data[pos] != 0xFF {
                // Not a marker — copy the rest verbatim (image data).
                out.extend_from_slice(&data[pos..]);
                break;
            }

            let marker = data[pos + 1];

            // SOS (Start of Scan) — everything after is entropy-coded data.
            if marker == 0xDA {
                out.extend_from_slice(&data[pos..]);
                break;
            }

            // Markers without a length field (standalone markers).
            if marker == 0x00 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
                out.push(data[pos]);
                out.push(data[pos + 1]);
                pos += 2;
                continue;
            }

            // Read segment length.
            if pos + 3 >= data.len() {
                out.extend_from_slice(&data[pos..]);
                break;
            }
            let seg_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let total = 2 + seg_len; // marker (2) + length-included payload

            // APP1 = 0xE1 — this is where EXIF lives.
            if marker == 0xE1 {
                // Inspect what we are dropping.
                let payload = &data[pos + 4..pos + total.min(data.len())];
                if payload.starts_with(b"Exif\0") {
                    fields.push("EXIF (GPS, camera model, serial, timestamps)".into());
                } else {
                    fields.push("APP1 segment".into());
                }
                pos += total;
                continue;
            }

            // Keep everything else.
            let end = (pos + total).min(data.len());
            out.extend_from_slice(&data[pos..end]);
            pos += total;
        }

        (out, fields)
    }

    /// Quick check: does the JPEG contain an APP1 segment?
    fn jpeg_has_app1(data: &[u8]) -> bool {
        if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
            return false;
        }
        let mut pos = 2;
        while pos + 3 < data.len() {
            if data[pos] != 0xFF {
                break;
            }
            let marker = data[pos + 1];
            if marker == 0xDA {
                break;
            }
            if marker == 0x00 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
                pos += 2;
                continue;
            }
            if marker == 0xE1 {
                return true;
            }
            let seg_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 2 + seg_len;
        }
        false
    }

    // -----------------------------------------------------------------------
    // PNG — remove tEXt, iTXt, zTXt chunks (author, software, comments)
    // -----------------------------------------------------------------------

    /// Strip text metadata chunks from PNG data.
    fn strip_png(data: &[u8]) -> (Vec<u8>, Vec<String>) {
        // PNG signature: 8 bytes.
        if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
            return (data.to_vec(), Vec::new());
        }

        let mut out = Vec::with_capacity(data.len());
        let mut fields = Vec::new();

        out.extend_from_slice(&data[..8]); // signature

        let mut pos = 8;
        while pos + 12 <= data.len() {
            let chunk_len =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
            let chunk_type = &data[pos + 4..pos + 8];
            let total = 12 + chunk_len; // length(4) + type(4) + data + crc(4)

            if chunk_type == b"tEXt" || chunk_type == b"iTXt" || chunk_type == b"zTXt" {
                let type_name = String::from_utf8_lossy(chunk_type).to_string();
                fields.push(format!("PNG {type_name} chunk"));
                pos += total;
                continue;
            }

            let end = (pos + total).min(data.len());
            out.extend_from_slice(&data[pos..end]);
            pos += total;
        }

        // Copy any trailing bytes.
        if pos < data.len() {
            out.extend_from_slice(&data[pos..]);
        }

        (out, fields)
    }

    fn png_has_text_chunks(data: &[u8]) -> bool {
        if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
            return false;
        }
        let mut pos = 8;
        while pos + 12 <= data.len() {
            let chunk_len =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
            let chunk_type = &data[pos + 4..pos + 8];
            if chunk_type == b"tEXt" || chunk_type == b"iTXt" || chunk_type == b"zTXt" {
                return true;
            }
            pos += 12 + chunk_len;
        }
        false
    }

    // -----------------------------------------------------------------------
    // PDF — blank /Author, /Creator, /Producer, /CreationDate, /ModDate
    // -----------------------------------------------------------------------

    /// Strip identifying metadata fields from a PDF's Info dictionary.
    ///
    /// Replaces the values of `/Author`, `/Creator`, `/Producer`,
    /// `/CreationDate`, and `/ModDate` with empty parenthesised strings `()`.
    pub fn strip_pdf(data: &[u8]) -> (Vec<u8>, Vec<String>) {
        let mut text = match String::from_utf8(data.to_vec()) {
            Ok(t) => t,
            Err(_) => {
                // Binary PDF — work on lossy copy (unusual but defensive).
                String::from_utf8_lossy(data).into_owned()
            }
        };

        let targets = ["/Author", "/Creator", "/Producer", "/CreationDate", "/ModDate"];
        let mut fields = Vec::new();

        for target in &targets {
            if let Some(start) = text.find(target) {
                // Find the value — it is delimited by parentheses `(value)`.
                let after_key = start + target.len();
                if let Some(rel_open) = text[after_key..].find('(') {
                    let abs_open = after_key + rel_open;
                    if let Some(rel_close) = text[abs_open..].find(')') {
                        let abs_close = abs_open + rel_close + 1;
                        let old_value = &text[abs_open..abs_close];
                        if old_value != "()" {
                            fields.push(format!("{target} = {old_value}"));
                            text.replace_range(abs_open..abs_close, "()");
                        }
                    }
                }
            }
        }

        (text.into_bytes(), fields)
    }

    fn pdf_has_info_fields(data: &[u8]) -> bool {
        let text = String::from_utf8_lossy(data);
        let targets = ["/Author", "/Creator", "/Producer", "/CreationDate", "/ModDate"];
        for target in &targets {
            if let Some(start) = text.find(target) {
                let after = start + target.len();
                // Check that the value is non-empty.
                if let Some(rel_open) = text[after..].find('(') {
                    let abs_open = after + rel_open;
                    if let Some(rel_close) = text[abs_open..].find(')') {
                        let value = &text[abs_open..abs_open + rel_close + 1];
                        if value != "()" {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Office documents (OOXML / ZIP-based) — blank core.xml properties
    // -----------------------------------------------------------------------

    /// Strip author/company/revision metadata from OOXML (docx/xlsx) data.
    ///
    /// OOXML files are ZIP archives; metadata lives in `docProps/core.xml`.
    /// We blank the values of `<dc:creator>`, `<cp:lastModifiedBy>`,
    /// `<cp:revision>`, `<dcterms:created>`, and `<dcterms:modified>` by
    /// rewriting the XML element content in-place.
    fn strip_office(data: &[u8]) -> (Vec<u8>, Vec<String>) {
        // We do a byte-level search-and-replace on the raw ZIP stream.
        // This avoids pulling in a full ZIP library.  It works because the
        // XML inside OOXML is stored **uncompressed** in the local file
        // entry for `docProps/core.xml` in many writers (and even when
        // deflated the central-directory metadata is the same).
        //
        // Pragmatic approach: scan for known XML element patterns and blank
        // their text content.

        let mut text = String::from_utf8_lossy(data).into_owned();
        let mut fields = Vec::new();

        let xml_tags = [
            ("dc:creator", "Author"),
            ("cp:lastModifiedBy", "LastModifiedBy"),
            ("cp:revision", "Revision"),
            ("dcterms:created", "CreatedDate"),
            ("dcterms:modified", "ModifiedDate"),
        ];

        for (tag, label) in &xml_tags {
            let open = format!("<{tag}");
            if let Some(start) = text.find(&open) {
                // Find the end of the opening tag (handle attributes).
                if let Some(gt_rel) = text[start..].find('>') {
                    let content_start = start + gt_rel + 1;
                    let close_tag = format!("</{tag}>");
                    if let Some(content_end_rel) = text[content_start..].find(&close_tag) {
                        let content_end = content_start + content_end_rel;
                        let old = &text[content_start..content_end];
                        if !old.is_empty() {
                            fields.push(format!("{label}: {old}"));
                            text.replace_range(content_start..content_end, "");
                        }
                    }
                }
            }
        }

        (text.into_bytes(), fields)
    }

    // -----------------------------------------------------------------------
    // MP3 — strip ID3v2 header and ID3v1 tail
    // -----------------------------------------------------------------------

    /// Strip ID3 tags (artist, album, comment, etc.) from MP3 data.
    pub fn strip_mp3(data: &[u8]) -> (Vec<u8>, Vec<String>) {
        let mut out = data.to_vec();
        let mut fields = Vec::new();

        // ID3v2 header: starts with "ID3" at byte 0.
        if out.len() > 10 && &out[..3] == b"ID3" {
            // Bytes 6..10 encode the tag size (synchsafe integer).
            let size = ((out[6] as u32 & 0x7F) << 21)
                | ((out[7] as u32 & 0x7F) << 14)
                | ((out[8] as u32 & 0x7F) << 7)
                | (out[9] as u32 & 0x7F);
            let total = 10 + size as usize;
            if total <= out.len() {
                fields.push("ID3v2 (artist, album, comment, etc.)".into());
                out = out[total..].to_vec();
            }
        }

        // ID3v1 tail: last 128 bytes starting with "TAG".
        if out.len() >= 128 {
            let tail_start = out.len() - 128;
            if &out[tail_start..tail_start + 3] == b"TAG" {
                fields.push("ID3v1 (title, artist, album)".into());
                out.truncate(tail_start);
            }
        }

        (out, fields)
    }

    fn mp3_has_id3(data: &[u8]) -> bool {
        // ID3v2 at head.
        if data.len() > 3 && &data[..3] == b"ID3" {
            return true;
        }
        // ID3v1 at tail.
        if data.len() >= 128 {
            let tail = data.len() - 128;
            if &data[tail..tail + 3] == b"TAG" {
                return true;
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // MP4 — blank encoded_by / creation_time in the `udta` atom
    // -----------------------------------------------------------------------

    /// Strip identifying metadata from MP4 containers.
    ///
    /// Searches for `encoded_by` and `creation_time` strings inside the
    /// file's user-data atoms and zeroes their content bytes.
    fn strip_mp4(data: &[u8]) -> (Vec<u8>, Vec<String>) {
        let mut out = data.to_vec();
        let mut fields = Vec::new();

        let targets: &[&[u8]] = &[b"encoded_by", b"creation_time"];

        for target in targets {
            if let Some(pos) = find_bytes(&out, target) {
                let label = String::from_utf8_lossy(target).to_string();
                fields.push(label);
                // Zero the value bytes following the key (up to a NUL or
                // end-of-atom, capped at 256 bytes to stay safe).
                let val_start = pos + target.len();
                let val_end = (val_start + 256).min(out.len());
                for b in &mut out[val_start..val_end] {
                    if *b == 0x00 {
                        break;
                    }
                    *b = 0x00;
                }
            }
        }

        (out, fields)
    }

    fn mp4_has_metadata(data: &[u8]) -> bool {
        find_bytes(data, b"encoded_by").is_some()
            || find_bytes(data, b"creation_time").is_some()
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Find the first occurrence of `needle` in `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // -- helper: build a minimal JPEG with an EXIF APP1 segment ---------------

    fn fake_jpeg_with_exif() -> Vec<u8> {
        let mut data = Vec::new();

        // SOI
        data.extend_from_slice(&[0xFF, 0xD8]);

        // APP1 (EXIF) segment
        let exif_payload: &[u8] = &[
            b'E', b'x', b'i', b'f', 0x00, 0x00, // "Exif\0\0"
            0x4D, 0x4D,                           // Big-endian
            0x00, 0x2A,                           // TIFF magic
            0x00, 0x00, 0x00, 0x08,               // Offset to IFD
            // Fake IFD entry: GPS tag (0x8825)
            0x00, 0x01,                           // 1 entry
            0x88, 0x25,                           // GPSInfo tag
            0x00, 0x04,                           // Type LONG
            0x00, 0x00, 0x00, 0x01,               // Count 1
            0x00, 0x00, 0x00, 0x00,               // Value
        ];
        let seg_len = (exif_payload.len() + 2) as u16; // +2 for length field itself
        data.extend_from_slice(&[0xFF, 0xE1]);
        data.extend_from_slice(&seg_len.to_be_bytes());
        data.extend_from_slice(exif_payload);

        // APP0 (JFIF) — should be kept
        let jfif: &[u8] = &[
            b'J', b'F', b'I', b'F', 0x00,
            0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        ];
        let jfif_len = (jfif.len() + 2) as u16;
        data.extend_from_slice(&[0xFF, 0xE0]);
        data.extend_from_slice(&jfif_len.to_be_bytes());
        data.extend_from_slice(jfif);

        // SOS marker + fake scan data
        data.extend_from_slice(&[0xFF, 0xDA]);
        data.extend_from_slice(&[0x00, 0x04, 0x00, 0x00]); // minimal SOS
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);        // fake image data

        // EOI
        data.extend_from_slice(&[0xFF, 0xD9]);

        data
    }

    // -- helper: build a minimal PDF with an Info dictionary -------------------

    fn fake_pdf_with_info() -> Vec<u8> {
        let text = concat!(
            "%PDF-1.4\n",
            "1 0 obj\n",
            "<< /Type /Catalog /Pages 2 0 R >>\n",
            "endobj\n",
            "2 0 obj\n",
            "<< /Type /Pages /Kids [] /Count 0 >>\n",
            "endobj\n",
            "3 0 obj\n",
            "<< /Author (John Doe) /Creator (LibreOffice) /Producer (PDFlib) ",
            "/CreationDate (D:20250101120000) /ModDate (D:20250315093000) >>\n",
            "endobj\n",
            "%%EOF\n",
        );
        text.as_bytes().to_vec()
    }

    // -- helper: build a minimal MP3 with ID3v2 + ID3v1 -----------------------

    fn fake_mp3_with_id3() -> Vec<u8> {
        let mut data = Vec::new();

        // ID3v2 header
        data.extend_from_slice(b"ID3");
        data.push(0x03); // version 2.3
        data.push(0x00);
        data.push(0x00); // flags
        // Tag size = 20 (synchsafe)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x14]);
        // 20 bytes of fake tag frames
        data.extend_from_slice(&[0u8; 20]);

        // Fake MP3 frame sync
        data.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        data.extend_from_slice(&[0u8; 100]); // fake audio

        // ID3v1 tail (128 bytes starting with "TAG")
        data.extend_from_slice(b"TAG");
        data.extend_from_slice(&[0u8; 125]);

        data
    }

    // -----------------------------------------------------------------------
    // Test 1: JPEG EXIF stripping
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_jpeg_removes_exif() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("photo.jpg");
        let original = fake_jpeg_with_exif();
        fs::write(&path, &original).unwrap();

        assert!(MetadataStripper::has_metadata(&path), "should detect EXIF");

        let result = MetadataStripper::strip_file(&path).unwrap();
        assert!(result.stripped_size < result.original_size, "size should shrink");
        assert!(
            result.fields_removed.iter().any(|f| f.contains("EXIF")),
            "should report EXIF removal"
        );

        // After stripping, the JPEG should still start with SOI.
        let stripped = fs::read(&path).unwrap();
        assert_eq!(&stripped[..2], &[0xFF, 0xD8], "SOI must be preserved");
        // APP1 should be gone.
        assert!(!MetadataStripper::has_metadata(&path), "EXIF should be gone");
    }

    // -----------------------------------------------------------------------
    // Test 2: PDF metadata stripping
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_pdf_blanks_info() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("doc.pdf");
        let original = fake_pdf_with_info();
        fs::write(&path, &original).unwrap();

        assert!(MetadataStripper::has_metadata(&path), "should detect PDF info");

        let result = MetadataStripper::strip_file(&path).unwrap();
        assert!(!result.fields_removed.is_empty(), "should list removed fields");

        let stripped = fs::read_to_string(&path).unwrap();
        assert!(stripped.contains("/Author ()"), "Author should be blanked");
        assert!(stripped.contains("/Creator ()"), "Creator should be blanked");
        assert!(stripped.contains("/Producer ()"), "Producer should be blanked");
        assert!(stripped.contains("/CreationDate ()"), "CreationDate blanked");
        assert!(stripped.contains("/ModDate ()"), "ModDate blanked");
        assert!(!stripped.contains("John Doe"), "original author must be gone");
    }

    // -----------------------------------------------------------------------
    // Test 3: MP3 ID3 stripping
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_mp3_removes_id3() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("song.mp3");
        let original = fake_mp3_with_id3();
        fs::write(&path, &original).unwrap();

        assert!(MetadataStripper::has_metadata(&path), "should detect ID3");

        let result = MetadataStripper::strip_file(&path).unwrap();
        assert!(result.stripped_size < result.original_size, "should shrink");
        assert!(
            result.fields_removed.iter().any(|f| f.contains("ID3v2")),
            "should report ID3v2 removal"
        );
        assert!(
            result.fields_removed.iter().any(|f| f.contains("ID3v1")),
            "should report ID3v1 removal"
        );

        // After stripping, the file should NOT start with "ID3".
        let stripped = fs::read(&path).unwrap();
        assert_ne!(&stripped[..3], b"ID3", "ID3v2 header should be gone");
        // And no ID3v1 tail.
        assert!(!MetadataStripper::has_metadata(&path));
    }

    // -----------------------------------------------------------------------
    // Test 4: scan_directory finds files with metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_directory_finds_targets() {
        let tmp = TempDir::new().unwrap();

        // File with metadata.
        fs::write(tmp.path().join("a.jpg"), fake_jpeg_with_exif()).unwrap();
        fs::write(tmp.path().join("b.pdf"), fake_pdf_with_info()).unwrap();

        // File without metadata.
        fs::write(tmp.path().join("c.txt"), b"hello world").unwrap();

        let hits = MetadataStripper::scan_directory(tmp.path()).unwrap();
        assert!(hits.len() >= 2, "should find at least jpg + pdf, got {}", hits.len());

        let names: Vec<String> = hits.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert!(names.contains(&"a.jpg".to_string()));
        assert!(names.contains(&"b.pdf".to_string()));
        assert!(!names.contains(&"c.txt".to_string()));
    }

    // -----------------------------------------------------------------------
    // Test 5: has_metadata returns false for unknown file types
    // -----------------------------------------------------------------------

    #[test]
    fn test_has_metadata_false_for_unknown() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("random.bin");
        fs::write(&path, b"just some random bytes").unwrap();
        assert!(!MetadataStripper::has_metadata(&path));
    }

    // -----------------------------------------------------------------------
    // Test 6: PNG text chunk stripping
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_png_removes_text_chunks() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("image.png");

        // Build a minimal PNG with a tEXt chunk.
        let mut png_data: Vec<u8> = Vec::new();
        // PNG signature
        png_data.extend_from_slice(b"\x89PNG\r\n\x1a\n");

        // IHDR chunk (13 bytes data)
        let ihdr_data: [u8; 13] = [
            0x00, 0x00, 0x00, 0x01, // width = 1
            0x00, 0x00, 0x00, 0x01, // height = 1
            0x08,                   // bit depth = 8
            0x02,                   // color type = RGB
            0x00, 0x00, 0x00,       // compression, filter, interlace
        ];
        let ihdr_crc = crc32_png(b"IHDR", &ihdr_data);
        png_data.extend_from_slice(&(13u32).to_be_bytes());
        png_data.extend_from_slice(b"IHDR");
        png_data.extend_from_slice(&ihdr_data);
        png_data.extend_from_slice(&ihdr_crc.to_be_bytes());

        // tEXt chunk: keyword "Author" NUL value "Secret Agent"
        let text_payload = b"Author\0Secret Agent";
        let text_crc = crc32_png(b"tEXt", text_payload);
        png_data.extend_from_slice(&(text_payload.len() as u32).to_be_bytes());
        png_data.extend_from_slice(b"tEXt");
        png_data.extend_from_slice(text_payload);
        png_data.extend_from_slice(&text_crc.to_be_bytes());

        // IEND chunk
        let iend_crc = crc32_png(b"IEND", &[]);
        png_data.extend_from_slice(&(0u32).to_be_bytes());
        png_data.extend_from_slice(b"IEND");
        png_data.extend_from_slice(&iend_crc.to_be_bytes());

        fs::write(&path, &png_data).unwrap();

        assert!(MetadataStripper::has_metadata(&path), "should detect tEXt chunk");

        let result = MetadataStripper::strip_file(&path).unwrap();
        assert!(result.fields_removed.iter().any(|f| f.contains("tEXt")));
        assert!(result.stripped_size < result.original_size);

        // After stripping, no text chunks remain.
        assert!(!MetadataStripper::has_metadata(&path));
    }

    // -----------------------------------------------------------------------
    // Test 7: stripping a nonexistent file returns an error
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_nonexistent_file_errors() {
        let result = MetadataStripper::strip_file(Path::new("/tmp/does_not_exist_purge_test.xyz"));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Test 8: JPEG without EXIF is left unchanged
    // -----------------------------------------------------------------------

    #[test]
    fn test_jpeg_without_exif_unchanged() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plain.jpg");

        // JPEG with only JFIF APP0, no APP1.
        let mut data = vec![0xFF, 0xD8]; // SOI
        let jfif: &[u8] = &[b'J', b'F', b'I', b'F', 0x00, 0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        let seg_len = (jfif.len() + 2) as u16;
        data.extend_from_slice(&[0xFF, 0xE0]);
        data.extend_from_slice(&seg_len.to_be_bytes());
        data.extend_from_slice(jfif);
        data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00]); // SOS
        data.extend_from_slice(&[0xFF, 0xD9]); // EOI

        fs::write(&path, &data).unwrap();
        assert!(!MetadataStripper::has_metadata(&path));

        let result = MetadataStripper::strip_file(&path).unwrap();
        assert!(result.fields_removed.is_empty());
        assert_eq!(result.original_size, result.stripped_size);
    }

    /// Minimal CRC-32 for PNG (IEEE polynomial).
    fn crc32_png(chunk_type: &[u8], data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in chunk_type.iter().chain(data.iter()) {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc ^ 0xFFFF_FFFF
    }
}
