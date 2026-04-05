//! File type detection — identify files by magic bytes, not extension.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileType {
    Jpeg, Png, Gif, Bmp, Webp, Pdf, Zip, Gzip, Bzip2, Xz, SevenZip,
    Tar, Rar, Exe, Elf, MachO, Sqlite, Mp3, Mp4, Flac, Ogg,
    Docx, Xlsx, Java, Deb, Rpm, Unknown,
}

/// Detect file type from magic bytes.
pub fn detect(data: &[u8]) -> FileType {
    if data.len() < 4 { return FileType::Unknown; }
    match &data[..4] {
        [0xFF, 0xD8, 0xFF, _] => FileType::Jpeg,
        [0x89, b'P', b'N', b'G'] => FileType::Png,
        [b'G', b'I', b'F', b'8'] => FileType::Gif,
        [b'B', b'M', _, _] => FileType::Bmp,
        [b'R', b'I', b'F', b'F'] if data.len() > 12 && &data[8..12] == b"WEBP" => FileType::Webp,
        [b'%', b'P', b'D', b'F'] => FileType::Pdf,
        [b'P', b'K', 0x03, 0x04] => {
            if data.len() > 30 && std::str::from_utf8(&data[30..]).ok().map(|s| s.starts_with("word/")).unwrap_or(false) { FileType::Docx }
            else if data.len() > 30 && std::str::from_utf8(&data[30..]).ok().map(|s| s.starts_with("xl/")).unwrap_or(false) { FileType::Xlsx }
            else { FileType::Zip }
        },
        [0x1F, 0x8B, _, _] => FileType::Gzip,
        [b'B', b'Z', b'h', _] => FileType::Bzip2,
        [0xFD, b'7', b'z', b'X'] => FileType::Xz,
        [b'7', b'z', 0xBC, 0xAF] => FileType::SevenZip,
        [0x7F, b'E', b'L', b'F'] => FileType::Elf,
        [b'M', b'Z', _, _] => FileType::Exe,
        [0xCF, 0xFA, 0xED, 0xFE] | [0xFE, 0xED, 0xFA, 0xCF] => FileType::MachO,
        [b'S', b'Q', b'L', b'i'] => FileType::Sqlite,
        [b'I', b'D', b'3', _] | [0xFF, 0xFB, _, _] => FileType::Mp3,
        [b'f', b'L', b'a', b'C'] => FileType::Flac,
        [b'O', b'g', b'g', b'S'] => FileType::Ogg,
        [0xCA, 0xFE, b'B', b'A'] => FileType::Java,
        _ => {
            if data.len() > 8 && &data[4..8] == b"ftyp" { FileType::Mp4 }
            else if data.starts_with(b"!<arch>\n") && data.len() > 68 && std::str::from_utf8(&data[8..]).ok().map(|s| s.contains("debian")).unwrap_or(false) { FileType::Deb }
            else { FileType::Unknown }
        }
    }
}

/// Detect from file path (reads first 64 bytes).
pub fn detect_file(path: &Path) -> FileType {
    std::fs::read(path).ok().map(|d| detect(&d)).unwrap_or(FileType::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jpeg() { assert_eq!(detect(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]), FileType::Jpeg); }
    #[test]
    fn test_png() { assert_eq!(detect(&[0x89, b'P', b'N', b'G', 0x0D]), FileType::Png); }
    #[test]
    fn test_pdf() { assert_eq!(detect(b"%PDF-1.7"), FileType::Pdf); }
    #[test]
    fn test_elf() { assert_eq!(detect(&[0x7F, b'E', b'L', b'F', 0x02]), FileType::Elf); }
    #[test]
    fn test_zip() { assert_eq!(detect(&[b'P', b'K', 0x03, 0x04, 0x00]), FileType::Zip); }
    #[test]
    fn test_sqlite() { assert_eq!(detect(b"SQLite format 3"), FileType::Sqlite); }
    #[test]
    fn test_unknown() { assert_eq!(detect(b"random data here"), FileType::Unknown); }
    #[test]
    fn test_short() { assert_eq!(detect(&[0x00, 0x01]), FileType::Unknown); }
}
