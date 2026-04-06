//! File type registry — classify files by extension and magic bytes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Category of file content.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileCategory {
    Document,
    Image,
    Video,
    Audio,
    Archive,
    Executable,
    SourceCode,
    Database,
    Config,
    Log,
    Unknown,
}

/// Classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileClassification {
    pub category: FileCategory,
    pub mime_hint: String,
    pub from_extension: bool,
    pub from_magic: bool,
    pub sensitive: bool,
}

/// File type registry.
pub struct FileRegistry {
    extensions: HashMap<String, (FileCategory, String)>,
    magic_signatures: Vec<MagicSignature>,
    sensitive_extensions: std::collections::HashSet<String>,
}

#[derive(Debug, Clone)]
struct MagicSignature {
    bytes: Vec<u8>,
    offset: usize,
    category: FileCategory,
    mime: String,
}

impl FileRegistry {
    pub fn new() -> Self {
        let mut r = Self {
            extensions: HashMap::new(),
            magic_signatures: Vec::new(),
            sensitive_extensions: std::collections::HashSet::new(),
        };
        r.load_defaults();
        r
    }

    fn load_defaults(&mut self) {
        // Documents.
        for (ext, mime) in [
            ("pdf", "application/pdf"),
            ("doc", "application/msword"),
            ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            ("odt", "application/vnd.oasis.opendocument.text"),
            ("txt", "text/plain"),
            ("rtf", "application/rtf"),
            ("md", "text/markdown"),
        ] {
            self.extensions.insert(ext.into(), (FileCategory::Document, mime.into()));
        }

        // Images.
        for (ext, mime) in [
            ("jpg", "image/jpeg"), ("jpeg", "image/jpeg"),
            ("png", "image/png"),
            ("gif", "image/gif"),
            ("webp", "image/webp"),
            ("tiff", "image/tiff"),
            ("svg", "image/svg+xml"),
        ] {
            self.extensions.insert(ext.into(), (FileCategory::Image, mime.into()));
        }

        // Videos.
        for (ext, mime) in [
            ("mp4", "video/mp4"),
            ("mkv", "video/x-matroska"),
            ("webm", "video/webm"),
            ("avi", "video/x-msvideo"),
            ("mov", "video/quicktime"),
        ] {
            self.extensions.insert(ext.into(), (FileCategory::Video, mime.into()));
        }

        // Audio.
        for (ext, mime) in [
            ("mp3", "audio/mpeg"),
            ("flac", "audio/flac"),
            ("ogg", "audio/ogg"),
            ("wav", "audio/wav"),
            ("opus", "audio/opus"),
        ] {
            self.extensions.insert(ext.into(), (FileCategory::Audio, mime.into()));
        }

        // Archives.
        for (ext, mime) in [
            ("zip", "application/zip"),
            ("tar", "application/x-tar"),
            ("gz", "application/gzip"),
            ("bz2", "application/x-bzip2"),
            ("xz", "application/x-xz"),
            ("7z", "application/x-7z-compressed"),
        ] {
            self.extensions.insert(ext.into(), (FileCategory::Archive, mime.into()));
        }

        // Source code.
        for (ext, mime) in [
            ("rs", "text/x-rust"),
            ("py", "text/x-python"),
            ("js", "text/javascript"),
            ("ts", "text/typescript"),
            ("c", "text/x-c"),
            ("h", "text/x-c-header"),
            ("cpp", "text/x-c++"),
            ("go", "text/x-go"),
            ("java", "text/x-java"),
        ] {
            self.extensions.insert(ext.into(), (FileCategory::SourceCode, mime.into()));
        }

        // Databases.
        for (ext, mime) in [
            ("sqlite", "application/vnd.sqlite3"),
            ("sqlite3", "application/vnd.sqlite3"),
            ("db", "application/x-sqlite3"),
        ] {
            self.extensions.insert(ext.into(), (FileCategory::Database, mime.into()));
        }

        // Config.
        for (ext, mime) in [
            ("toml", "application/toml"),
            ("yaml", "application/x-yaml"),
            ("yml", "application/x-yaml"),
            ("json", "application/json"),
            ("ini", "text/plain"),
            ("conf", "text/plain"),
        ] {
            self.extensions.insert(ext.into(), (FileCategory::Config, mime.into()));
        }

        // Logs.
        self.extensions.insert("log".into(), (FileCategory::Log, "text/plain".into()));

        // Magic signatures.
        self.magic_signatures.push(MagicSignature {
            bytes: vec![0x89, 0x50, 0x4e, 0x47],
            offset: 0,
            category: FileCategory::Image,
            mime: "image/png".into(),
        });
        self.magic_signatures.push(MagicSignature {
            bytes: vec![0xff, 0xd8, 0xff],
            offset: 0,
            category: FileCategory::Image,
            mime: "image/jpeg".into(),
        });
        self.magic_signatures.push(MagicSignature {
            bytes: vec![0x25, 0x50, 0x44, 0x46],
            offset: 0,
            category: FileCategory::Document,
            mime: "application/pdf".into(),
        });
        self.magic_signatures.push(MagicSignature {
            bytes: vec![0x50, 0x4b, 0x03, 0x04],
            offset: 0,
            category: FileCategory::Archive,
            mime: "application/zip".into(),
        });
        self.magic_signatures.push(MagicSignature {
            bytes: vec![0x7f, 0x45, 0x4c, 0x46],
            offset: 0,
            category: FileCategory::Executable,
            mime: "application/x-elf".into(),
        });
        self.magic_signatures.push(MagicSignature {
            bytes: b"SQLite format 3".to_vec(),
            offset: 0,
            category: FileCategory::Database,
            mime: "application/vnd.sqlite3".into(),
        });

        // Sensitive extensions.
        for ext in &["pdf", "doc", "docx", "odt", "sqlite", "sqlite3", "db", "key", "pem", "p12", "pfx"] {
            self.sensitive_extensions.insert((*ext).into());
        }
    }

    /// Classify by extension only.
    pub fn classify_by_extension(&self, path: &Path) -> Option<FileClassification> {
        let ext = path.extension()?.to_str()?.to_lowercase();
        let (category, mime) = self.extensions.get(&ext)?;
        Some(FileClassification {
            category: category.clone(),
            mime_hint: mime.clone(),
            from_extension: true,
            from_magic: false,
            sensitive: self.sensitive_extensions.contains(&ext),
        })
    }

    /// Classify by magic bytes.
    pub fn classify_by_magic(&self, content: &[u8]) -> Option<FileClassification> {
        for sig in &self.magic_signatures {
            if content.len() >= sig.offset + sig.bytes.len()
                && content[sig.offset..sig.offset + sig.bytes.len()] == sig.bytes[..]
            {
                return Some(FileClassification {
                    category: sig.category.clone(),
                    mime_hint: sig.mime.clone(),
                    from_extension: false,
                    from_magic: true,
                    sensitive: false,
                });
            }
        }
        None
    }

    /// Classify using both methods, preferring magic bytes.
    pub fn classify(&self, path: &Path, content: Option<&[u8]>) -> FileClassification {
        if let Some(bytes) = content {
            if let Some(cls) = self.classify_by_magic(bytes) {
                return cls;
            }
        }
        self.classify_by_extension(path).unwrap_or(FileClassification {
            category: FileCategory::Unknown,
            mime_hint: "application/octet-stream".into(),
            from_extension: false,
            from_magic: false,
            sensitive: false,
        })
    }

    /// Detect extension/magic mismatch (could indicate file hiding).
    pub fn check_mismatch(&self, path: &Path, content: &[u8]) -> bool {
        let by_ext = self.classify_by_extension(path);
        let by_magic = self.classify_by_magic(content);
        match (by_ext, by_magic) {
            (Some(e), Some(m)) => e.category != m.category,
            _ => false,
        }
    }

    /// Registered extensions.
    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }
}

impl Default for FileRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_extension_classification() {
        let r = FileRegistry::new();
        let cls = r.classify_by_extension(&PathBuf::from("/home/user/doc.pdf")).unwrap();
        assert_eq!(cls.category, FileCategory::Document);
        assert!(cls.sensitive);
    }

    #[test]
    fn test_magic_classification_png() {
        let r = FileRegistry::new();
        let content = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
        let cls = r.classify_by_magic(&content).unwrap();
        assert_eq!(cls.category, FileCategory::Image);
        assert_eq!(cls.mime_hint, "image/png");
    }

    #[test]
    fn test_magic_beats_extension() {
        let r = FileRegistry::new();
        // PNG content but .txt extension.
        let content = vec![0x89, 0x50, 0x4e, 0x47];
        let cls = r.classify(&PathBuf::from("not_an_image.txt"), Some(&content));
        assert_eq!(cls.category, FileCategory::Image);
    }

    #[test]
    fn test_mismatch_detection() {
        let r = FileRegistry::new();
        let content = vec![0x89, 0x50, 0x4e, 0x47];
        assert!(r.check_mismatch(&PathBuf::from("fake.pdf"), &content));
    }

    #[test]
    fn test_no_mismatch_on_match() {
        let r = FileRegistry::new();
        let content = vec![0x89, 0x50, 0x4e, 0x47];
        assert!(!r.check_mismatch(&PathBuf::from("real.png"), &content));
    }

    #[test]
    fn test_unknown_fallback() {
        let r = FileRegistry::new();
        let cls = r.classify(&PathBuf::from("weird.xyz"), None);
        assert_eq!(cls.category, FileCategory::Unknown);
    }

    #[test]
    fn test_source_code() {
        let r = FileRegistry::new();
        let cls = r.classify_by_extension(&PathBuf::from("main.rs")).unwrap();
        assert_eq!(cls.category, FileCategory::SourceCode);
    }

    #[test]
    fn test_archive() {
        let r = FileRegistry::new();
        let content = vec![0x50, 0x4b, 0x03, 0x04];
        let cls = r.classify_by_magic(&content).unwrap();
        assert_eq!(cls.category, FileCategory::Archive);
    }

    #[test]
    fn test_elf() {
        let r = FileRegistry::new();
        let content = vec![0x7f, 0x45, 0x4c, 0x46];
        let cls = r.classify_by_magic(&content).unwrap();
        assert_eq!(cls.category, FileCategory::Executable);
    }

    #[test]
    fn test_sqlite_magic() {
        let r = FileRegistry::new();
        let content = b"SQLite format 3\0".to_vec();
        let cls = r.classify_by_magic(&content).unwrap();
        assert_eq!(cls.category, FileCategory::Database);
    }

    #[test]
    fn test_extension_count() {
        let r = FileRegistry::new();
        assert!(r.extension_count() > 30);
    }
}
