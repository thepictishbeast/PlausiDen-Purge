//! Metadata extractor — finds privacy-leaking metadata in files.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Type of metadata found.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetadataType {
    ExifGps,
    ExifCamera,
    ExifTimestamp,
    ExifAuthor,
    ExifSoftware,
    PdfAuthor,
    PdfTitle,
    PdfCreator,
    PdfProducer,
    OfficeAuthor,
    OfficeRevisions,
    OfficeComments,
    XmpData,
    IptcData,
    Custom(String),
}

/// A metadata finding in a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataFinding {
    pub file_path: PathBuf,
    pub metadata_type: String,
    pub value: String,
    pub privacy_risk: PrivacyRisk,
}

/// Privacy risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivacyRisk {
    Low,
    Medium,
    High,
    Critical,
}

/// Metadata extraction engine.
pub struct MetadataExtractor {
    /// File extensions to scan.
    image_exts: Vec<&'static str>,
    document_exts: Vec<&'static str>,
}

impl MetadataExtractor {
    pub fn new() -> Self {
        Self {
            image_exts: vec!["jpg", "jpeg", "png", "tiff", "tif", "heic", "webp", "raw", "cr2", "nef"],
            document_exts: vec!["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp"],
        }
    }

    /// Determine the type of file.
    pub fn classify_file(&self, path: &std::path::Path) -> FileType {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        if self.image_exts.contains(&ext.as_str()) {
            FileType::Image
        } else if self.document_exts.contains(&ext.as_str()) {
            FileType::Document
        } else {
            FileType::Other
        }
    }

    /// Get the privacy risk for a metadata type.
    pub fn risk_for_type(meta_type: &MetadataType) -> PrivacyRisk {
        match meta_type {
            MetadataType::ExifGps => PrivacyRisk::Critical,
            MetadataType::ExifAuthor | MetadataType::PdfAuthor | MetadataType::OfficeAuthor => PrivacyRisk::High,
            MetadataType::ExifCamera | MetadataType::ExifSoftware => PrivacyRisk::Medium,
            MetadataType::ExifTimestamp => PrivacyRisk::Medium,
            MetadataType::PdfTitle | MetadataType::PdfCreator | MetadataType::PdfProducer => PrivacyRisk::Low,
            MetadataType::OfficeRevisions | MetadataType::OfficeComments => PrivacyRisk::High,
            MetadataType::XmpData | MetadataType::IptcData => PrivacyRisk::Medium,
            MetadataType::Custom(_) => PrivacyRisk::Low,
        }
    }

    /// Generate strip commands for a file (uses external tools like exiftool, qpdf).
    pub fn strip_commands(&self, path: &std::path::Path) -> Vec<String> {
        let path_str = path.to_string_lossy();
        match self.classify_file(path) {
            FileType::Image => vec![
                format!("exiftool -all= -overwrite_original \"{path_str}\""),
                format!("# Or use: mat2 \"{path_str}\""),
            ],
            FileType::Document => {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "pdf" {
                    vec![format!("qpdf --linearize --remove-metadata \"{path_str}\" \"{path_str}.clean\"")]
                } else {
                    vec![format!("# Office files: open and use File > Properties > Remove personal info")]
                }
            }
            FileType::Other => vec![format!("# No metadata strip command for {path_str}")],
        }
    }

    /// Quick check if file likely has privacy-sensitive metadata.
    pub fn needs_review(&self, path: &std::path::Path) -> bool {
        !matches!(self.classify_file(path), FileType::Other)
    }
}

impl Default for MetadataExtractor {
    fn default() -> Self { Self::new() }
}

/// Classification of file types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileType {
    Image,
    Document,
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_classify_image() {
        let ext = MetadataExtractor::new();
        assert_eq!(ext.classify_file(Path::new("photo.jpg")), FileType::Image);
        assert_eq!(ext.classify_file(Path::new("photo.PNG")), FileType::Image);
    }

    #[test]
    fn test_classify_document() {
        let ext = MetadataExtractor::new();
        assert_eq!(ext.classify_file(Path::new("report.pdf")), FileType::Document);
        assert_eq!(ext.classify_file(Path::new("data.xlsx")), FileType::Document);
    }

    #[test]
    fn test_classify_other() {
        let ext = MetadataExtractor::new();
        assert_eq!(ext.classify_file(Path::new("script.sh")), FileType::Other);
    }

    #[test]
    fn test_risk_levels() {
        assert_eq!(MetadataExtractor::risk_for_type(&MetadataType::ExifGps), PrivacyRisk::Critical);
        assert_eq!(MetadataExtractor::risk_for_type(&MetadataType::ExifAuthor), PrivacyRisk::High);
        assert_eq!(MetadataExtractor::risk_for_type(&MetadataType::PdfTitle), PrivacyRisk::Low);
    }

    #[test]
    fn test_strip_commands_image() {
        let ext = MetadataExtractor::new();
        let cmds = ext.strip_commands(Path::new("photo.jpg"));
        assert!(cmds.iter().any(|c| c.contains("exiftool")));
    }

    #[test]
    fn test_strip_commands_pdf() {
        let ext = MetadataExtractor::new();
        let cmds = ext.strip_commands(Path::new("doc.pdf"));
        assert!(cmds.iter().any(|c| c.contains("qpdf")));
    }

    #[test]
    fn test_needs_review() {
        let ext = MetadataExtractor::new();
        assert!(ext.needs_review(Path::new("photo.jpg")));
        assert!(ext.needs_review(Path::new("report.pdf")));
        assert!(!ext.needs_review(Path::new("script.sh")));
    }

    #[test]
    fn test_risk_ordering() {
        assert!(PrivacyRisk::Critical > PrivacyRisk::High);
        assert!(PrivacyRisk::High > PrivacyRisk::Medium);
        assert!(PrivacyRisk::Medium > PrivacyRisk::Low);
    }
}
