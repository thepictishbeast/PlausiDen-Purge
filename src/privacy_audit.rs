//! Privacy audit engine — scans the filesystem for sensitive data leaks.
//!
//! Discovers SSH keys in unexpected locations, orphaned PGP/GPG keys,
//! browser-saved passwords, WiFi credentials, API tokens embedded in config
//! files, git credentials, Docker/cloud credentials, cryptocurrency wallet
//! files, and JPEG photos with EXIF GPS metadata.
//!
//! Each finding is tagged with a [`RiskLevel`] so the caller can filter by
//! severity threshold.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Auditor that walks the filesystem looking for privacy-sensitive data.
pub struct PrivacyAuditor {
    /// Only report findings at or above this level.
    pub min_risk: RiskLevel,
    /// Root directories to scan (defaults to user home).
    scan_roots: Vec<PathBuf>,
    /// Home directory override (for testing).
    home_dir: PathBuf,
}

/// Severity of a privacy finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Classification of the sensitive data category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingCategory {
    SshKey,
    GpgKey,
    BrowserPassword,
    WifiPassword,
    ApiToken,
    GitCredential,
    DockerCredential,
    CloudCredential,
    CryptoWallet,
    ExifGps,
}

/// A single privacy finding on disk.
#[derive(Debug, Clone)]
pub struct PrivacyFinding {
    /// Filesystem path where the data was found.
    pub path: PathBuf,
    /// Severity rating.
    pub risk: RiskLevel,
    /// What kind of sensitive data this is.
    pub category: FindingCategory,
    /// Human-readable explanation.
    pub description: String,
}

/// Summary report produced by [`PrivacyAuditor::audit`].
#[derive(Debug)]
pub struct AuditReport {
    pub findings: Vec<PrivacyFinding>,
    pub total_critical: usize,
    pub total_high: usize,
    pub total_medium: usize,
    pub total_low: usize,
    pub scan_duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Patterns we look for inside config files (case-insensitive)
// ---------------------------------------------------------------------------

/// Patterns that indicate an embedded secret in a config file.
const SECRET_PATTERNS: &[&str] = &[
    "api_key=",
    "api_key =",
    "apikey=",
    "api_secret=",
    "token=",
    "access_token=",
    "secret=",
    "secret_key=",
    "password=",
    "passwd=",
    "auth_token=",
    "private_key=",
    "client_secret=",
    "aws_secret_access_key=",
    "aws_access_key_id=",
];

/// File extensions we consider "config files" worth scanning for secrets.
const CONFIG_EXTENSIONS: &[&str] = &[
    "conf", "cfg", "ini", "toml", "yaml", "yml", "json", "env", "properties",
    "xml", "rc",
];

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl PrivacyAuditor {
    /// Create an auditor rooted at the real user home directory.
    pub fn new(min_risk: RiskLevel) -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        Self {
            min_risk,
            scan_roots: vec![home.clone()],
            home_dir: home,
        }
    }

    /// Create an auditor rooted at an arbitrary directory (for testing).
    pub fn with_home(home: PathBuf, min_risk: RiskLevel) -> Self {
        Self {
            min_risk,
            scan_roots: vec![home.clone()],
            home_dir: home,
        }
    }

    /// Run the full audit and return a report.
    pub fn audit(&self) -> AuditReport {
        let start = std::time::Instant::now();
        let mut findings: Vec<PrivacyFinding> = Vec::new();

        self.audit_ssh_keys(&mut findings);
        self.audit_gpg_keys(&mut findings);
        self.audit_browser_passwords(&mut findings);
        self.audit_wifi_passwords(&mut findings);
        self.audit_api_tokens(&mut findings);
        self.audit_git_credentials(&mut findings);
        self.audit_docker_credentials(&mut findings);
        self.audit_cloud_credentials(&mut findings);
        self.audit_crypto_wallets(&mut findings);
        self.audit_exif_gps(&mut findings);

        // Filter by min_risk.
        findings.retain(|f| f.risk >= self.min_risk);

        // Sort: critical first.
        findings.sort_by(|a, b| b.risk.cmp(&a.risk));

        let total_critical = findings.iter().filter(|f| f.risk == RiskLevel::Critical).count();
        let total_high = findings.iter().filter(|f| f.risk == RiskLevel::High).count();
        let total_medium = findings.iter().filter(|f| f.risk == RiskLevel::Medium).count();
        let total_low = findings.iter().filter(|f| f.risk == RiskLevel::Low).count();

        AuditReport {
            findings,
            total_critical,
            total_high,
            total_medium,
            total_low,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    // -----------------------------------------------------------------------
    // 1. SSH keys in unexpected locations
    // -----------------------------------------------------------------------

    fn audit_ssh_keys(&self, findings: &mut Vec<PrivacyFinding>) {
        let expected_ssh_dir = self.home_dir.join(".ssh");

        for root in &self.scan_roots {
            for entry in WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();

                // Skip the canonical ~/.ssh directory.
                if path.starts_with(&expected_ssh_dir) {
                    continue;
                }

                if looks_like_ssh_private_key(path) {
                    findings.push(PrivacyFinding {
                        path: path.to_path_buf(),
                        risk: RiskLevel::Critical,
                        category: FindingCategory::SshKey,
                        description: format!(
                            "SSH private key found outside ~/.ssh: {}",
                            path.display()
                        ),
                    });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 2. PGP/GPG keys outside ~/.gnupg
    // -----------------------------------------------------------------------

    fn audit_gpg_keys(&self, findings: &mut Vec<PrivacyFinding>) {
        let expected_gpg_dir = self.home_dir.join(".gnupg");

        for root in &self.scan_roots {
            for entry in WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();

                if path.starts_with(&expected_gpg_dir) {
                    continue;
                }

                let name = path.file_name().unwrap_or_default().to_string_lossy();
                let is_gpg_file = name.ends_with(".gpg")
                    || name.ends_with(".pgp")
                    || name.ends_with(".asc")
                    || name == "secring.gpg"
                    || name == "pubring.gpg"
                    || name == "trustdb.gpg";

                if is_gpg_file && looks_like_gpg_key(path) {
                    findings.push(PrivacyFinding {
                        path: path.to_path_buf(),
                        risk: RiskLevel::High,
                        category: FindingCategory::GpgKey,
                        description: format!(
                            "PGP/GPG key material outside ~/.gnupg: {}",
                            path.display()
                        ),
                    });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3. Browser saved passwords
    // -----------------------------------------------------------------------

    fn audit_browser_passwords(&self, findings: &mut Vec<PrivacyFinding>) {
        // Chromium-based: "Login Data" (SQLite)
        // Firefox: "logins.json"
        let password_filenames: HashSet<&str> =
            ["Login Data", "logins.json", "signons.sqlite", "key4.db"]
                .iter()
                .copied()
                .collect();

        for root in &self.scan_roots {
            for entry in WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy();
                if password_filenames.contains(name.as_ref()) {
                    findings.push(PrivacyFinding {
                        path: entry.path().to_path_buf(),
                        risk: RiskLevel::Critical,
                        category: FindingCategory::BrowserPassword,
                        description: format!(
                            "Browser saved passwords: {}",
                            entry.path().display()
                        ),
                    });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 4. WiFi passwords
    // -----------------------------------------------------------------------

    fn audit_wifi_passwords(&self, findings: &mut Vec<PrivacyFinding>) {
        let nm_dir = PathBuf::from("/etc/NetworkManager/system-connections");
        if !nm_dir.is_dir() {
            return;
        }

        for entry in WalkDir::new(&nm_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            // NetworkManager connection files contain psk= lines.
            if file_contains_pattern(entry.path(), &["psk=", "password="]) {
                findings.push(PrivacyFinding {
                    path: entry.path().to_path_buf(),
                    risk: RiskLevel::High,
                    category: FindingCategory::WifiPassword,
                    description: format!(
                        "WiFi password stored in NetworkManager config: {}",
                        entry.path().display()
                    ),
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // 5. API tokens/keys in config files
    // -----------------------------------------------------------------------

    fn audit_api_tokens(&self, findings: &mut Vec<PrivacyFinding>) {
        for root in &self.scan_roots {
            for entry in WalkDir::new(root)
                .follow_links(false)
                .max_depth(5) // Avoid going too deep.
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();

                if !is_config_file(path) {
                    continue;
                }

                // Skip very large files (> 1 MiB).
                let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                if size > 1_048_576 || size == 0 {
                    continue;
                }

                if file_contains_pattern(path, SECRET_PATTERNS) {
                    findings.push(PrivacyFinding {
                        path: path.to_path_buf(),
                        risk: RiskLevel::High,
                        category: FindingCategory::ApiToken,
                        description: format!(
                            "Config file contains API key/token/secret: {}",
                            path.display()
                        ),
                    });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 6. Git credentials
    // -----------------------------------------------------------------------

    fn audit_git_credentials(&self, findings: &mut Vec<PrivacyFinding>) {
        let git_cred_files = [
            self.home_dir.join(".gitconfig"),
            self.home_dir.join(".git-credentials"),
            self.home_dir.join(".config/git/credentials"),
        ];

        for path in &git_cred_files {
            if path.is_file() {
                // .git-credentials is always sensitive — it stores plaintext tokens.
                let risk = if path.file_name().unwrap_or_default() == "credentials"
                    || path.file_name().unwrap_or_default() == ".git-credentials"
                {
                    RiskLevel::Critical
                } else {
                    // .gitconfig might contain a credential helper reference (medium risk).
                    RiskLevel::Medium
                };

                findings.push(PrivacyFinding {
                    path: path.clone(),
                    risk,
                    category: FindingCategory::GitCredential,
                    description: format!(
                        "Git credential file: {}",
                        path.display()
                    ),
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // 7. Docker credentials
    // -----------------------------------------------------------------------

    fn audit_docker_credentials(&self, findings: &mut Vec<PrivacyFinding>) {
        let docker_config = self.home_dir.join(".docker/config.json");
        if docker_config.is_file() {
            // Check if it contains "auths" with actual tokens.
            if file_contains_pattern(&docker_config, &["\"auths\"", "\"auth\""]) {
                findings.push(PrivacyFinding {
                    path: docker_config,
                    risk: RiskLevel::High,
                    category: FindingCategory::DockerCredential,
                    description: "Docker registry credentials stored in config.json".to_string(),
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // 8. Cloud credentials (AWS, GCloud, Azure)
    // -----------------------------------------------------------------------

    fn audit_cloud_credentials(&self, findings: &mut Vec<PrivacyFinding>) {
        let cloud_paths = [
            (self.home_dir.join(".aws/credentials"), "AWS credentials"),
            (self.home_dir.join(".aws/config"), "AWS config (may contain session tokens)"),
            (
                self.home_dir.join(".config/gcloud/credentials.db"),
                "Google Cloud credentials database",
            ),
            (
                self.home_dir.join(".config/gcloud/application_default_credentials.json"),
                "Google Cloud application default credentials",
            ),
            (self.home_dir.join(".azure/accessTokens.json"), "Azure access tokens"),
            (self.home_dir.join(".azure/azureProfile.json"), "Azure profile"),
        ];

        for (path, desc) in &cloud_paths {
            if path.is_file() {
                findings.push(PrivacyFinding {
                    path: path.clone(),
                    risk: RiskLevel::Critical,
                    category: FindingCategory::CloudCredential,
                    description: format!("{desc}: {}", path.display()),
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // 9. Cryptocurrency wallets
    // -----------------------------------------------------------------------

    fn audit_crypto_wallets(&self, findings: &mut Vec<PrivacyFinding>) {
        let known_wallet_dirs = [
            (self.home_dir.join(".bitcoin"), "Bitcoin wallet"),
            (self.home_dir.join(".ethereum"), "Ethereum wallet"),
            (self.home_dir.join(".monero"), "Monero wallet"),
            (self.home_dir.join(".electrum"), "Electrum wallet"),
        ];

        for (dir, desc) in &known_wallet_dirs {
            if dir.is_dir() {
                findings.push(PrivacyFinding {
                    path: dir.clone(),
                    risk: RiskLevel::Critical,
                    category: FindingCategory::CryptoWallet,
                    description: format!("{desc} directory: {}", dir.display()),
                });
            }
        }

        // Scan for stray .wallet files and seed phrase files.
        for root in &self.scan_roots {
            for entry in WalkDir::new(root)
                .follow_links(false)
                .max_depth(5)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_lowercase();

                if name.ends_with(".wallet")
                    || name.contains("seed_phrase")
                    || name.contains("seedphrase")
                    || name.contains("mnemonic")
                    || name == "wallet.dat"
                {
                    findings.push(PrivacyFinding {
                        path: entry.path().to_path_buf(),
                        risk: RiskLevel::Critical,
                        category: FindingCategory::CryptoWallet,
                        description: format!(
                            "Cryptocurrency wallet/seed file: {}",
                            entry.path().display()
                        ),
                    });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 10. JPEG photos with EXIF GPS data
    // -----------------------------------------------------------------------

    fn audit_exif_gps(&self, findings: &mut Vec<PrivacyFinding>) {
        for root in &self.scan_roots {
            for entry in WalkDir::new(root)
                .follow_links(false)
                .max_depth(5)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_lowercase();
                if !(name.ends_with(".jpg") || name.ends_with(".jpeg")) {
                    continue;
                }

                if jpeg_has_exif_gps(entry.path()) {
                    findings.push(PrivacyFinding {
                        path: entry.path().to_path_buf(),
                        risk: RiskLevel::Medium,
                        category: FindingCategory::ExifGps,
                        description: format!(
                            "JPEG with EXIF GPS coordinates: {}",
                            entry.path().display()
                        ),
                    });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Check whether a file looks like an SSH private key by reading its header.
fn looks_like_ssh_private_key(path: &Path) -> bool {
    let mut buf = [0u8; 64];
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let Ok(n) = f.read(&mut buf) else {
        return false;
    };
    let header = String::from_utf8_lossy(&buf[..n]);
    header.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || header.contains("-----BEGIN RSA PRIVATE KEY-----")
        || header.contains("-----BEGIN EC PRIVATE KEY-----")
        || header.contains("-----BEGIN DSA PRIVATE KEY-----")
}

/// Check whether a file is GPG key material (by extension + header sniff).
fn looks_like_gpg_key(path: &Path) -> bool {
    let mut buf = [0u8; 128];
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let Ok(n) = f.read(&mut buf) else {
        return false;
    };
    let header = String::from_utf8_lossy(&buf[..n]);
    header.contains("-----BEGIN PGP")
        || header.contains("-----BEGIN GPG")
        // Binary GPG keys start with specific packet tags.
        || (n >= 2 && (buf[0] & 0x80 != 0))
}

/// Return `true` if any line in the file contains any of the given patterns
/// (case-insensitive).
fn file_contains_pattern(path: &Path, patterns: &[&str]) -> bool {
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    let lower = content.to_lowercase();
    patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
}

/// Determine whether a path is a config file worth scanning for secrets.
fn is_config_file(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();

    // Dotfiles like .env, .bashrc, etc.
    if name.starts_with('.') && !name.starts_with("..") {
        return true;
    }

    // Check extension.
    if let Some(ext) = path.extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        if CONFIG_EXTENSIONS.contains(&ext_lower.as_ref()) {
            return true;
        }
    }

    false
}

/// Minimal EXIF GPS detection for JPEG files.
///
/// Looks for the EXIF GPS IFD tag (0x8825) inside the APP1 segment.
/// This is a lightweight heuristic — not a full EXIF parser — to avoid
/// pulling in heavy image dependencies.
fn jpeg_has_exif_gps(path: &Path) -> bool {
    let mut buf = vec![0u8; 65536]; // Read up to 64 KiB (EXIF is in APP1 near the start).
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let Ok(n) = f.read(&mut buf) else {
        return false;
    };
    let data = &buf[..n];

    // Must start with JPEG SOI marker.
    if n < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return false;
    }

    // Search for the GPS IFD pointer tag (0x88 0x25) in big-endian or
    // (0x25 0x88) in little-endian EXIF.
    // The tag number 0x8825 marks the GPS Info IFD.
    for i in 2..n.saturating_sub(1) {
        if (data[i] == 0x88 && data[i + 1] == 0x25)
            || (data[i] == 0x25 && data[i + 1] == 0x88)
        {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SshKey => write!(f, "SSH Key"),
            Self::GpgKey => write!(f, "GPG Key"),
            Self::BrowserPassword => write!(f, "Browser Password"),
            Self::WifiPassword => write!(f, "WiFi Password"),
            Self::ApiToken => write!(f, "API Token"),
            Self::GitCredential => write!(f, "Git Credential"),
            Self::DockerCredential => write!(f, "Docker Credential"),
            Self::CloudCredential => write!(f, "Cloud Credential"),
            Self::CryptoWallet => write!(f, "Crypto Wallet"),
            Self::ExifGps => write!(f, "EXIF GPS"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // -- test: SSH key outside ~/.ssh is flagged as Critical --------------------
    #[test]
    fn test_ssh_key_outside_ssh_dir() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();

        // Legitimate key in ~/.ssh — should NOT be reported.
        let ssh_dir = home.join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(
            ssh_dir.join("id_rsa"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n",
        )
        .unwrap();

        // Stray key in ~/Documents — SHOULD be reported.
        let docs = home.join("Documents");
        fs::create_dir_all(&docs).unwrap();
        fs::write(
            docs.join("backup_key"),
            "-----BEGIN RSA PRIVATE KEY-----\nfake\n",
        )
        .unwrap();

        let auditor = PrivacyAuditor::with_home(home.to_path_buf(), RiskLevel::Low);
        let report = auditor.audit();

        let ssh_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::SshKey)
            .collect();

        assert_eq!(ssh_findings.len(), 1, "Should find exactly 1 stray SSH key");
        assert_eq!(ssh_findings[0].risk, RiskLevel::Critical);
        assert!(
            ssh_findings[0].path.to_string_lossy().contains("Documents"),
            "Finding should be in Documents, not .ssh"
        );
    }

    // -- test: Browser password files are flagged ------------------------------
    #[test]
    fn test_browser_passwords_detected() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();

        // Chromium-style Login Data.
        let chrome = home.join(".config/google-chrome/Default");
        fs::create_dir_all(&chrome).unwrap();
        fs::write(chrome.join("Login Data"), "sqlite-blob").unwrap();

        // Firefox-style logins.json.
        let ff = home.join(".mozilla/firefox/abc.default");
        fs::create_dir_all(&ff).unwrap();
        fs::write(ff.join("logins.json"), "{}").unwrap();

        let auditor = PrivacyAuditor::with_home(home.to_path_buf(), RiskLevel::Low);
        let report = auditor.audit();

        let pw_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::BrowserPassword)
            .collect();

        assert!(
            pw_findings.len() >= 2,
            "Should find at least Login Data and logins.json, found {}",
            pw_findings.len()
        );
        assert!(pw_findings.iter().all(|f| f.risk == RiskLevel::Critical));
    }

    // -- test: API tokens in config files are flagged --------------------------
    #[test]
    fn test_api_tokens_in_config_files() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();

        // A config file with a secret.
        fs::write(
            home.join(".env"),
            "DATABASE_URL=postgres://...\napi_key=sk-12345abcdef\n",
        )
        .unwrap();

        // A YAML config with a token.
        fs::write(
            home.join("service.yaml"),
            "service:\n  token= ghp_xxxxxxxxxxxx\n",
        )
        .unwrap();

        // A non-config file (should be ignored).
        fs::write(home.join("readme.txt"), "api_key=not-a-config").unwrap();

        let auditor = PrivacyAuditor::with_home(home.to_path_buf(), RiskLevel::Low);
        let report = auditor.audit();

        let token_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::ApiToken)
            .collect();

        assert!(
            token_findings.len() >= 2,
            "Should find secrets in .env and .yaml, found {}",
            token_findings.len()
        );
    }

    // -- test: Git credentials detected ----------------------------------------
    #[test]
    fn test_git_credentials_detected() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();

        fs::write(
            home.join(".git-credentials"),
            "https://user:ghp_token@github.com\n",
        )
        .unwrap();
        fs::write(
            home.join(".gitconfig"),
            "[user]\n  name = Test\n[credential]\n  helper = store\n",
        )
        .unwrap();

        let auditor = PrivacyAuditor::with_home(home.to_path_buf(), RiskLevel::Low);
        let report = auditor.audit();

        let git_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::GitCredential)
            .collect();

        assert_eq!(
            git_findings.len(),
            2,
            "Should find .git-credentials and .gitconfig"
        );

        // .git-credentials should be Critical, .gitconfig should be Medium.
        let crit = git_findings.iter().find(|f| f.risk == RiskLevel::Critical);
        assert!(crit.is_some(), ".git-credentials should be Critical");
        let med = git_findings.iter().find(|f| f.risk == RiskLevel::Medium);
        assert!(med.is_some(), ".gitconfig should be Medium");
    }

    // -- test: Cloud credentials detected --------------------------------------
    #[test]
    fn test_cloud_credentials_detected() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();

        let aws = home.join(".aws");
        fs::create_dir_all(&aws).unwrap();
        fs::write(
            aws.join("credentials"),
            "[default]\naws_access_key_id = AKIA...\naws_secret_access_key = secret\n",
        )
        .unwrap();

        let gcloud = home.join(".config/gcloud");
        fs::create_dir_all(&gcloud).unwrap();
        fs::write(
            gcloud.join("application_default_credentials.json"),
            "{}",
        )
        .unwrap();

        let auditor = PrivacyAuditor::with_home(home.to_path_buf(), RiskLevel::Low);
        let report = auditor.audit();

        let cloud_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::CloudCredential)
            .collect();

        assert!(
            cloud_findings.len() >= 2,
            "Should find AWS + GCloud credentials, found {}",
            cloud_findings.len()
        );
        assert!(cloud_findings.iter().all(|f| f.risk == RiskLevel::Critical));
    }

    // -- test: Crypto wallet files detected ------------------------------------
    #[test]
    fn test_crypto_wallets_detected() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();

        // Known wallet directory.
        let btc = home.join(".bitcoin");
        fs::create_dir_all(&btc).unwrap();
        fs::write(btc.join("wallet.dat"), "fake-wallet").unwrap();

        // Stray wallet file.
        fs::write(home.join("backup.wallet"), "wallet-backup").unwrap();

        // Seed phrase file.
        fs::write(home.join("seed_phrase.txt"), "abandon abandon ...").unwrap();

        let auditor = PrivacyAuditor::with_home(home.to_path_buf(), RiskLevel::Low);
        let report = auditor.audit();

        let crypto_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::CryptoWallet)
            .collect();

        // .bitcoin dir + wallet.dat + backup.wallet + seed_phrase.txt = at least 4.
        assert!(
            crypto_findings.len() >= 3,
            "Should find wallet dir + stray files, found {}",
            crypto_findings.len()
        );
        assert!(crypto_findings.iter().all(|f| f.risk == RiskLevel::Critical));
    }

    // -- test: EXIF GPS in JPEG is flagged -------------------------------------
    #[test]
    fn test_exif_gps_detection() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();

        // Build a minimal JPEG-like file with the GPS IFD tag bytes.
        // SOI marker (0xFFD8) + APP1 marker + Exif header + GPS tag (0x8825).
        let mut fake_jpeg: Vec<u8> = vec![
            0xFF, 0xD8, // SOI
            0xFF, 0xE1, // APP1 marker
            0x00, 0x20, // Segment length (32 bytes)
            b'E', b'x', b'i', b'f', 0x00, 0x00, // "Exif\0\0"
            0x4D, 0x4D, // Big-endian ("MM")
            0x00, 0x2A, // TIFF magic
            0x00, 0x00, 0x00, 0x08, // Offset to first IFD
            // Fake IFD with GPS tag
            0x00, 0x01, // Number of entries: 1
            0x88, 0x25, // Tag: GPSInfo (0x8825)
            0x00, 0x04, // Type: LONG
            0x00, 0x00, 0x00, 0x01, // Count: 1
            0x00, 0x00, 0x00, 0x00, // Value: offset 0
        ];
        // Pad to make it look more realistic.
        fake_jpeg.extend_from_slice(&[0u8; 32]);

        fs::write(home.join("photo.jpg"), &fake_jpeg).unwrap();

        // A JPEG without GPS data.
        let plain_jpeg = vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10,
            b'J', b'F', b'I', b'F', 0x00, 0x01,
            0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        ];
        fs::write(home.join("plain.jpg"), &plain_jpeg).unwrap();

        let auditor = PrivacyAuditor::with_home(home.to_path_buf(), RiskLevel::Low);
        let report = auditor.audit();

        let exif_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::ExifGps)
            .collect();

        assert_eq!(exif_findings.len(), 1, "Should flag the GPS JPEG but not the plain one");
        assert!(exif_findings[0].path.to_string_lossy().contains("photo.jpg"));
        assert_eq!(exif_findings[0].risk, RiskLevel::Medium);
    }

    // -- test: min_risk filtering works ----------------------------------------
    #[test]
    fn test_min_risk_filters_findings() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();

        // Medium risk item: .gitconfig
        fs::write(
            home.join(".gitconfig"),
            "[user]\n  name = Test\n",
        )
        .unwrap();

        // Critical risk item: .git-credentials
        fs::write(
            home.join(".git-credentials"),
            "https://user:token@github.com\n",
        )
        .unwrap();

        // Audit at Critical level — should only see .git-credentials.
        let auditor = PrivacyAuditor::with_home(home.to_path_buf(), RiskLevel::Critical);
        let report = auditor.audit();

        let git_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::GitCredential)
            .collect();

        assert_eq!(
            git_findings.len(),
            1,
            "Critical filter should exclude Medium .gitconfig"
        );
        assert_eq!(git_findings[0].risk, RiskLevel::Critical);
    }

    // -- test: Docker credentials detected -------------------------------------
    #[test]
    fn test_docker_credentials_detected() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();

        let docker_dir = home.join(".docker");
        fs::create_dir_all(&docker_dir).unwrap();
        fs::write(
            docker_dir.join("config.json"),
            r#"{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}"#,
        )
        .unwrap();

        let auditor = PrivacyAuditor::with_home(home.to_path_buf(), RiskLevel::Low);
        let report = auditor.audit();

        let docker_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::DockerCredential)
            .collect();

        assert_eq!(docker_findings.len(), 1, "Should find Docker credentials");
        assert_eq!(docker_findings[0].risk, RiskLevel::High);
    }
}
