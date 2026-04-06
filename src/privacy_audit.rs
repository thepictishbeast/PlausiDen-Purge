//! Privacy auditor — scans the system for privacy-sensitive data.
//!
//! Detects browser history, cookies, saved passwords, shell history files,
//! SSH keys, clipboard manager data, thumbnail caches, recently-accessed
//! file lists, and system logs with user activity. Each finding is scored
//! by risk level with a recommended remediation action.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Category of privacy-sensitive data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyCategory {
    BrowserData,
    ShellHistory,
    SshData,
    ClipboardHistory,
    Thumbnails,
    RecentFiles,
    SystemLogs,
    Credentials,
    TempFiles,
}

impl std::fmt::Display for PrivacyCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BrowserData => write!(f, "Browser Data"),
            Self::ShellHistory => write!(f, "Shell History"),
            Self::SshData => write!(f, "SSH Data"),
            Self::ClipboardHistory => write!(f, "Clipboard History"),
            Self::Thumbnails => write!(f, "Thumbnails"),
            Self::RecentFiles => write!(f, "Recent Files"),
            Self::SystemLogs => write!(f, "System Logs"),
            Self::Credentials => write!(f, "Credentials"),
            Self::TempFiles => write!(f, "Temp Files"),
        }
    }
}

/// Risk level of a finding — higher means more urgently actionable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Numeric weight used for aggregate scoring.
    pub fn score(self) -> u32 {
        match self {
            Self::Low => 1,
            Self::Medium => 5,
            Self::High => 15,
            Self::Critical => 40,
        }
    }
}

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

/// Recommended remediation action for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Shred,
    Encrypt,
    Archive,
    Review,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shred => write!(f, "Shred"),
            Self::Encrypt => write!(f, "Encrypt"),
            Self::Archive => write!(f, "Archive"),
            Self::Review => write!(f, "Review"),
        }
    }
}

// ---------------------------------------------------------------------------
// PrivacyFinding
// ---------------------------------------------------------------------------

/// A single privacy-relevant item discovered during an audit scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyFinding {
    pub path: String,
    pub category: PrivacyCategory,
    pub risk_level: RiskLevel,
    pub size_bytes: u64,
    pub description: String,
    pub recommended_action: Action,
}

// ---------------------------------------------------------------------------
// PrivacyReport
// ---------------------------------------------------------------------------

/// Aggregated output of a full privacy audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyReport {
    pub findings: Vec<PrivacyFinding>,
    pub total_risk_score: u32,
    pub total_size_bytes: u64,
    pub category_counts: Vec<(String, usize)>,
}

impl PrivacyReport {
    /// Render a human-readable summary.
    pub fn render_text(&self) -> String {
        let mut lines = vec![
            "=== Privacy Audit Report ===".to_string(),
            format!("Total findings: {}", self.findings.len()),
            format!("Total risk score: {}", self.total_risk_score),
            format!("Total data size: {} bytes", self.total_size_bytes),
            String::new(),
        ];

        for (cat, count) in &self.category_counts {
            lines.push(format!("  {cat}: {count} finding(s)"));
        }

        if !self.findings.is_empty() {
            lines.push(String::new());
            lines.push("Findings (sorted by risk, highest first):".to_string());
            for finding in &self.findings {
                lines.push(format!(
                    "  [{risk}] {cat} | {path} ({sz} B) -- {desc} -> {action}",
                    risk = finding.risk_level,
                    cat = finding.category,
                    path = finding.path,
                    sz = finding.size_bytes,
                    desc = finding.description,
                    action = finding.recommended_action,
                ));
            }
        }

        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// PrivacyAuditor
// ---------------------------------------------------------------------------

/// Scans filesystem trees for privacy-sensitive data and produces a scored
/// report with recommended actions.
pub struct PrivacyAuditor {
    /// Base path for home-relative scans (normally `$HOME`).
    home: PathBuf,
    /// Base path for system-level scans (normally `/`).
    sys_root: PathBuf,
}

impl PrivacyAuditor {
    /// Create an auditor targeting the real system.
    pub fn new() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        Self {
            home,
            sys_root: PathBuf::from("/"),
        }
    }

    /// Create an auditor pointing at custom base paths so tests can operate
    /// inside temp directories without touching the real filesystem.
    pub fn with_base_paths(home: &Path, sys_root: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
            sys_root: sys_root.to_path_buf(),
        }
    }

    // -- public scan methods ------------------------------------------------

    /// Detect browser history, cookies, saved passwords, and autofill data
    /// across Firefox, Chrome, Chromium, and Brave.
    pub fn scan_browser_data(&self) -> Vec<PrivacyFinding> {
        let mut findings = Vec::new();

        let browsers: &[(&str, &[&str])] = &[
            ("Firefox", &[".mozilla/firefox"]),
            ("Chrome", &[".config/google-chrome"]),
            ("Chromium", &[".config/chromium"]),
            ("Brave", &[".config/BraveSoftware/Brave-Browser"]),
        ];

        let sensitive_names: &[(&str, RiskLevel, &str)] = &[
            ("places.sqlite", RiskLevel::High, "browsing history and bookmarks"),
            ("cookies.sqlite", RiskLevel::High, "session cookies"),
            ("formhistory.sqlite", RiskLevel::High, "autofill form data"),
            ("logins.json", RiskLevel::Critical, "saved passwords"),
            ("key4.db", RiskLevel::Critical, "password encryption keys"),
            ("signons.sqlite", RiskLevel::Critical, "legacy saved passwords"),
            ("Cookies", RiskLevel::High, "session cookies"),
            ("History", RiskLevel::High, "browsing history"),
            ("Login Data", RiskLevel::Critical, "saved passwords"),
            ("Web Data", RiskLevel::High, "autofill data"),
            ("Bookmarks", RiskLevel::Medium, "bookmarks with URLs"),
            ("Favicons", RiskLevel::Low, "favicon cache revealing visited sites"),
        ];

        for (browser_name, profile_dirs) in browsers {
            for rel in *profile_dirs {
                let browser_dir = self.home.join(rel);
                if !browser_dir.is_dir() {
                    continue;
                }
                self.walk_for_names(
                    &browser_dir,
                    sensitive_names,
                    browser_name,
                    PrivacyCategory::BrowserData,
                    &mut findings,
                );
            }
        }

        findings
    }

    /// Detect recently-accessed file lists (GTK recent, KDE recent, Zeitgeist).
    pub fn scan_recent_files(&self) -> Vec<PrivacyFinding> {
        let mut findings = Vec::new();

        let targets: &[(&str, RiskLevel, &str)] = &[
            (".local/share/recently-used.xbel", RiskLevel::Medium, "GTK recently-used file list"),
            (".local/share/RecentDocuments", RiskLevel::Medium, "KDE recent documents"),
            (".local/share/zeitgeist", RiskLevel::Medium, "Zeitgeist activity log"),
            (".local/share/tracker", RiskLevel::Low, "GNOME Tracker index"),
            (".local/share/baloo", RiskLevel::Low, "KDE Baloo file index"),
        ];

        for (rel, risk, desc) in targets {
            let path = self.home.join(rel);
            if path.exists() {
                let size = dir_or_file_size(&path);
                findings.push(PrivacyFinding {
                    path: path.display().to_string(),
                    category: PrivacyCategory::RecentFiles,
                    risk_level: *risk,
                    size_bytes: size,
                    description: desc.to_string(),
                    recommended_action: Action::Shred,
                });
            }
        }

        findings
    }

    /// Detect shell history files (bash, zsh, fish, python, node, etc.).
    pub fn scan_shell_history(&self) -> Vec<PrivacyFinding> {
        let mut findings = Vec::new();

        let targets: &[(&str, &str)] = &[
            (".bash_history", "Bash command history"),
            (".zsh_history", "Zsh command history"),
            (".local/share/fish/fish_history", "Fish command history"),
            (".python_history", "Python REPL history"),
            (".node_repl_history", "Node.js REPL history"),
            (".lesshst", "less pager history"),
            (".mysql_history", "MySQL client history"),
            (".psql_history", "PostgreSQL client history"),
            (".sqlite_history", "SQLite client history"),
            (".wget-hsts", "wget HSTS cache"),
        ];

        for (rel, desc) in targets {
            let path = self.home.join(rel);
            if path.is_file() {
                let size = file_size(&path);
                findings.push(PrivacyFinding {
                    path: path.display().to_string(),
                    category: PrivacyCategory::ShellHistory,
                    risk_level: RiskLevel::High,
                    size_bytes: size,
                    description: desc.to_string(),
                    recommended_action: Action::Shred,
                });
            }
        }

        findings
    }

    /// Detect SSH-related sensitive files: known_hosts, authorized_keys,
    /// config, and private keys.
    pub fn scan_ssh_data(&self) -> Vec<PrivacyFinding> {
        let mut findings = Vec::new();

        let ssh_dir = self.home.join(".ssh");
        if !ssh_dir.is_dir() {
            return findings;
        }

        let named_targets: &[(&str, RiskLevel, &str, Action)] = &[
            ("known_hosts", RiskLevel::Medium, "SSH known hosts -- reveals servers contacted", Action::Review),
            ("authorized_keys", RiskLevel::High, "SSH authorized keys -- grants remote access", Action::Review),
            ("config", RiskLevel::Medium, "SSH client config -- reveals server aliases", Action::Review),
        ];

        for (name, risk, desc, action) in named_targets {
            let path = ssh_dir.join(name);
            if path.is_file() {
                let size = file_size(&path);
                findings.push(PrivacyFinding {
                    path: path.display().to_string(),
                    category: PrivacyCategory::SshData,
                    risk_level: *risk,
                    size_bytes: size,
                    description: desc.to_string(),
                    recommended_action: *action,
                });
            }
        }

        // Detect private keys: files without .pub extension that are not
        // known_hosts, config, authorized_keys, or other known non-key files.
        if let Ok(entries) = fs::read_dir(&ssh_dir) {
            let skip_names = [
                "known_hosts",
                "authorized_keys",
                "config",
                "known_hosts.old",
                "environment",
            ];
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let fname = match path.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                if fname.ends_with(".pub") || skip_names.contains(&fname.as_str()) {
                    continue;
                }
                let size = file_size(&path);
                // Heuristic: small files without .pub are likely private keys.
                if size > 0 && size < 16384 {
                    findings.push(PrivacyFinding {
                        path: path.display().to_string(),
                        category: PrivacyCategory::SshData,
                        risk_level: RiskLevel::Critical,
                        size_bytes: size,
                        description: format!("Possible SSH private key: {fname}"),
                        recommended_action: Action::Encrypt,
                    });
                }
            }
        }

        findings
    }

    /// Detect clipboard manager history (CopyQ, GPaste, Klipper, clipman).
    pub fn scan_clipboard_managers(&self) -> Vec<PrivacyFinding> {
        let mut findings = Vec::new();

        let targets: &[(&str, &str)] = &[
            (".config/copyq", "CopyQ clipboard manager data"),
            (".local/share/copyq", "CopyQ clipboard history"),
            (".local/share/gpaste", "GPaste clipboard history"),
            (".local/share/klipper", "Klipper clipboard history"),
            (".config/CopyQ", "CopyQ clipboard manager data (alt path)"),
            (".local/share/clipman", "Clipman clipboard history"),
        ];

        for (rel, desc) in targets {
            let path = self.home.join(rel);
            if path.exists() {
                let size = dir_or_file_size(&path);
                findings.push(PrivacyFinding {
                    path: path.display().to_string(),
                    category: PrivacyCategory::ClipboardHistory,
                    risk_level: RiskLevel::High,
                    size_bytes: size,
                    description: desc.to_string(),
                    recommended_action: Action::Shred,
                });
            }
        }

        findings
    }

    /// Detect thumbnail caches that reveal viewed images and documents.
    pub fn scan_thumbnails(&self) -> Vec<PrivacyFinding> {
        let mut findings = Vec::new();

        let targets: &[(&str, &str)] = &[
            (".cache/thumbnails", "XDG thumbnail cache"),
            (".thumbnails", "Legacy thumbnail cache"),
            (".cache/shotwell/thumbs", "Shotwell photo thumbs"),
        ];

        for (rel, desc) in targets {
            let path = self.home.join(rel);
            if path.exists() {
                let size = dir_or_file_size(&path);
                findings.push(PrivacyFinding {
                    path: path.display().to_string(),
                    category: PrivacyCategory::Thumbnails,
                    risk_level: RiskLevel::Medium,
                    size_bytes: size,
                    description: desc.to_string(),
                    recommended_action: Action::Shred,
                });
            }
        }

        findings
    }

    /// Detect system logs that may contain user activity traces
    /// (auth.log, syslog, wtmp, journal, etc.).
    pub fn scan_logs(&self) -> Vec<PrivacyFinding> {
        let mut findings = Vec::new();

        let log_dir = self.sys_root.join("var/log");
        let targets: &[(&str, RiskLevel, &str)] = &[
            ("auth.log", RiskLevel::High, "Authentication log -- login times, sudo usage"),
            ("syslog", RiskLevel::Medium, "System log -- may contain user activity"),
            ("kern.log", RiskLevel::Low, "Kernel log -- USB device insertions"),
            ("wtmp", RiskLevel::High, "Login records (binary)"),
            ("btmp", RiskLevel::Medium, "Failed login attempts (binary)"),
            ("lastlog", RiskLevel::Medium, "Last login per user (binary)"),
            ("faillog", RiskLevel::Medium, "Login failure counts"),
        ];

        for (name, risk, desc) in targets {
            let path = log_dir.join(name);
            if path.is_file() {
                let size = file_size(&path);
                findings.push(PrivacyFinding {
                    path: path.display().to_string(),
                    category: PrivacyCategory::SystemLogs,
                    risk_level: *risk,
                    size_bytes: size,
                    description: desc.to_string(),
                    recommended_action: Action::Shred,
                });
            }
        }

        // Also check for systemd journal directory.
        let journal_dir = log_dir.join("journal");
        if journal_dir.is_dir() {
            let size = dir_or_file_size(&journal_dir);
            findings.push(PrivacyFinding {
                path: journal_dir.display().to_string(),
                category: PrivacyCategory::SystemLogs,
                risk_level: RiskLevel::High,
                size_bytes: size,
                description: "systemd journal -- detailed user session activity".to_string(),
                recommended_action: Action::Review,
            });
        }

        findings
    }

    // -- aggregate ----------------------------------------------------------

    /// Run every scan and produce a consolidated report with findings sorted
    /// by risk level (highest first).
    pub fn full_audit(&self) -> PrivacyReport {
        let mut findings = Vec::new();
        findings.extend(self.scan_browser_data());
        findings.extend(self.scan_recent_files());
        findings.extend(self.scan_shell_history());
        findings.extend(self.scan_ssh_data());
        findings.extend(self.scan_clipboard_managers());
        findings.extend(self.scan_thumbnails());
        findings.extend(self.scan_logs());

        // Sort by risk descending.
        findings.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));

        let total_risk_score: u32 = findings.iter().map(|f| f.risk_level.score()).sum();
        let total_size_bytes: u64 = findings.iter().map(|f| f.size_bytes).sum();

        // Count per category.
        let mut cat_map: BTreeMap<String, usize> = BTreeMap::new();
        for finding in &findings {
            *cat_map.entry(finding.category.to_string()).or_insert(0) += 1;
        }
        let category_counts: Vec<(String, usize)> = cat_map.into_iter().collect();

        PrivacyReport {
            findings,
            total_risk_score,
            total_size_bytes,
            category_counts,
        }
    }

    // -- private helpers ----------------------------------------------------

    /// Walk a directory looking for files matching any of the given names.
    fn walk_for_names(
        &self,
        root: &Path,
        names: &[(&str, RiskLevel, &str)],
        browser: &str,
        category: PrivacyCategory,
        findings: &mut Vec<PrivacyFinding>,
    ) {
        let walker = walkdir::WalkDir::new(root)
            .max_depth(4)
            .into_iter()
            .filter_map(|e| e.ok());

        for entry in walker {
            if !entry.file_type().is_file() {
                continue;
            }
            let fname = match entry.file_name().to_str() {
                Some(n) => n,
                None => continue,
            };
            for (target_name, risk, desc) in names {
                if fname == *target_name {
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    findings.push(PrivacyFinding {
                        path: entry.path().display().to_string(),
                        category,
                        risk_level: *risk,
                        size_bytes: size,
                        description: format!("{browser}: {desc}"),
                        recommended_action: if *risk >= RiskLevel::High {
                            Action::Shred
                        } else {
                            Action::Review
                        },
                    });
                }
            }
        }
    }
}

impl Default for PrivacyAuditor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Size of a single file, or 0 on error.
fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Total size of a file or directory tree.
fn dir_or_file_size(path: &Path) -> u64 {
    if path.is_file() {
        return file_size(path);
    }
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a temp home directory with a populated `.ssh` tree.
    fn setup_ssh(home: &Path) {
        let ssh = home.join(".ssh");
        fs::create_dir_all(&ssh).expect("create .ssh");
        fs::write(ssh.join("known_hosts"), "github.com ssh-ed25519 AAAA...\n").expect("known_hosts");
        fs::write(ssh.join("authorized_keys"), "ssh-ed25519 AAAA... user@host\n").expect("authorized_keys");
        fs::write(ssh.join("id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n").expect("id_ed25519");
        fs::write(ssh.join("id_ed25519.pub"), "ssh-ed25519 AAAA... user@host\n").expect("id_ed25519.pub");
        fs::write(ssh.join("config"), "Host github\n  Hostname github.com\n").expect("config");
    }

    /// Build a temp home directory with shell history files.
    fn setup_shell_history(home: &Path) {
        fs::write(home.join(".bash_history"), "ls\ncd /tmp\nsudo rm -rf /\n").expect("bash_history");
        fs::write(home.join(".zsh_history"), ": 1700000000:0;echo hello\n").expect("zsh_history");
        let fish_dir = home.join(".local/share/fish");
        fs::create_dir_all(&fish_dir).expect("fish dir");
        fs::write(fish_dir.join("fish_history"), "- cmd: ls\n  when: 1700000000\n").expect("fish_history");
    }

    /// Build a temp home directory with browser-like data.
    fn setup_browser_data(home: &Path) {
        let ff = home.join(".mozilla/firefox/abc123.default");
        fs::create_dir_all(&ff).expect("firefox dir");
        fs::write(ff.join("places.sqlite"), "fake-sqlite-data").expect("places.sqlite");
        fs::write(ff.join("cookies.sqlite"), "cookie-jar").expect("cookies.sqlite");
        fs::write(ff.join("logins.json"), r#"{"logins":[]}"#).expect("logins.json");

        let chrome = home.join(".config/google-chrome/Default");
        fs::create_dir_all(&chrome).expect("chrome dir");
        fs::write(chrome.join("History"), "chrome-history-data").expect("History");
        fs::write(chrome.join("Login Data"), "chrome-login-data").expect("Login Data");
    }

    // -- 1. scan_ssh_data detects keys and known_hosts ----------------------

    #[test]
    fn test_scan_ssh_data() {
        let dir = TempDir::new().expect("tempdir");
        let home = dir.path();
        setup_ssh(home);

        let auditor = PrivacyAuditor::with_base_paths(home, home);
        let findings = auditor.scan_ssh_data();

        // Should find: known_hosts, authorized_keys, config, id_ed25519.
        // Should NOT include id_ed25519.pub.
        assert!(
            findings.len() >= 4,
            "expected at least 4 SSH findings, got {}",
            findings.len()
        );

        assert!(findings.iter().all(|f| f.category == PrivacyCategory::SshData));

        // Private key must be Critical.
        let key_finding = findings
            .iter()
            .find(|f| f.path.contains("id_ed25519") && !f.path.contains(".pub"));
        assert!(key_finding.is_some(), "private key should be detected");
        assert_eq!(
            key_finding.map(|f| f.risk_level),
            Some(RiskLevel::Critical)
        );

        // .pub file should be absent.
        assert!(
            !findings.iter().any(|f| f.path.ends_with(".pub")),
            ".pub key should not appear"
        );
    }

    // -- 2. scan_shell_history finds history files --------------------------

    #[test]
    fn test_scan_shell_history() {
        let dir = TempDir::new().expect("tempdir");
        let home = dir.path();
        setup_shell_history(home);

        let auditor = PrivacyAuditor::with_base_paths(home, home);
        let findings = auditor.scan_shell_history();

        assert_eq!(findings.len(), 3, "should find bash, zsh, fish history");
        assert!(findings.iter().all(|f| f.category == PrivacyCategory::ShellHistory));
        assert!(findings.iter().all(|f| f.risk_level == RiskLevel::High));
        assert!(findings.iter().all(|f| f.recommended_action == Action::Shred));
    }

    // -- 3. scan_browser_data finds Firefox and Chrome data -----------------

    #[test]
    fn test_scan_browser_data() {
        let dir = TempDir::new().expect("tempdir");
        let home = dir.path();
        setup_browser_data(home);

        let auditor = PrivacyAuditor::with_base_paths(home, home);
        let findings = auditor.scan_browser_data();

        assert!(
            findings.len() >= 5,
            "expected at least 5 browser findings, got {}",
            findings.len()
        );

        // Logins must be Critical.
        let critical_count = findings
            .iter()
            .filter(|f| f.risk_level == RiskLevel::Critical)
            .count();
        assert!(
            critical_count >= 2,
            "login/password files should be Critical, found {} critical",
            critical_count
        );

        assert!(findings.iter().all(|f| f.category == PrivacyCategory::BrowserData));
    }

    // -- 4. scan_recent_files detects GTK recently-used ---------------------

    #[test]
    fn test_scan_recent_files() {
        let dir = TempDir::new().expect("tempdir");
        let home = dir.path();

        let recent_dir = home.join(".local/share");
        fs::create_dir_all(&recent_dir).expect("create recent dir");
        fs::write(recent_dir.join("recently-used.xbel"), "<xbel></xbel>").expect("xbel");

        let auditor = PrivacyAuditor::with_base_paths(home, home);
        let findings = auditor.scan_recent_files();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, PrivacyCategory::RecentFiles);
        assert_eq!(findings[0].risk_level, RiskLevel::Medium);
    }

    // -- 5. scan_clipboard_managers detects CopyQ ---------------------------

    #[test]
    fn test_scan_clipboard_managers() {
        let dir = TempDir::new().expect("tempdir");
        let home = dir.path();

        let copyq = home.join(".local/share/copyq");
        fs::create_dir_all(&copyq).expect("create copyq dir");
        fs::write(copyq.join("copyq.dat"), "clipboard item 1\npassword123\n").expect("copyq.dat");

        let auditor = PrivacyAuditor::with_base_paths(home, home);
        let findings = auditor.scan_clipboard_managers();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, PrivacyCategory::ClipboardHistory);
        assert_eq!(findings[0].risk_level, RiskLevel::High);
    }

    // -- 6. scan_thumbnails detects cache -----------------------------------

    #[test]
    fn test_scan_thumbnails() {
        let dir = TempDir::new().expect("tempdir");
        let home = dir.path();

        let thumbs = home.join(".cache/thumbnails/normal");
        fs::create_dir_all(&thumbs).expect("create thumbs dir");
        fs::write(thumbs.join("abc123.png"), vec![0u8; 4096]).expect("thumb1");
        fs::write(thumbs.join("def456.png"), vec![0u8; 2048]).expect("thumb2");

        let auditor = PrivacyAuditor::with_base_paths(home, home);
        let findings = auditor.scan_thumbnails();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, PrivacyCategory::Thumbnails);
        assert_eq!(findings[0].size_bytes, 4096 + 2048);
    }

    // -- 7. full_audit aggregates and sorts by risk -------------------------

    #[test]
    fn test_full_audit_aggregation() {
        let dir = TempDir::new().expect("tempdir");
        let home = dir.path();

        setup_ssh(home);
        setup_shell_history(home);
        setup_browser_data(home);

        let auditor = PrivacyAuditor::with_base_paths(home, home);
        let report = auditor.full_audit();

        assert!(
            report.findings.len() >= 10,
            "full audit should aggregate many findings, got {}",
            report.findings.len()
        );
        assert!(report.total_risk_score > 0);
        assert!(report.total_size_bytes > 0);
        assert!(!report.category_counts.is_empty());

        // Verify sort order: risk levels must be non-increasing.
        for pair in report.findings.windows(2) {
            assert!(
                pair[0].risk_level >= pair[1].risk_level,
                "findings must be sorted by risk descending"
            );
        }

        // Render should produce expected content.
        let text = report.render_text();
        assert!(text.contains("Privacy Audit Report"));
        assert!(text.contains("CRITICAL"));
    }

    // -- 8. scan_logs with fake var/log directory ---------------------------

    #[test]
    fn test_scan_logs() {
        let dir = TempDir::new().expect("tempdir");
        let sys_root = dir.path();

        let log_dir = sys_root.join("var/log");
        fs::create_dir_all(&log_dir).expect("create log dir");
        fs::write(
            log_dir.join("auth.log"),
            "Apr  5 10:00:00 host sudo: user : TTY=pts/0\n",
        )
        .expect("auth.log");
        fs::write(log_dir.join("syslog"), "kernel: usb device attached\n").expect("syslog");
        fs::write(log_dir.join("wtmp"), vec![0u8; 512]).expect("wtmp");

        let fake_home = dir.path().join("fakehome");
        fs::create_dir_all(&fake_home).expect("create fakehome");

        let auditor = PrivacyAuditor::with_base_paths(&fake_home, sys_root);
        let findings = auditor.scan_logs();

        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| f.category == PrivacyCategory::SystemLogs));

        let auth_finding = findings.iter().find(|f| f.path.contains("auth.log"));
        assert!(auth_finding.is_some());
        assert_eq!(
            auth_finding.map(|f| f.risk_level),
            Some(RiskLevel::High)
        );
    }

    // -- 9. empty home yields no findings -----------------------------------

    #[test]
    fn test_empty_home_no_findings() {
        let dir = TempDir::new().expect("tempdir");
        let home = dir.path();
        let sys = dir.path().join("sysroot");
        fs::create_dir_all(&sys).expect("create sysroot");

        let auditor = PrivacyAuditor::with_base_paths(home, &sys);
        let report = auditor.full_audit();

        assert!(report.findings.is_empty());
        assert_eq!(report.total_risk_score, 0);
        assert_eq!(report.total_size_bytes, 0);
    }

    // -- 10. risk_level ordering is correct ---------------------------------

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
        assert_eq!(RiskLevel::Critical.score(), 40);
        assert_eq!(RiskLevel::Low.score(), 1);
    }
}
