//! Browser cache and temp file cleanup.
//!
//! Discovers all major browser profiles on Linux, scans for reclaimable
//! data across 15 categories (cache, cookies, history, sessions, form data,
//! passwords, downloads, thumbnails, service workers, IndexedDB, local
//! storage, WebSQL, logs, crash reports, extensions), and securely deletes
//! selected categories using algorithms from `algorithms.rs`.
//!
//! Also covers system temp files: `/tmp` (user-owned), `~/.cache`,
//! `~/.local/share/Trash`, and recent-documents lists.
//!
//! More thorough than CCleaner/BleachBit: covers Firefox, Chrome, Chromium,
//! Brave, Vivaldi, Edge, and every Chromium derivative that follows the
//! standard `Default/` profile layout.

use plausiden_purge::algorithms::ErasureAlgorithm;
use plausiden_purge::destroyer;
use plausiden_purge::error::Result;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Top-level cleaner that holds all discovered browser profiles and system
/// temp targets.
pub struct BrowserCleaner {
    pub browsers: Vec<BrowserProfile>,
    pub system_targets: Vec<CleanTarget>,
    home_dir: PathBuf,
}

/// A single browser installation/profile on disk.
pub struct BrowserProfile {
    pub name: String,
    pub data_paths: Vec<CleanTarget>,
}

/// One cleanable target (file or directory).
pub struct CleanTarget {
    pub category: CleanCategory,
    pub path: PathBuf,
    pub description: String,
    pub size_bytes: Option<u64>,
}

/// Categories of browser / system data that can be cleaned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CleanCategory {
    Cache,
    Cookies,
    History,
    Sessions,
    FormData,
    Passwords,
    Downloads,
    Thumbnails,
    ServiceWorkers,
    IndexedDB,
    LocalStorage,
    WebSQL,
    Logs,
    CrashReports,
    Extensions,
    /// System temp files (not browser-specific).
    SystemTemp,
}

// ---------------------------------------------------------------------------
// Report returned by scan / dry_run
// ---------------------------------------------------------------------------

/// Summary produced by `scan()` and `dry_run()`.
#[derive(Debug)]
pub struct CleanReport {
    pub total_targets: usize,
    pub total_bytes: u64,
    pub by_category: Vec<(CleanCategory, u64)>,
    pub entries: Vec<CleanReportEntry>,
}

#[derive(Debug)]
pub struct CleanReportEntry {
    pub browser: String,
    pub category: CleanCategory,
    pub path: String,
    pub size_bytes: u64,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl BrowserCleaner {
    // -- constructors -------------------------------------------------------

    /// Create a cleaner rooted at the real user home directory.
    pub fn new() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        Self {
            browsers: Vec::new(),
            system_targets: Vec::new(),
            home_dir,
        }
    }

    /// Create a cleaner rooted at an arbitrary directory (for testing).
    pub fn with_home(home: PathBuf) -> Self {
        Self {
            browsers: Vec::new(),
            system_targets: Vec::new(),
            home_dir: home,
        }
    }

    // -- discover -----------------------------------------------------------

    /// Scan the system for all browser profiles and system temp targets.
    pub fn discover(&mut self) {
        self.browsers.clear();
        self.system_targets.clear();

        self.discover_firefox();
        self.discover_chromium_variant("Google Chrome", "google-chrome");
        self.discover_chromium_variant("Chromium", "chromium");
        self.discover_chromium_variant("Brave", "BraveSoftware/Brave-Browser");
        self.discover_chromium_variant("Vivaldi", "vivaldi");
        self.discover_chromium_variant("Microsoft Edge", "microsoft-edge");
        self.discover_chromium_variant("Opera", "opera");
        self.discover_system_temps();
    }

    // -- scan ---------------------------------------------------------------

    /// Calculate what would be cleaned and how much space would be freed.
    /// Populates `size_bytes` on every target.
    pub fn scan(&mut self) -> CleanReport {
        // Ensure sizes are populated.
        for browser in &mut self.browsers {
            for target in &mut browser.data_paths {
                if target.size_bytes.is_none() {
                    target.size_bytes = Some(path_size(&target.path));
                }
            }
        }
        for target in &mut self.system_targets {
            if target.size_bytes.is_none() {
                target.size_bytes = Some(path_size(&target.path));
            }
        }

        self.build_report()
    }

    // -- clean --------------------------------------------------------------

    /// Securely delete targets matching the given categories using the
    /// specified erasure algorithm.
    pub fn clean(
        &mut self,
        categories: &[CleanCategory],
        algorithm: ErasureAlgorithm,
    ) -> Result<CleanReport> {
        let report = self.scan();
        let passes = algorithm.patterns().len() as u32;

        for browser in &self.browsers {
            for target in &browser.data_paths {
                if !categories.contains(&target.category) {
                    continue;
                }
                if target.path.exists() {
                    let p = target.path.to_string_lossy().to_string();
                    if let Err(e) = destroyer::secure_delete(&p, passes, false) {
                        tracing::warn!("Failed to clean {p}: {e}");
                    }
                }
            }
        }

        for target in &self.system_targets {
            if !categories.contains(&target.category) {
                continue;
            }
            if target.path.exists() {
                let p = target.path.to_string_lossy().to_string();
                if let Err(e) = destroyer::secure_delete(&p, passes, false) {
                    tracing::warn!("Failed to clean {p}: {e}");
                }
            }
        }

        Ok(report)
    }

    // -- dry_run ------------------------------------------------------------

    /// Show what would be cleaned without deleting anything.
    pub fn dry_run(&mut self) -> CleanReport {
        self.scan()
    }

    // -----------------------------------------------------------------------
    // Internal: Firefox discovery
    // -----------------------------------------------------------------------

    fn discover_firefox(&mut self) {
        let ff_root = self.home_dir.join(".mozilla/firefox");
        if !ff_root.is_dir() {
            return;
        }

        let profiles = match fs::read_dir(&ff_root) {
            Ok(rd) => rd,
            Err(_) => return,
        };

        for entry in profiles.flatten() {
            let profile_dir = entry.path();
            if !profile_dir.is_dir() {
                continue;
            }
            // Firefox profiles are named like `xxxxxxxx.default-release`
            let name_os = entry.file_name();
            let profile_name = name_os.to_string_lossy();

            let mut targets: Vec<CleanTarget> = Vec::new();

            // Cache
            push_if_exists(&mut targets, &profile_dir.join("cache2"), CleanCategory::Cache,
                "Firefox browser cache");
            push_if_exists(&mut targets, &profile_dir.join("cache"), CleanCategory::Cache,
                "Firefox legacy cache");
            push_if_exists(&mut targets, &profile_dir.join("OfflineCache"), CleanCategory::Cache,
                "Firefox offline cache");
            push_if_exists(&mut targets, &profile_dir.join("startupCache"), CleanCategory::Cache,
                "Firefox startup cache");

            // Cookies
            push_if_exists(&mut targets, &profile_dir.join("cookies.sqlite"), CleanCategory::Cookies,
                "Firefox cookies database");
            push_if_exists(&mut targets, &profile_dir.join("cookies.sqlite-wal"), CleanCategory::Cookies,
                "Firefox cookies WAL");
            push_if_exists(&mut targets, &profile_dir.join("cookies.sqlite-shm"), CleanCategory::Cookies,
                "Firefox cookies SHM");

            // History
            push_if_exists(&mut targets, &profile_dir.join("places.sqlite"), CleanCategory::History,
                "Firefox history and bookmarks");
            push_if_exists(&mut targets, &profile_dir.join("places.sqlite-wal"), CleanCategory::History,
                "Firefox places WAL");
            push_if_exists(&mut targets, &profile_dir.join("places.sqlite-shm"), CleanCategory::History,
                "Firefox places SHM");

            // Sessions
            push_if_exists(&mut targets, &profile_dir.join("sessionstore.jsonlz4"), CleanCategory::Sessions,
                "Firefox session restore data");
            push_if_exists(&mut targets, &profile_dir.join("sessionstore-backups"), CleanCategory::Sessions,
                "Firefox session restore backups");
            push_if_exists(&mut targets, &profile_dir.join("sessionCheckpoints.json"), CleanCategory::Sessions,
                "Firefox session checkpoints");

            // Form data
            push_if_exists(&mut targets, &profile_dir.join("formhistory.sqlite"), CleanCategory::FormData,
                "Firefox form autofill history");
            push_if_exists(&mut targets, &profile_dir.join("formhistory.sqlite-wal"), CleanCategory::FormData,
                "Firefox form history WAL");

            // Passwords
            push_if_exists(&mut targets, &profile_dir.join("logins.json"), CleanCategory::Passwords,
                "Firefox saved passwords");
            push_if_exists(&mut targets, &profile_dir.join("key4.db"), CleanCategory::Passwords,
                "Firefox password encryption key");
            push_if_exists(&mut targets, &profile_dir.join("signons.sqlite"), CleanCategory::Passwords,
                "Firefox legacy passwords");

            // Downloads
            push_if_exists(&mut targets, &profile_dir.join("downloads.sqlite"), CleanCategory::Downloads,
                "Firefox download history");
            push_if_exists(&mut targets, &profile_dir.join("downloads.json"), CleanCategory::Downloads,
                "Firefox download metadata");

            // Thumbnails
            push_if_exists(&mut targets, &profile_dir.join("thumbnails"), CleanCategory::Thumbnails,
                "Firefox page thumbnails");
            push_if_exists(&mut targets, &profile_dir.join("favicons.sqlite"), CleanCategory::Thumbnails,
                "Firefox favicons");
            push_if_exists(&mut targets, &profile_dir.join("favicons.sqlite-wal"), CleanCategory::Thumbnails,
                "Firefox favicons WAL");

            // Service Workers
            push_if_exists(&mut targets, &profile_dir.join("serviceworker"), CleanCategory::ServiceWorkers,
                "Firefox service worker registrations");

            // IndexedDB
            push_if_exists(&mut targets, &profile_dir.join("indexedDB"), CleanCategory::IndexedDB,
                "Firefox IndexedDB databases");
            push_if_exists(&mut targets, &profile_dir.join("storage/default"), CleanCategory::IndexedDB,
                "Firefox storage (default origin)");

            // Local Storage
            push_if_exists(&mut targets, &profile_dir.join("webappsstore.sqlite"), CleanCategory::LocalStorage,
                "Firefox local storage database");
            push_if_exists(&mut targets, &profile_dir.join("webappsstore.sqlite-wal"), CleanCategory::LocalStorage,
                "Firefox local storage WAL");
            push_if_exists(&mut targets, &profile_dir.join("storage/ls"), CleanCategory::LocalStorage,
                "Firefox local storage (new backend)");

            // WebSQL (Firefox used storage/default for this)
            push_if_exists(&mut targets, &profile_dir.join("storage/temporary"), CleanCategory::WebSQL,
                "Firefox temporary storage");

            // Logs / diagnostics
            push_if_exists(&mut targets, &profile_dir.join("weave/logs"), CleanCategory::Logs,
                "Firefox sync logs");
            push_if_exists(&mut targets, &profile_dir.join("datareporting"), CleanCategory::Logs,
                "Firefox telemetry data");
            push_if_exists(&mut targets, &profile_dir.join("saved-telemetry-pings"), CleanCategory::Logs,
                "Firefox telemetry pings");

            // Crash reports
            push_if_exists(&mut targets, &profile_dir.join("minidumps"), CleanCategory::CrashReports,
                "Firefox crash minidumps");

            // Crash reports at the top-level firefox dir
            let cr = ff_root.join("Crash Reports");
            push_if_exists(&mut targets, &cr, CleanCategory::CrashReports,
                "Firefox crash reports");

            // Extensions
            push_if_exists(&mut targets, &profile_dir.join("extensions"), CleanCategory::Extensions,
                "Firefox extensions");

            if !targets.is_empty() {
                self.browsers.push(BrowserProfile {
                    name: format!("Firefox ({profile_name})"),
                    data_paths: targets,
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Chromium-based browser discovery
    // -----------------------------------------------------------------------

    fn discover_chromium_variant(&mut self, browser_name: &str, config_dir: &str) {
        let base = self.home_dir.join(".config").join(config_dir);
        if !base.is_dir() {
            return;
        }

        // Chromium browsers can have Default, Profile 1, Profile 2, etc.
        let profile_dirs: Vec<PathBuf> = fs::read_dir(&base)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir() && {
                    let name = p.file_name().unwrap_or_default().to_string_lossy();
                    name == "Default"
                        || name.starts_with("Profile ")
                        || name == "Guest Profile"
                }
            })
            .collect();

        for profile_dir in profile_dirs {
            let profile_name = profile_dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let mut targets: Vec<CleanTarget> = Vec::new();

            // Cache (multiple locations)
            push_if_exists(&mut targets, &profile_dir.join("Cache"), CleanCategory::Cache,
                &format!("{browser_name} cache"));
            push_if_exists(&mut targets, &profile_dir.join("Code Cache"), CleanCategory::Cache,
                &format!("{browser_name} compiled code cache"));
            push_if_exists(&mut targets, &profile_dir.join("GPUCache"), CleanCategory::Cache,
                &format!("{browser_name} GPU shader cache"));
            push_if_exists(&mut targets, &profile_dir.join("ShaderCache"), CleanCategory::Cache,
                &format!("{browser_name} shader cache"));
            push_if_exists(&mut targets, &profile_dir.join("Storage/ext"), CleanCategory::Cache,
                &format!("{browser_name} extension storage cache"));
            // Top-level cache directories
            push_if_exists(&mut targets, &base.join("ShaderCache"), CleanCategory::Cache,
                &format!("{browser_name} top-level shader cache"));
            push_if_exists(&mut targets, &base.join("GrShaderCache"), CleanCategory::Cache,
                &format!("{browser_name} Gr shader cache"));
            push_if_exists(&mut targets, &base.join("GraphiteDawnCache"), CleanCategory::Cache,
                &format!("{browser_name} Graphite Dawn cache"));

            // Cookies
            push_if_exists(&mut targets, &profile_dir.join("Cookies"), CleanCategory::Cookies,
                &format!("{browser_name} cookies"));
            push_if_exists(&mut targets, &profile_dir.join("Cookies-journal"), CleanCategory::Cookies,
                &format!("{browser_name} cookies journal"));

            // History
            push_if_exists(&mut targets, &profile_dir.join("History"), CleanCategory::History,
                &format!("{browser_name} browsing history"));
            push_if_exists(&mut targets, &profile_dir.join("History-journal"), CleanCategory::History,
                &format!("{browser_name} history journal"));
            push_if_exists(&mut targets, &profile_dir.join("Visited Links"), CleanCategory::History,
                &format!("{browser_name} visited links bloom filter"));
            push_if_exists(&mut targets, &profile_dir.join("Top Sites"), CleanCategory::History,
                &format!("{browser_name} top sites"));
            push_if_exists(&mut targets, &profile_dir.join("Network Action Predictor"), CleanCategory::History,
                &format!("{browser_name} network action predictor"));

            // Sessions
            push_if_exists(&mut targets, &profile_dir.join("Sessions"), CleanCategory::Sessions,
                &format!("{browser_name} session data"));
            push_if_exists(&mut targets, &profile_dir.join("Session Storage"), CleanCategory::Sessions,
                &format!("{browser_name} session storage"));
            push_if_exists(&mut targets, &profile_dir.join("Current Session"), CleanCategory::Sessions,
                &format!("{browser_name} current session"));
            push_if_exists(&mut targets, &profile_dir.join("Current Tabs"), CleanCategory::Sessions,
                &format!("{browser_name} current tabs"));
            push_if_exists(&mut targets, &profile_dir.join("Last Session"), CleanCategory::Sessions,
                &format!("{browser_name} last session"));
            push_if_exists(&mut targets, &profile_dir.join("Last Tabs"), CleanCategory::Sessions,
                &format!("{browser_name} last tabs"));

            // Form data
            push_if_exists(&mut targets, &profile_dir.join("Web Data"), CleanCategory::FormData,
                &format!("{browser_name} autofill / web data"));
            push_if_exists(&mut targets, &profile_dir.join("Web Data-journal"), CleanCategory::FormData,
                &format!("{browser_name} web data journal"));

            // Passwords
            push_if_exists(&mut targets, &profile_dir.join("Login Data"), CleanCategory::Passwords,
                &format!("{browser_name} saved passwords"));
            push_if_exists(&mut targets, &profile_dir.join("Login Data-journal"), CleanCategory::Passwords,
                &format!("{browser_name} login data journal"));
            push_if_exists(&mut targets, &profile_dir.join("Login Data For Account"), CleanCategory::Passwords,
                &format!("{browser_name} account login data"));

            // Downloads
            push_if_exists(&mut targets, &profile_dir.join("DownloadMetadata"), CleanCategory::Downloads,
                &format!("{browser_name} download metadata"));

            // Thumbnails / favicons
            push_if_exists(&mut targets, &profile_dir.join("Favicons"), CleanCategory::Thumbnails,
                &format!("{browser_name} favicons"));
            push_if_exists(&mut targets, &profile_dir.join("Favicons-journal"), CleanCategory::Thumbnails,
                &format!("{browser_name} favicons journal"));
            push_if_exists(&mut targets, &profile_dir.join("Thumbnails"), CleanCategory::Thumbnails,
                &format!("{browser_name} page thumbnails"));

            // Service Workers
            push_if_exists(&mut targets, &profile_dir.join("Service Worker"), CleanCategory::ServiceWorkers,
                &format!("{browser_name} service worker registrations"));

            // IndexedDB
            push_if_exists(&mut targets, &profile_dir.join("IndexedDB"), CleanCategory::IndexedDB,
                &format!("{browser_name} IndexedDB databases"));

            // Local Storage
            push_if_exists(&mut targets, &profile_dir.join("Local Storage"), CleanCategory::LocalStorage,
                &format!("{browser_name} local storage"));

            // WebSQL
            push_if_exists(&mut targets, &profile_dir.join("databases"), CleanCategory::WebSQL,
                &format!("{browser_name} WebSQL databases"));

            // Logs
            push_if_exists(&mut targets, &profile_dir.join("chrome_debug.log"), CleanCategory::Logs,
                &format!("{browser_name} debug log"));
            push_if_exists(&mut targets, &base.join("chrome_debug.log"), CleanCategory::Logs,
                &format!("{browser_name} top-level debug log"));

            // Crash reports
            push_if_exists(&mut targets, &base.join("Crash Reports"), CleanCategory::CrashReports,
                &format!("{browser_name} crash reports"));
            push_if_exists(&mut targets, &profile_dir.join("Crash Reports"), CleanCategory::CrashReports,
                &format!("{browser_name} profile crash reports"));

            // Extensions
            push_if_exists(&mut targets, &profile_dir.join("Extensions"), CleanCategory::Extensions,
                &format!("{browser_name} extensions"));

            if !targets.is_empty() {
                self.browsers.push(BrowserProfile {
                    name: format!("{browser_name} ({profile_name})"),
                    data_paths: targets,
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: System temp targets
    // -----------------------------------------------------------------------

    fn discover_system_temps(&mut self) {
        let uid = unsafe { libc::getuid() };

        // /tmp — only user-owned files
        let tmp = PathBuf::from("/tmp");
        if tmp.is_dir() {
            for entry in fs::read_dir(&tmp).into_iter().flatten().flatten() {
                let path = entry.path();
                if let Ok(meta) = fs::metadata(&path) {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if meta.uid() == uid {
                            self.system_targets.push(CleanTarget {
                                category: CleanCategory::SystemTemp,
                                path: path.clone(),
                                description: format!("User temp file: {}", path.display()),
                                size_bytes: Some(if meta.is_dir() {
                                    path_size(&path)
                                } else {
                                    meta.len()
                                }),
                            });
                        }
                    }
                }
            }
        }

        // ~/.cache subdirectories
        let cache_root = self.home_dir.join(".cache");
        let cache_subdirs = [
            ("thumbnails", "Desktop thumbnails"),
            ("fontconfig", "Font configuration cache"),
            ("mesa_shader_cache", "Mesa GPU shader cache"),
            ("mozilla", "Mozilla cache"),
            ("google-chrome", "Chrome cache"),
            ("chromium", "Chromium cache"),
            ("BraveSoftware", "Brave cache"),
            ("vivaldi", "Vivaldi cache"),
            ("microsoft-edge", "Edge cache"),
            ("opera", "Opera cache"),
            ("gstreamer-1.0", "GStreamer media cache"),
            ("pip", "Python pip cache"),
            ("yarn", "Yarn package cache"),
            ("node", "Node.js cache"),
        ];
        for (subdir, desc) in cache_subdirs {
            let p = cache_root.join(subdir);
            push_if_exists(&mut self.system_targets, &p, CleanCategory::Cache, desc);
        }

        // ~/.local/share/Trash
        let trash = self.home_dir.join(".local/share/Trash");
        push_if_exists(&mut self.system_targets, &trash, CleanCategory::SystemTemp,
            "Desktop trash");

        // Recent documents lists
        let recent_docs = [
            self.home_dir.join(".local/share/recently-used.xbel"),
            self.home_dir.join(".local/share/recent"),
        ];
        for p in recent_docs {
            push_if_exists(&mut self.system_targets, &p, CleanCategory::History,
                "Recent documents list");
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Build report from current state
    // -----------------------------------------------------------------------

    fn build_report(&self) -> CleanReport {
        let mut entries: Vec<CleanReportEntry> = Vec::new();
        let mut cat_totals: std::collections::HashMap<CleanCategory, u64> =
            std::collections::HashMap::new();

        for browser in &self.browsers {
            for target in &browser.data_paths {
                let size = target.size_bytes.unwrap_or(0);
                entries.push(CleanReportEntry {
                    browser: browser.name.clone(),
                    category: target.category,
                    path: target.path.to_string_lossy().to_string(),
                    size_bytes: size,
                });
                *cat_totals.entry(target.category).or_insert(0) += size;
            }
        }

        for target in &self.system_targets {
            let size = target.size_bytes.unwrap_or(0);
            entries.push(CleanReportEntry {
                browser: "System".to_string(),
                category: target.category,
                path: target.path.to_string_lossy().to_string(),
                size_bytes: size,
            });
            *cat_totals.entry(target.category).or_insert(0) += size;
        }

        let total_bytes: u64 = entries.iter().map(|e| e.size_bytes).sum();
        let mut by_category: Vec<(CleanCategory, u64)> = cat_totals.into_iter().collect();
        by_category.sort_by(|a, b| b.1.cmp(&a.1));

        CleanReport {
            total_targets: entries.len(),
            total_bytes,
            by_category,
            entries,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// If `path` exists, push a `CleanTarget` onto `targets`.
fn push_if_exists(
    targets: &mut Vec<CleanTarget>,
    path: &Path,
    category: CleanCategory,
    description: &str,
) {
    if path.exists() {
        targets.push(CleanTarget {
            category,
            path: path.to_path_buf(),
            description: description.to_string(),
            size_bytes: None,
        });
    }
}

/// Recursively compute the size of a path (file or directory).
fn path_size(path: &Path) -> u64 {
    if path.is_file() {
        return fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    }
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum()
}

// ---------------------------------------------------------------------------
// Display for CleanCategory
// ---------------------------------------------------------------------------

impl std::fmt::Display for CleanCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cache => write!(f, "Cache"),
            Self::Cookies => write!(f, "Cookies"),
            Self::History => write!(f, "History"),
            Self::Sessions => write!(f, "Sessions"),
            Self::FormData => write!(f, "Form Data"),
            Self::Passwords => write!(f, "Passwords"),
            Self::Downloads => write!(f, "Downloads"),
            Self::Thumbnails => write!(f, "Thumbnails"),
            Self::ServiceWorkers => write!(f, "Service Workers"),
            Self::IndexedDB => write!(f, "IndexedDB"),
            Self::LocalStorage => write!(f, "Local Storage"),
            Self::WebSQL => write!(f, "WebSQL"),
            Self::Logs => write!(f, "Logs"),
            Self::CrashReports => write!(f, "Crash Reports"),
            Self::Extensions => write!(f, "Extensions"),
            Self::SystemTemp => write!(f, "System Temp"),
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

    /// Build a fake Firefox profile tree inside `home`.
    fn make_firefox_profile(home: &Path) -> PathBuf {
        let profile = home.join(".mozilla/firefox/abc12345.default-release");
        fs::create_dir_all(&profile).unwrap();
        // Create some cleanable files / dirs
        fs::create_dir_all(profile.join("cache2/entries")).unwrap();
        fs::write(profile.join("cache2/entries/data"), "cached").unwrap();
        fs::write(profile.join("cookies.sqlite"), "cookie-data").unwrap();
        fs::write(profile.join("places.sqlite"), "history-data").unwrap();
        fs::write(profile.join("formhistory.sqlite"), "form-data").unwrap();
        fs::write(profile.join("sessionstore.jsonlz4"), "session").unwrap();
        fs::write(profile.join("favicons.sqlite"), "favicons").unwrap();
        fs::write(profile.join("webappsstore.sqlite"), "localstorage").unwrap();
        fs::create_dir_all(profile.join("storage/default")).unwrap();
        fs::write(profile.join("storage/default/dummy"), "idb").unwrap();
        profile
    }

    /// Build a fake Chrome profile tree inside `home`.
    fn make_chrome_profile(home: &Path) -> PathBuf {
        let default = home.join(".config/google-chrome/Default");
        fs::create_dir_all(&default).unwrap();
        fs::create_dir_all(default.join("Cache/data")).unwrap();
        fs::write(default.join("Cache/data/f_00001"), "chrome-cache").unwrap();
        fs::write(default.join("Cookies"), "chrome-cookies").unwrap();
        fs::write(default.join("History"), "chrome-history").unwrap();
        fs::write(default.join("Login Data"), "passwords").unwrap();
        fs::write(default.join("Web Data"), "form-data").unwrap();
        fs::write(default.join("Favicons"), "icons").unwrap();
        fs::create_dir_all(default.join("IndexedDB")).unwrap();
        fs::write(default.join("IndexedDB/db"), "idb-data").unwrap();
        fs::create_dir_all(default.join("Service Worker")).unwrap();
        fs::write(default.join("Service Worker/sw"), "sw-data").unwrap();
        fs::create_dir_all(default.join("Local Storage")).unwrap();
        fs::write(default.join("Local Storage/ls"), "ls-data").unwrap();
        default
    }

    // -- test: discover finds Firefox profile in temp dir -------------------
    #[test]
    fn test_discover_firefox() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        make_firefox_profile(home);

        let mut cleaner = BrowserCleaner::with_home(home.to_path_buf());
        cleaner.discover();

        let ff = cleaner.browsers.iter().find(|b| b.name.contains("Firefox"));
        assert!(ff.is_some(), "Firefox profile should be discovered");
        let ff = ff.unwrap();
        assert!(
            ff.data_paths.len() >= 5,
            "Should find at least 5 targets, found {}",
            ff.data_paths.len()
        );
        // Check that cache target exists
        assert!(
            ff.data_paths.iter().any(|t| t.category == CleanCategory::Cache),
            "Should find cache targets"
        );
    }

    // -- test: discover finds Chrome profile in temp dir --------------------
    #[test]
    fn test_discover_chrome() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        make_chrome_profile(home);

        let mut cleaner = BrowserCleaner::with_home(home.to_path_buf());
        cleaner.discover();

        let chrome = cleaner.browsers.iter().find(|b| b.name.contains("Chrome"));
        assert!(chrome.is_some(), "Chrome profile should be discovered");
        let chrome = chrome.unwrap();
        assert!(
            chrome.data_paths.len() >= 5,
            "Should find at least 5 targets, found {}",
            chrome.data_paths.len()
        );
        assert!(
            chrome.data_paths.iter().any(|t| t.category == CleanCategory::Cookies),
            "Should find cookies target"
        );
    }

    // -- test: scan calculates correct sizes --------------------------------
    #[test]
    fn test_scan_calculates_sizes() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        make_firefox_profile(home);

        let mut cleaner = BrowserCleaner::with_home(home.to_path_buf());
        cleaner.discover();
        let report = cleaner.scan();

        assert!(report.total_targets > 0, "Should have targets");
        assert!(report.total_bytes > 0, "Should have non-zero total bytes");

        // Every browser target should now have size_bytes populated
        for browser in &cleaner.browsers {
            for target in &browser.data_paths {
                assert!(target.size_bytes.is_some(), "size_bytes should be populated for {}", target.path.display());
            }
        }
    }

    // -- test: clean removes files ------------------------------------------
    #[test]
    fn test_clean_removes_files() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let profile = make_firefox_profile(home);

        let cookies_path = profile.join("cookies.sqlite");
        assert!(cookies_path.exists(), "cookies should exist before clean");

        let mut cleaner = BrowserCleaner::with_home(home.to_path_buf());
        cleaner.discover();

        // Clean only cookies
        cleaner.clean(
            &[CleanCategory::Cookies],
            ErasureAlgorithm::ZeroFill,
        ).unwrap();

        assert!(!cookies_path.exists(), "cookies should be deleted after clean");

        // Cache should still exist (we only cleaned cookies)
        assert!(profile.join("cache2").exists(), "cache should not be touched");
    }

    // -- test: dry_run doesn't delete anything ------------------------------
    #[test]
    fn test_dry_run_no_delete() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let profile = make_firefox_profile(home);

        let mut cleaner = BrowserCleaner::with_home(home.to_path_buf());
        cleaner.discover();

        let report = cleaner.dry_run();
        assert!(report.total_targets > 0);
        assert!(report.total_bytes > 0);

        // Nothing should be deleted
        assert!(profile.join("cookies.sqlite").exists());
        assert!(profile.join("cache2").exists());
        assert!(profile.join("places.sqlite").exists());
    }

    // -- test: category filtering works -------------------------------------
    #[test]
    fn test_category_filtering() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let profile = make_firefox_profile(home);

        let mut cleaner = BrowserCleaner::with_home(home.to_path_buf());
        cleaner.discover();

        // Clean only cache, not passwords or cookies
        cleaner.clean(
            &[CleanCategory::Cache],
            ErasureAlgorithm::ZeroFill,
        ).unwrap();

        // Cache should be gone
        assert!(!profile.join("cache2").exists(), "cache should be deleted");

        // Everything else should remain
        assert!(profile.join("cookies.sqlite").exists(), "cookies should remain");
        assert!(profile.join("places.sqlite").exists(), "history should remain");
        assert!(profile.join("formhistory.sqlite").exists(), "form data should remain");
        assert!(profile.join("sessionstore.jsonlz4").exists(), "sessions should remain");
    }
}
