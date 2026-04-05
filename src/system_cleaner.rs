//! System-wide cleanup engine.
//!
//! Discovers and securely deletes system caches, logs, temp files, old kernels,
//! package manager caches, container artifacts, and more across the entire OS.
//!
//! More thorough than BleachBit: covers package manager caches (apt, dnf,
//! pacman), systemd journal, old kernels, rotated logs, thumbnail/font/shader
//! caches, language tool caches (pip, npm, yarn, cargo), Docker/Podman
//! artifacts, Snap/Flatpak leftovers, core dumps, temp files, and recent
//! document tracking files.

use plausiden_purge::algorithms::ErasureAlgorithm;
use plausiden_purge::destroyer;
use plausiden_purge::error::Result;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// System-wide cleaner that discovers and removes OS-level waste.
pub struct SystemCleaner {
    pub targets: Vec<SystemCleanTarget>,
    home_dir: PathBuf,
}

/// A single cleanable system target (file or directory).
pub struct SystemCleanTarget {
    pub category: SystemCategory,
    pub paths: Vec<PathBuf>,
    pub description: String,
    pub requires_root: bool,
    pub size_bytes: Option<u64>,
}

/// Categories of system data that can be cleaned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemCategory {
    PackageCache,
    SystemLogs,
    OldKernels,
    ThumbnailCache,
    ShaderCache,
    LanguageCache,
    ContainerCache,
    SnapFlatpak,
    TempFiles,
    CoreDumps,
    RecentDocuments,
}

impl std::fmt::Display for SystemCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PackageCache => write!(f, "Package Cache"),
            Self::SystemLogs => write!(f, "System Logs"),
            Self::OldKernels => write!(f, "Old Kernels"),
            Self::ThumbnailCache => write!(f, "Thumbnail Cache"),
            Self::ShaderCache => write!(f, "Shader Cache"),
            Self::LanguageCache => write!(f, "Language Cache"),
            Self::ContainerCache => write!(f, "Container Cache"),
            Self::SnapFlatpak => write!(f, "Snap/Flatpak"),
            Self::TempFiles => write!(f, "Temp Files"),
            Self::CoreDumps => write!(f, "Core Dumps"),
            Self::RecentDocuments => write!(f, "Recent Documents"),
        }
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Summary produced by `scan()` and `dry_run()`.
#[derive(Debug)]
pub struct SystemCleanReport {
    pub total_targets: usize,
    pub total_bytes: u64,
    pub by_category: Vec<(SystemCategory, u64)>,
    pub entries: Vec<SystemReportEntry>,
}

#[derive(Debug)]
pub struct SystemReportEntry {
    pub category: SystemCategory,
    pub description: String,
    pub paths: Vec<String>,
    pub size_bytes: u64,
    pub requires_root: bool,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl SystemCleaner {
    /// Create a cleaner rooted at the real user home directory.
    pub fn new() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        Self {
            targets: Vec::new(),
            home_dir,
        }
    }

    /// Create a cleaner rooted at an arbitrary directory (for testing).
    pub fn with_home(home: PathBuf) -> Self {
        Self {
            targets: Vec::new(),
            home_dir: home,
        }
    }

    // -- discover -----------------------------------------------------------

    /// Scan the system for all cleanable targets.
    pub fn discover(&mut self) {
        self.targets.clear();

        self.discover_package_caches();
        self.discover_system_logs();
        self.discover_old_kernels();
        self.discover_thumbnail_cache();
        self.discover_shader_cache();
        self.discover_language_caches();
        self.discover_container_caches();
        self.discover_snap_flatpak();
        self.discover_temp_files();
        self.discover_core_dumps();
        self.discover_recent_documents();
    }

    // -- scan ---------------------------------------------------------------

    /// Calculate sizes for all discovered targets. Returns a report.
    pub fn scan(&mut self) -> SystemCleanReport {
        for target in &mut self.targets {
            if target.size_bytes.is_none() {
                let total: u64 = target
                    .paths
                    .iter()
                    .map(|p| path_size(p))
                    .sum();
                target.size_bytes = Some(total);
            }
        }
        self.build_report()
    }

    // -- clean --------------------------------------------------------------

    /// Securely delete targets matching the given categories using the
    /// specified erasure algorithm.
    pub fn clean(
        &mut self,
        categories: &[SystemCategory],
        algorithm: ErasureAlgorithm,
    ) -> Result<SystemCleanReport> {
        let report = self.scan();
        let passes = algorithm.patterns().len() as u32;

        for target in &self.targets {
            if !categories.contains(&target.category) {
                continue;
            }
            for path in &target.paths {
                if path.exists() {
                    let p = path.to_string_lossy().to_string();
                    if let Err(e) = destroyer::secure_delete(&p, passes, false) {
                        tracing::warn!("Failed to clean {p}: {e}");
                    }
                }
            }
        }

        Ok(report)
    }

    // -- dry_run ------------------------------------------------------------

    /// Show what would be cleaned without deleting anything.
    pub fn dry_run(&mut self) -> SystemCleanReport {
        self.scan()
    }

    // -----------------------------------------------------------------------
    // Internal: Package manager caches
    // -----------------------------------------------------------------------

    fn discover_package_caches(&mut self) {
        // APT .deb cache
        let apt_cache = PathBuf::from("/var/cache/apt/archives");
        if apt_cache.is_dir() {
            let debs: Vec<PathBuf> = fs::read_dir(&apt_cache)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .is_some_and(|ext| ext == "deb")
                })
                .collect();
            if !debs.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::PackageCache,
                    paths: debs,
                    description: "APT downloaded .deb packages".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // APT partial downloads
        let apt_partial = PathBuf::from("/var/cache/apt/archives/partial");
        if apt_partial.is_dir() {
            let partials: Vec<PathBuf> = collect_files_in_dir(&apt_partial);
            if !partials.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::PackageCache,
                    paths: partials,
                    description: "APT partial downloads".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // APT lists cache
        let apt_lists = PathBuf::from("/var/cache/apt/pkgcache.bin");
        push_single_if_exists(
            &mut self.targets,
            &apt_lists,
            SystemCategory::PackageCache,
            "APT package list cache",
            true,
        );
        let apt_src_lists = PathBuf::from("/var/cache/apt/srcpkgcache.bin");
        push_single_if_exists(
            &mut self.targets,
            &apt_src_lists,
            SystemCategory::PackageCache,
            "APT source package list cache",
            true,
        );

        // DNF cache
        let dnf_cache = PathBuf::from("/var/cache/dnf");
        if dnf_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::PackageCache,
                paths: vec![dnf_cache],
                description: "DNF package cache".to_string(),
                requires_root: true,
                size_bytes: None,
            });
        }

        // Pacman cache
        let pacman_cache = PathBuf::from("/var/cache/pacman/pkg");
        if pacman_cache.is_dir() {
            let pkgs: Vec<PathBuf> = collect_files_in_dir(&pacman_cache);
            if !pkgs.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::PackageCache,
                    paths: pkgs,
                    description: "Pacman downloaded packages".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // Zypper cache (openSUSE)
        let zypper_cache = PathBuf::from("/var/cache/zypp/packages");
        if zypper_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::PackageCache,
                paths: vec![zypper_cache],
                description: "Zypper package cache".to_string(),
                requires_root: true,
                size_bytes: None,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Internal: System logs
    // -----------------------------------------------------------------------

    fn discover_system_logs(&mut self) {
        let var_log = PathBuf::from("/var/log");
        if !var_log.is_dir() {
            return;
        }

        // Rotated logs: *.log.1, *.log.2.gz, syslog.1, etc.
        let rotated: Vec<PathBuf> = fs::read_dir(&var_log)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && is_rotated_log(p))
            .collect();
        if !rotated.is_empty() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::SystemLogs,
                paths: rotated,
                description: "Rotated log files in /var/log".to_string(),
                requires_root: true,
                size_bytes: None,
            });
        }

        // Rotated logs in subdirectories (apt, dpkg, etc.)
        let log_subdirs = ["apt", "dpkg", "cups", "samba", "nginx", "apache2",
                           "mysql", "postgresql", "unattended-upgrades", "installer"];
        for subdir in log_subdirs {
            let sub_path = var_log.join(subdir);
            if sub_path.is_dir() {
                let old_logs: Vec<PathBuf> = collect_files_recursive(&sub_path)
                    .into_iter()
                    .filter(|p| is_rotated_log(p))
                    .collect();
                if !old_logs.is_empty() {
                    self.targets.push(SystemCleanTarget {
                        category: SystemCategory::SystemLogs,
                        paths: old_logs,
                        description: format!("Rotated logs in /var/log/{subdir}"),
                        requires_root: true,
                        size_bytes: None,
                    });
                }
            }
        }

        // Systemd journal — old entries in /var/log/journal
        let journal_dir = var_log.join("journal");
        if journal_dir.is_dir() {
            // Find archived journal files (system@*.journal, user-*@*.journal)
            let archived: Vec<PathBuf> = collect_files_recursive(&journal_dir)
                .into_iter()
                .filter(|p| {
                    let name = p.file_name().unwrap_or_default().to_string_lossy();
                    // Archived journals contain @ with a timestamp
                    name.ends_with(".journal") && name.contains('@')
                })
                .collect();
            if !archived.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::SystemLogs,
                    paths: archived,
                    description: "Archived systemd journal files".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // Btmp, wtmp old entries
        let btmp = var_log.join("btmp.1");
        push_single_if_exists(
            &mut self.targets,
            &btmp,
            SystemCategory::SystemLogs,
            "Old failed login log (btmp.1)",
            true,
        );
        let wtmp = var_log.join("wtmp.1");
        push_single_if_exists(
            &mut self.targets,
            &wtmp,
            SystemCategory::SystemLogs,
            "Old login log (wtmp.1)",
            true,
        );

        // Dmesg old logs
        let dmesg_old = var_log.join("dmesg.0");
        push_single_if_exists(
            &mut self.targets,
            &dmesg_old,
            SystemCategory::SystemLogs,
            "Old dmesg log",
            true,
        );
        let dmesg_old1 = var_log.join("dmesg.1.gz");
        push_single_if_exists(
            &mut self.targets,
            &dmesg_old1,
            SystemCategory::SystemLogs,
            "Compressed old dmesg log",
            true,
        );
    }

    // -----------------------------------------------------------------------
    // Internal: Old kernels
    // -----------------------------------------------------------------------

    fn discover_old_kernels(&mut self) {
        let current_kernel = get_running_kernel_version();

        // /boot/vmlinuz-* — old kernel images
        let boot = PathBuf::from("/boot");
        if boot.is_dir() {
            let old_kernel_files: Vec<PathBuf> = fs::read_dir(&boot)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let name = p.file_name().unwrap_or_default().to_string_lossy();
                    let is_kernel = name.starts_with("vmlinuz-")
                        || name.starts_with("initrd.img-")
                        || name.starts_with("initramfs-")
                        || name.starts_with("System.map-")
                        || name.starts_with("config-");
                    if !is_kernel {
                        return false;
                    }
                    // Don't touch the running kernel
                    if let Some(ref current) = current_kernel {
                        !name.contains(current.as_str())
                    } else {
                        // If we can't determine the running kernel, skip all
                        false
                    }
                })
                .collect();
            if !old_kernel_files.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::OldKernels,
                    paths: old_kernel_files,
                    description: "Old kernel images, initramfs, and config in /boot".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // /lib/modules/*/ — old kernel module directories
        let lib_modules = PathBuf::from("/lib/modules");
        if lib_modules.is_dir() {
            let old_modules: Vec<PathBuf> = fs::read_dir(&lib_modules)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    if !p.is_dir() {
                        return false;
                    }
                    let name = p.file_name().unwrap_or_default().to_string_lossy();
                    if let Some(ref current) = current_kernel {
                        !name.contains(current.as_str())
                    } else {
                        false
                    }
                })
                .collect();
            if !old_modules.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::OldKernels,
                    paths: old_modules,
                    description: "Old kernel module directories in /lib/modules".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // /usr/src/ — old kernel headers
        let usr_src = PathBuf::from("/usr/src");
        if usr_src.is_dir() {
            let old_headers: Vec<PathBuf> = fs::read_dir(&usr_src)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let name = p.file_name().unwrap_or_default().to_string_lossy();
                    let is_header = name.starts_with("linux-headers-");
                    if !is_header {
                        return false;
                    }
                    if let Some(ref current) = current_kernel {
                        !name.contains(current.as_str())
                    } else {
                        false
                    }
                })
                .collect();
            if !old_headers.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::OldKernels,
                    paths: old_headers,
                    description: "Old kernel headers in /usr/src".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Thumbnail cache
    // -----------------------------------------------------------------------

    fn discover_thumbnail_cache(&mut self) {
        let thumb = self.home_dir.join(".cache/thumbnails");
        if thumb.is_dir() {
            // Individual subdirs: normal, large, x-large, fail
            let subdirs: Vec<PathBuf> = fs::read_dir(&thumb)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            if !subdirs.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::ThumbnailCache,
                    paths: subdirs,
                    description: "Desktop thumbnail cache (~/.cache/thumbnails)".to_string(),
                    requires_root: false,
                    size_bytes: None,
                });
            }
        }

        // GNOME-specific thumbnail cache
        let gnome_thumbs = self.home_dir.join(".thumbnails");
        if gnome_thumbs.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::ThumbnailCache,
                paths: vec![gnome_thumbs],
                description: "Legacy GNOME thumbnail cache (~/.thumbnails)".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Shader cache (Mesa, NVIDIA, etc.)
    // -----------------------------------------------------------------------

    fn discover_shader_cache(&mut self) {
        let cache_root = &self.home_dir.join(".cache");

        let shader_dirs = [
            ("mesa_shader_cache", "Mesa OpenGL/Vulkan shader cache"),
            ("mesa_shader_cache_db", "Mesa shader cache database"),
            ("nvidia", "NVIDIA GL shader cache"),
            ("radv_builtin_shaders64", "RADV Vulkan built-in shaders"),
        ];

        for (dir_name, desc) in shader_dirs {
            let p = cache_root.join(dir_name);
            if p.exists() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::ShaderCache,
                    paths: vec![p],
                    description: desc.to_string(),
                    requires_root: false,
                    size_bytes: None,
                });
            }
        }

        // DRI state cache
        let dri_prime = self.home_dir.join(".nv");
        if dri_prime.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::ShaderCache,
                paths: vec![dri_prime],
                description: "NVIDIA DRI state cache (~/.nv)".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // Font cache
        let fontconfig = cache_root.join("fontconfig");
        if fontconfig.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::ShaderCache, // group with shader/render caches
                paths: vec![fontconfig],
                description: "Font configuration cache (~/.cache/fontconfig)".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Language / tool caches (pip, npm, yarn, cargo)
    // -----------------------------------------------------------------------

    fn discover_language_caches(&mut self) {
        let cache_root = &self.home_dir.join(".cache");

        // pip
        let pip_cache = cache_root.join("pip");
        if pip_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![pip_cache],
                description: "Python pip download cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }
        // pip HTTP cache (older pip)
        let pip_http = cache_root.join("pip/http");
        if pip_http.is_dir() {
            // Already covered by parent pip dir above if it was found
        }

        // npm
        let npm_cache_1 = cache_root.join("npm");
        let npm_cache_2 = self.home_dir.join(".npm");
        let mut npm_paths = Vec::new();
        if npm_cache_1.is_dir() {
            npm_paths.push(npm_cache_1);
        }
        if npm_cache_2.is_dir() {
            npm_paths.push(npm_cache_2);
        }
        if !npm_paths.is_empty() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: npm_paths,
                description: "npm package cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // yarn
        let yarn_cache_1 = cache_root.join("yarn");
        let yarn_cache_2 = self.home_dir.join(".yarn/cache");
        let mut yarn_paths = Vec::new();
        if yarn_cache_1.is_dir() {
            yarn_paths.push(yarn_cache_1);
        }
        if yarn_cache_2.is_dir() {
            yarn_paths.push(yarn_cache_2);
        }
        if !yarn_paths.is_empty() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: yarn_paths,
                description: "Yarn package cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // pnpm
        let pnpm_cache = cache_root.join("pnpm");
        if pnpm_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![pnpm_cache],
                description: "pnpm package cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // cargo registry cache — ONLY cache dir, NOT src (don't break builds)
        let cargo_cache = self.home_dir.join(".cargo/registry/cache");
        if cargo_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![cargo_cache],
                description: "Cargo registry .crate download cache (safe to remove)".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // Go module cache
        let go_cache = cache_root.join("go-build");
        if go_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![go_cache],
                description: "Go build cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }
        let gopath_cache = self.home_dir.join("go/pkg/mod/cache/download");
        if gopath_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![gopath_cache],
                description: "Go module download cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // Maven / Gradle
        let maven_repo = self.home_dir.join(".m2/repository");
        if maven_repo.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![maven_repo],
                description: "Maven local repository cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }
        let gradle_caches = self.home_dir.join(".gradle/caches");
        if gradle_caches.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![gradle_caches],
                description: "Gradle build caches".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // Composer (PHP)
        let composer_cache = cache_root.join("composer");
        if composer_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![composer_cache],
                description: "PHP Composer package cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // Gem (Ruby)
        let gem_cache = self.home_dir.join(".gem");
        if gem_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![gem_cache],
                description: "Ruby gem cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // NuGet (.NET)
        let nuget_cache = self.home_dir.join(".nuget/packages");
        if nuget_cache.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::LanguageCache,
                paths: vec![nuget_cache],
                description: ".NET NuGet package cache".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Container caches (Docker, Podman)
    // -----------------------------------------------------------------------

    fn discover_container_caches(&mut self) {
        // Docker — check for socket / root directory
        let docker_root = PathBuf::from("/var/lib/docker");
        if docker_root.is_dir() {
            // Docker build cache
            let build_cache = docker_root.join("buildkit");
            if build_cache.is_dir() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::ContainerCache,
                    paths: vec![build_cache],
                    description: "Docker BuildKit cache".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }

            // Docker overlay2 diff layers (dangling)
            let overlay = docker_root.join("overlay2");
            if overlay.is_dir() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::ContainerCache,
                    paths: vec![overlay.join("l")], // link directory
                    description: "Docker overlay2 layer links (run `docker system prune`)".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }

            // Docker volumes (orphaned — the overlay itself)
            let volumes = docker_root.join("volumes");
            if volumes.is_dir() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::ContainerCache,
                    paths: vec![volumes],
                    description: "Docker volumes (review before cleaning)".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }

            // Docker tmp
            let docker_tmp = docker_root.join("tmp");
            if docker_tmp.is_dir() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::ContainerCache,
                    paths: vec![docker_tmp],
                    description: "Docker temp files".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // Podman (rootless — user-level)
        let podman_root = self.home_dir.join(".local/share/containers");
        if podman_root.is_dir() {
            let podman_cache = podman_root.join("cache");
            if podman_cache.is_dir() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::ContainerCache,
                    paths: vec![podman_cache],
                    description: "Podman container cache".to_string(),
                    requires_root: false,
                    size_bytes: None,
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Snap / Flatpak leftovers
    // -----------------------------------------------------------------------

    fn discover_snap_flatpak(&mut self) {
        // Snap: old revisions kept in /snap/<name>/
        let snap_dir = PathBuf::from("/snap");
        if snap_dir.is_dir() {
            let mut old_snaps = Vec::new();
            if let Ok(entries) = fs::read_dir(&snap_dir) {
                for entry in entries.flatten() {
                    let snap_app = entry.path();
                    if !snap_app.is_dir() {
                        continue;
                    }
                    // Each snap app directory has numbered revision dirs
                    // The current revision is symlinked; old revisions can be removed
                    if let Ok(revisions) = fs::read_dir(&snap_app) {
                        let mut rev_dirs: Vec<PathBuf> = revisions
                            .flatten()
                            .map(|e| e.path())
                            .filter(|p| {
                                p.is_dir()
                                    && !p.is_symlink()
                                    && p.file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .chars()
                                        .all(|c| c.is_ascii_digit())
                            })
                            .collect();
                        // Sort by revision number descending, skip the newest
                        rev_dirs.sort_by(|a, b| {
                            let a_num: u64 = a.file_name().unwrap_or_default()
                                .to_string_lossy().parse().unwrap_or(0);
                            let b_num: u64 = b.file_name().unwrap_or_default()
                                .to_string_lossy().parse().unwrap_or(0);
                            b_num.cmp(&a_num)
                        });
                        if rev_dirs.len() > 1 {
                            // Keep newest, add rest as old
                            old_snaps.extend(rev_dirs.into_iter().skip(1));
                        }
                    }
                }
            }
            if !old_snaps.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::SnapFlatpak,
                    paths: old_snaps,
                    description: "Old Snap revisions".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // Snap cache
        let snap_cache = self.home_dir.join("snap");
        if snap_cache.is_dir() {
            // User-level snap data (can accumulate old common dirs)
            let common_dirs: Vec<PathBuf> = fs::read_dir(&snap_cache)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path().join("common/.cache"))
                .filter(|p| p.is_dir())
                .collect();
            if !common_dirs.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::SnapFlatpak,
                    paths: common_dirs,
                    description: "Snap application common caches".to_string(),
                    requires_root: false,
                    size_bytes: None,
                });
            }
        }

        // Flatpak unused runtimes
        let flatpak_runtime = PathBuf::from("/var/lib/flatpak/runtime");
        if flatpak_runtime.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::SnapFlatpak,
                paths: vec![flatpak_runtime],
                description: "Flatpak runtimes (run `flatpak uninstall --unused`)".to_string(),
                requires_root: true,
                size_bytes: None,
            });
        }

        // User-level Flatpak
        let flatpak_user = self.home_dir.join(".local/share/flatpak/repo/tmp");
        if flatpak_user.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::SnapFlatpak,
                paths: vec![flatpak_user],
                description: "Flatpak user repo temp files".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Temp files
    // -----------------------------------------------------------------------

    fn discover_temp_files(&mut self) {
        let uid = unsafe { libc::getuid() };

        // /tmp — only user-owned files
        let tmp = PathBuf::from("/tmp");
        if tmp.is_dir() {
            let user_tmp: Vec<PathBuf> = fs::read_dir(&tmp)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|entry| {
                    let path = entry.path();
                    let meta = fs::symlink_metadata(&path).ok()?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if meta.uid() == uid {
                            return Some(path);
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = meta;
                        return Some(path);
                    }
                    None
                })
                .collect();
            if !user_tmp.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::TempFiles,
                    paths: user_tmp,
                    description: "User-owned files in /tmp".to_string(),
                    requires_root: false,
                    size_bytes: None,
                });
            }
        }

        // /var/tmp — old files (>7 days by convention)
        let var_tmp = PathBuf::from("/var/tmp");
        if var_tmp.is_dir() {
            let old_var_tmp: Vec<PathBuf> = fs::read_dir(&var_tmp)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|entry| {
                    let path = entry.path();
                    let meta = fs::metadata(&path).ok()?;
                    let modified = meta.modified().ok()?;
                    let age = modified.elapsed().ok()?;
                    // Older than 7 days
                    if age.as_secs() > 7 * 86400 {
                        Some(path)
                    } else {
                        None
                    }
                })
                .collect();
            if !old_var_tmp.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::TempFiles,
                    paths: old_var_tmp,
                    description: "Old files in /var/tmp (>7 days)".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // ~/.local/share/Trash
        let trash = self.home_dir.join(".local/share/Trash");
        if trash.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::TempFiles,
                paths: vec![trash],
                description: "Desktop trash".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // Vim/Neovim swap and undo files
        let vim_swap = self.home_dir.join(".local/state/nvim/swap");
        let vim_undo = self.home_dir.join(".local/state/nvim/undo");
        let mut vim_paths = Vec::new();
        if vim_swap.is_dir() {
            vim_paths.push(vim_swap);
        }
        if vim_undo.is_dir() {
            vim_paths.push(vim_undo);
        }
        if !vim_paths.is_empty() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::TempFiles,
                paths: vim_paths,
                description: "Neovim swap and undo files".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // .xsession-errors (can grow unbounded)
        let xsession = self.home_dir.join(".xsession-errors");
        push_single_if_exists(
            &mut self.targets,
            &xsession,
            SystemCategory::TempFiles,
            "X session error log",
            false,
        );
        let xsession_old = self.home_dir.join(".xsession-errors.old");
        push_single_if_exists(
            &mut self.targets,
            &xsession_old,
            SystemCategory::TempFiles,
            "Old X session error log",
            false,
        );
    }

    // -----------------------------------------------------------------------
    // Internal: Core dumps
    // -----------------------------------------------------------------------

    fn discover_core_dumps(&mut self) {
        // Systemd coredumps
        let coredump_dir = PathBuf::from("/var/lib/systemd/coredump");
        if coredump_dir.is_dir() {
            let dumps: Vec<PathBuf> = collect_files_in_dir(&coredump_dir);
            if !dumps.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::CoreDumps,
                    paths: dumps,
                    description: "Systemd core dumps".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }

        // User core dumps (core.* in home or common dirs)
        let mut user_cores = Vec::new();
        let core_locations = [&self.home_dir as &Path, Path::new("/tmp")];
        for dir in core_locations {
            if dir.is_dir() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with("core.") || name == "core" {
                            let path = entry.path();
                            if path.is_file() {
                                user_cores.push(path);
                            }
                        }
                    }
                }
            }
        }
        if !user_cores.is_empty() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::CoreDumps,
                paths: user_cores,
                description: "User core dump files".to_string(),
                requires_root: false,
                size_bytes: None,
            });
        }

        // Abrt (Fedora crash handler)
        let abrt_dir = PathBuf::from("/var/spool/abrt");
        if abrt_dir.is_dir() {
            self.targets.push(SystemCleanTarget {
                category: SystemCategory::CoreDumps,
                paths: vec![abrt_dir],
                description: "ABRT crash reports".to_string(),
                requires_root: true,
                size_bytes: None,
            });
        }

        // Apport (Ubuntu crash handler)
        let apport_dir = PathBuf::from("/var/crash");
        if apport_dir.is_dir() {
            let crash_files: Vec<PathBuf> = collect_files_in_dir(&apport_dir);
            if !crash_files.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::CoreDumps,
                    paths: crash_files,
                    description: "Apport crash reports".to_string(),
                    requires_root: true,
                    size_bytes: None,
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Recent documents
    // -----------------------------------------------------------------------

    fn discover_recent_documents(&mut self) {
        // recently-used.xbel (GNOME/XFCE/etc.)
        let recent_xbel = self.home_dir.join(".local/share/recently-used.xbel");
        push_single_if_exists(
            &mut self.targets,
            &recent_xbel,
            SystemCategory::RecentDocuments,
            "Recently used documents list (recently-used.xbel)",
            false,
        );

        // KDE recent documents
        let kde_recent = self.home_dir.join(".local/share/RecentDocuments");
        if kde_recent.is_dir() {
            let files: Vec<PathBuf> = collect_files_in_dir(&kde_recent);
            if !files.is_empty() {
                self.targets.push(SystemCleanTarget {
                    category: SystemCategory::RecentDocuments,
                    paths: files,
                    description: "KDE recent document entries".to_string(),
                    requires_root: false,
                    size_bytes: None,
                });
            }
        }

        // GTK recent manager bookmarks
        let gtk_recent = self.home_dir.join(".local/share/recently-used.xbel.bak");
        push_single_if_exists(
            &mut self.targets,
            &gtk_recent,
            SystemCategory::RecentDocuments,
            "Recently used backup file",
            false,
        );

        // Bash history
        let bash_history = self.home_dir.join(".bash_history");
        push_single_if_exists(
            &mut self.targets,
            &bash_history,
            SystemCategory::RecentDocuments,
            "Bash command history",
            false,
        );

        // Zsh history
        let zsh_history = self.home_dir.join(".zsh_history");
        push_single_if_exists(
            &mut self.targets,
            &zsh_history,
            SystemCategory::RecentDocuments,
            "Zsh command history",
            false,
        );

        // Python history
        let python_history = self.home_dir.join(".python_history");
        push_single_if_exists(
            &mut self.targets,
            &python_history,
            SystemCategory::RecentDocuments,
            "Python REPL history",
            false,
        );

        // Less history
        let less_history = self.home_dir.join(".lesshst");
        push_single_if_exists(
            &mut self.targets,
            &less_history,
            SystemCategory::RecentDocuments,
            "Less pager search history",
            false,
        );

        // Vim info / Neovim shada
        let viminfo = self.home_dir.join(".viminfo");
        push_single_if_exists(
            &mut self.targets,
            &viminfo,
            SystemCategory::RecentDocuments,
            "Vim history/registers (viminfo)",
            false,
        );
        let shada = self.home_dir.join(".local/state/nvim/shada/main.shada");
        push_single_if_exists(
            &mut self.targets,
            &shada,
            SystemCategory::RecentDocuments,
            "Neovim history/registers (shada)",
            false,
        );

        // Wget history
        let wget_hsts = self.home_dir.join(".wget-hsts");
        push_single_if_exists(
            &mut self.targets,
            &wget_hsts,
            SystemCategory::RecentDocuments,
            "Wget HSTS cache",
            false,
        );
    }

    // -----------------------------------------------------------------------
    // Internal: build report
    // -----------------------------------------------------------------------

    fn build_report(&self) -> SystemCleanReport {
        let mut entries: Vec<SystemReportEntry> = Vec::new();
        let mut cat_totals: HashMap<SystemCategory, u64> = HashMap::new();

        for target in &self.targets {
            let size = target.size_bytes.unwrap_or(0);
            entries.push(SystemReportEntry {
                category: target.category,
                description: target.description.clone(),
                paths: target.paths.iter().map(|p| p.to_string_lossy().to_string()).collect(),
                size_bytes: size,
                requires_root: target.requires_root,
            });
            *cat_totals.entry(target.category).or_insert(0) += size;
        }

        let total_bytes: u64 = entries.iter().map(|e| e.size_bytes).sum();
        let mut by_category: Vec<(SystemCategory, u64)> = cat_totals.into_iter().collect();
        by_category.sort_by(|a, b| b.1.cmp(&a.1));

        SystemCleanReport {
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

/// If `path` exists, push a `SystemCleanTarget` with a single path.
fn push_single_if_exists(
    targets: &mut Vec<SystemCleanTarget>,
    path: &Path,
    category: SystemCategory,
    description: &str,
    requires_root: bool,
) {
    if path.exists() {
        targets.push(SystemCleanTarget {
            category,
            paths: vec![path.to_path_buf()],
            description: description.to_string(),
            requires_root,
            size_bytes: None,
        });
    }
}

/// Collect all files (non-recursive) in a directory.
fn collect_files_in_dir(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect()
}

/// Collect all files recursively under a directory.
fn collect_files_recursive(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

/// Check if a filename looks like a rotated log.
fn is_rotated_log(path: &Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    // Matches: *.log.1, *.log.2.gz, syslog.1, kern.log.1, etc.
    // Also: *.gz, *.xz, *.bz2, *.zst (compressed old logs)
    // Also: *.old

    // Numbered rotations
    let has_rotation_number = name.contains(".1")
        || name.contains(".2")
        || name.contains(".3")
        || name.contains(".4")
        || name.contains(".5")
        || name.contains(".6")
        || name.contains(".7")
        || name.contains(".8")
        || name.contains(".9");

    if has_rotation_number {
        return true;
    }

    // Compressed old logs
    if name.ends_with(".gz") || name.ends_with(".xz")
        || name.ends_with(".bz2") || name.ends_with(".zst")
    {
        return true;
    }

    // Explicit ".old" suffix
    if name.ends_with(".old") {
        return true;
    }

    false
}

/// Recursively compute the size of a path (file or directory).
fn path_size(path: &Path) -> u64 {
    if path.is_file() {
        return fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    }
    if !path.exists() {
        return 0;
    }
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum()
}

/// Get the running kernel version string (e.g., "6.18.12+kali-amd64").
fn get_running_kernel_version() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let uname = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .ok()?;
        let version = String::from_utf8_lossy(&uname.stdout).trim().to_string();
        if version.is_empty() {
            None
        } else {
            Some(version)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Parse a comma-separated category string into a list of SystemCategory values.
/// Returns all categories if "all" is specified.
pub fn parse_system_categories(input: &str) -> Vec<SystemCategory> {
    if input.trim().eq_ignore_ascii_case("all") {
        return vec![
            SystemCategory::PackageCache,
            SystemCategory::SystemLogs,
            SystemCategory::OldKernels,
            SystemCategory::ThumbnailCache,
            SystemCategory::ShaderCache,
            SystemCategory::LanguageCache,
            SystemCategory::ContainerCache,
            SystemCategory::SnapFlatpak,
            SystemCategory::TempFiles,
            SystemCategory::CoreDumps,
            SystemCategory::RecentDocuments,
        ];
    }

    input
        .split(',')
        .filter_map(|s| match s.trim().to_lowercase().as_str() {
            "packagecache" | "package" | "apt" | "dnf" | "pacman" => {
                Some(SystemCategory::PackageCache)
            }
            "systemlogs" | "logs" | "journal" => Some(SystemCategory::SystemLogs),
            "oldkernels" | "kernels" => Some(SystemCategory::OldKernels),
            "thumbnailcache" | "thumbnails" | "thumbs" => {
                Some(SystemCategory::ThumbnailCache)
            }
            "shadercache" | "shaders" | "mesa" | "fontcache" => {
                Some(SystemCategory::ShaderCache)
            }
            "languagecache" | "lang" | "pip" | "npm" | "yarn" | "cargo" => {
                Some(SystemCategory::LanguageCache)
            }
            "containercache" | "docker" | "podman" | "containers" => {
                Some(SystemCategory::ContainerCache)
            }
            "snapflatpak" | "snap" | "flatpak" => Some(SystemCategory::SnapFlatpak),
            "tempfiles" | "temp" | "tmp" => Some(SystemCategory::TempFiles),
            "coredumps" | "cores" | "dumps" => Some(SystemCategory::CoreDumps),
            "recentdocuments" | "recent" | "history" => {
                Some(SystemCategory::RecentDocuments)
            }
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a fake system layout inside a temp home directory.
    fn make_system_layout(home: &Path) {
        // Thumbnail cache
        let thumbs = home.join(".cache/thumbnails/normal");
        fs::create_dir_all(&thumbs).unwrap();
        fs::write(thumbs.join("abc123.png"), "thumb-data-1234").unwrap();
        fs::write(thumbs.join("def456.png"), "thumb-data-5678").unwrap();

        let thumbs_large = home.join(".cache/thumbnails/large");
        fs::create_dir_all(&thumbs_large).unwrap();
        fs::write(thumbs_large.join("big.png"), "large-thumb").unwrap();

        // Font cache
        let fontcfg = home.join(".cache/fontconfig");
        fs::create_dir_all(&fontcfg).unwrap();
        fs::write(fontcfg.join("cache-1"), "font-cache").unwrap();

        // Mesa shader cache
        let mesa = home.join(".cache/mesa_shader_cache");
        fs::create_dir_all(&mesa).unwrap();
        fs::write(mesa.join("shader.bin"), "compiled-shader").unwrap();

        // pip cache
        let pip = home.join(".cache/pip/wheels");
        fs::create_dir_all(&pip).unwrap();
        fs::write(pip.join("some_pkg.whl"), "wheel-data").unwrap();

        // npm cache
        let npm = home.join(".npm/_cacache");
        fs::create_dir_all(&npm).unwrap();
        fs::write(npm.join("entry"), "npm-cached").unwrap();

        // Cargo registry cache (NOT src)
        let cargo_cache = home.join(".cargo/registry/cache/crates-io");
        fs::create_dir_all(&cargo_cache).unwrap();
        fs::write(cargo_cache.join("serde-1.0.0.crate"), "crate-archive").unwrap();

        // Recently used
        let local_share = home.join(".local/share");
        fs::create_dir_all(&local_share).unwrap();
        fs::write(
            local_share.join("recently-used.xbel"),
            "<?xml version=\"1.0\"?><xbel/>",
        )
        .unwrap();

        // Bash history
        fs::write(home.join(".bash_history"), "ls\ncd /tmp\npwd\n").unwrap();

        // Trash
        let trash = home.join(".local/share/Trash/files");
        fs::create_dir_all(&trash).unwrap();
        fs::write(trash.join("deleted_doc.txt"), "trashed file").unwrap();

        // X session errors
        fs::write(home.join(".xsession-errors"), "some X error\n").unwrap();
    }

    // -- test: discover finds user-level targets in temp dir -------------------
    #[test]
    fn test_discover_finds_user_targets() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        make_system_layout(home);

        let mut cleaner = SystemCleaner::with_home(home.to_path_buf());
        cleaner.discover();

        assert!(
            !cleaner.targets.is_empty(),
            "Should discover at least some targets"
        );

        // Check that thumbnail cache was found
        let has_thumbs = cleaner.targets.iter().any(|t| {
            t.category == SystemCategory::ThumbnailCache
        });
        assert!(has_thumbs, "Should find thumbnail cache");

        // Check that shader cache was found
        let has_shader = cleaner.targets.iter().any(|t| {
            t.category == SystemCategory::ShaderCache
        });
        assert!(has_shader, "Should find shader/font cache");

        // Check that language caches were found
        let has_lang = cleaner.targets.iter().any(|t| {
            t.category == SystemCategory::LanguageCache
        });
        assert!(has_lang, "Should find language caches (pip, npm, cargo)");

        // Check recent documents
        let has_recent = cleaner.targets.iter().any(|t| {
            t.category == SystemCategory::RecentDocuments
        });
        assert!(has_recent, "Should find recent documents");
    }

    // -- test: scan populates sizes correctly ----------------------------------
    #[test]
    fn test_scan_populates_sizes() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        make_system_layout(home);

        let mut cleaner = SystemCleaner::with_home(home.to_path_buf());
        cleaner.discover();
        let report = cleaner.scan();

        assert!(report.total_targets > 0, "Should have targets");
        assert!(report.total_bytes > 0, "Should have non-zero total bytes");

        // Every target should now have size_bytes populated
        for target in &cleaner.targets {
            assert!(
                target.size_bytes.is_some(),
                "size_bytes should be populated for: {}",
                target.description
            );
        }
    }

    // -- test: dry_run does not delete anything --------------------------------
    #[test]
    fn test_dry_run_preserves_files() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        make_system_layout(home);

        let thumb_file = home.join(".cache/thumbnails/normal/abc123.png");
        assert!(thumb_file.exists(), "thumb should exist before dry_run");

        let mut cleaner = SystemCleaner::with_home(home.to_path_buf());
        cleaner.discover();
        let report = cleaner.dry_run();

        assert!(report.total_targets > 0);
        assert!(report.total_bytes > 0);

        // Nothing should be deleted
        assert!(
            thumb_file.exists(),
            "thumb should still exist after dry_run"
        );
        assert!(
            home.join(".cache/pip/wheels/some_pkg.whl").exists(),
            "pip cache should still exist after dry_run"
        );
        assert!(
            home.join(".local/share/recently-used.xbel").exists(),
            "recent docs should still exist after dry_run"
        );
    }

    // -- test: clean removes only selected categories --------------------------
    #[test]
    fn test_clean_removes_selected_categories() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        make_system_layout(home);

        let thumb_file = home.join(".cache/thumbnails/normal/abc123.png");
        let pip_file = home.join(".cache/pip/wheels/some_pkg.whl");
        let recent_file = home.join(".local/share/recently-used.xbel");

        assert!(thumb_file.exists());
        assert!(pip_file.exists());
        assert!(recent_file.exists());

        let mut cleaner = SystemCleaner::with_home(home.to_path_buf());
        cleaner.discover();

        // Only clean thumbnail cache
        cleaner
            .clean(
                &[SystemCategory::ThumbnailCache],
                ErasureAlgorithm::ZeroFill,
            )
            .unwrap();

        // Thumbnails should be gone
        assert!(
            !thumb_file.exists(),
            "thumb should be deleted after cleaning ThumbnailCache"
        );

        // Other categories should remain untouched
        assert!(
            pip_file.exists(),
            "pip cache should remain (not in cleaned categories)"
        );
        assert!(
            recent_file.exists(),
            "recent docs should remain (not in cleaned categories)"
        );
    }

    // -- test: parse_system_categories handles "all" and individual names ------
    #[test]
    fn test_parse_system_categories() {
        let all = parse_system_categories("all");
        assert_eq!(all.len(), 11, "\"all\" should return all 11 categories");

        let specific = parse_system_categories("thumbnails,pip,recent");
        assert_eq!(specific.len(), 3);
        assert!(specific.contains(&SystemCategory::ThumbnailCache));
        assert!(specific.contains(&SystemCategory::LanguageCache));
        assert!(specific.contains(&SystemCategory::RecentDocuments));

        let aliases = parse_system_categories("apt,docker,cores");
        assert!(aliases.contains(&SystemCategory::PackageCache));
        assert!(aliases.contains(&SystemCategory::ContainerCache));
        assert!(aliases.contains(&SystemCategory::CoreDumps));

        let empty = parse_system_categories("bogus,invalid");
        assert!(empty.is_empty(), "invalid categories should be ignored");
    }

    // -- test: report groups by category correctly ----------------------------
    #[test]
    fn test_report_groups_by_category() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        make_system_layout(home);

        let mut cleaner = SystemCleaner::with_home(home.to_path_buf());
        cleaner.discover();
        let report = cleaner.scan();

        // by_category should have entries
        assert!(
            !report.by_category.is_empty(),
            "by_category should not be empty"
        );

        // Each category in by_category should sum correctly
        for (cat, cat_bytes) in &report.by_category {
            let entry_sum: u64 = report
                .entries
                .iter()
                .filter(|e| &e.category == cat)
                .map(|e| e.size_bytes)
                .sum();
            assert_eq!(
                *cat_bytes, entry_sum,
                "Category {cat} totals should match: {cat_bytes} vs {entry_sum}"
            );
        }
    }

    // -- test: requires_root is set correctly ---------------------------------
    #[test]
    fn test_requires_root_flag() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        make_system_layout(home);

        let mut cleaner = SystemCleaner::with_home(home.to_path_buf());
        cleaner.discover();

        // User-level targets (thumbnail cache, language cache, recent docs)
        // should NOT require root
        for target in &cleaner.targets {
            match target.category {
                SystemCategory::ThumbnailCache
                | SystemCategory::LanguageCache
                | SystemCategory::RecentDocuments => {
                    assert!(
                        !target.requires_root,
                        "{} should not require root",
                        target.description
                    );
                }
                _ => {}
            }
        }
    }

    // -- test: is_rotated_log detects rotated log filenames --------------------
    #[test]
    fn test_is_rotated_log() {
        assert!(is_rotated_log(Path::new("syslog.1")));
        assert!(is_rotated_log(Path::new("kern.log.2.gz")));
        assert!(is_rotated_log(Path::new("auth.log.3.xz")));
        assert!(is_rotated_log(Path::new("daemon.log.old")));
        assert!(is_rotated_log(Path::new("messages.4.bz2")));
        assert!(is_rotated_log(Path::new("dpkg.log.1")));

        assert!(!is_rotated_log(Path::new("syslog")));
        assert!(!is_rotated_log(Path::new("kern.log")));
        assert!(!is_rotated_log(Path::new("messages")));
    }
}
