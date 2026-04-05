//! PlausiDen Purge — Storage Sovereignty Engine
//!
//! Intelligent app usage tracking, archival, and secure data destruction
//! beyond NIST 800-88. Tracks which applications and files are actually used,
//! archives or securely deletes the rest, and backfills with synthetic data
//! via plausiden-engine.

mod algorithms;
mod analyzer;
mod archiver;
mod browser_cleaner;
mod config;
mod dedup;
mod destroyer;
mod error;
mod scanner;
mod system_cleaner;
mod tracker;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// PlausiDen Purge — storage sovereignty engine.
#[derive(Parser)]
#[command(name = "purge", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan the system for unused apps and files
    Scan {
        /// Directory to scan
        #[arg(default_value = "/home")]
        path: String,
        /// Days since last access to consider "unused"
        #[arg(long, default_value = "90")]
        unused_days: u64,
    },
    /// Show storage usage report
    Report,
    /// Archive unused files (compress + encrypt)
    Archive {
        /// Directory to archive from
        path: String,
    },
    /// Securely destroy files (beyond NIST 800-88)
    Destroy {
        /// File or directory to destroy
        path: String,
        /// Number of overwrite passes
        #[arg(long, default_value = "3")]
        passes: u32,
        /// Verify destruction
        #[arg(long)]
        verify: bool,
    },
    /// Show app usage tracking data
    Usage,
    /// Run as a daemon monitoring storage
    Daemon,
    /// Clean browser caches, cookies, history, and system temp files
    BrowserClean {
        /// Only show what would be cleaned (no deletions)
        #[arg(long)]
        dry_run: bool,
        /// Categories to clean (comma-separated). Default: cache.
        /// Options: cache,cookies,history,sessions,formdata,passwords,
        /// downloads,thumbnails,serviceworkers,indexeddb,localstorage,
        /// websql,logs,crashreports,extensions,systemtemp
        #[arg(long, default_value = "cache")]
        categories: String,
        /// Erasure algorithm: zerofill, nist, dod, gutmann, crypto
        #[arg(long, default_value = "nist")]
        algorithm: String,
    },
    /// System-wide cleanup: package caches, logs, old kernels, temp files, and more
    SystemClean {
        /// Only show what would be cleaned (no deletions)
        #[arg(long)]
        dry_run: bool,
        /// Categories to clean (comma-separated). Default: all.
        /// Options: all,package,logs,kernels,thumbnails,shaders,
        /// lang,docker,snap,temp,cores,recent
        #[arg(long, default_value = "all")]
        categories: String,
        /// Erasure algorithm: zerofill, nist, dod, gutmann, crypto
        #[arg(long, default_value = "nist")]
        algorithm: String,
    },
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    match cli.command {
        Commands::Scan { path, unused_days } => {
            tracing::info!("Scanning {path} for files unused in {unused_days} days");
            let results = scanner::scan_directory(&path, unused_days);
            match results {
                Ok(report) => {
                    println!("Scan complete:");
                    println!("  Total files: {}", report.total_files);
                    println!("  Unused files: {}", report.unused_files);
                    println!("  Reclaimable space: {}", bytesize::ByteSize(report.reclaimable_bytes));
                }
                Err(e) => eprintln!("Scan failed: {e}"),
            }
        }
        Commands::Report => {
            tracing::info!("Generating storage report");
            todo!("Storage report generation")
        }
        Commands::Archive { path } => {
            tracing::info!("Archiving unused files from {path}");
            todo!("Archive implementation")
        }
        Commands::Destroy { path, passes, verify } => {
            tracing::info!("Securely destroying {path} ({passes} passes, verify={verify})");
            match destroyer::secure_delete(&path, passes, verify) {
                Ok(()) => println!("Destruction complete: {path}"),
                Err(e) => eprintln!("Destruction failed: {e}"),
            }
        }
        Commands::Usage => {
            tracing::info!("Showing app usage data");
            todo!("Usage tracking display")
        }
        Commands::Daemon => {
            tracing::info!("Starting Purge daemon");
            todo!("Daemon mode")
        }
        Commands::BrowserClean { dry_run, categories, algorithm } => {
            tracing::info!("Browser clean (dry_run={dry_run})");

            let cats = parse_categories(&categories);
            if cats.is_empty() {
                eprintln!("No valid categories specified. Use --categories cache,cookies,...");
                std::process::exit(1);
            }

            let algo = match algorithm.as_str() {
                "zerofill" | "zero" => algorithms::ErasureAlgorithm::ZeroFill,
                "nist" => algorithms::ErasureAlgorithm::Nist80088,
                "dod" => algorithms::ErasureAlgorithm::Dod522022M,
                "gutmann" => algorithms::ErasureAlgorithm::Gutmann35,
                "crypto" => algorithms::ErasureAlgorithm::CryptographicErasure,
                other => {
                    eprintln!("Unknown algorithm: {other}");
                    std::process::exit(1);
                }
            };

            let mut cleaner = browser_cleaner::BrowserCleaner::new();
            cleaner.discover();

            if dry_run {
                let report = cleaner.dry_run();
                println!("DRY RUN — nothing will be deleted\n");
                print_browser_report(&report);
            } else {
                match cleaner.clean(&cats, algo) {
                    Ok(report) => {
                        println!("Clean complete:\n");
                        print_browser_report(&report);
                    }
                    Err(e) => eprintln!("Clean failed: {e}"),
                }
            }
        }
        Commands::SystemClean { dry_run, categories, algorithm } => {
            tracing::info!("System clean (dry_run={dry_run})");

            let cats = system_cleaner::parse_system_categories(&categories);
            if cats.is_empty() {
                eprintln!("No valid categories specified. Use --categories all or --categories thumbnails,logs,...");
                std::process::exit(1);
            }

            let algo = match algorithm.as_str() {
                "zerofill" | "zero" => algorithms::ErasureAlgorithm::ZeroFill,
                "nist" => algorithms::ErasureAlgorithm::Nist80088,
                "dod" => algorithms::ErasureAlgorithm::Dod522022M,
                "gutmann" => algorithms::ErasureAlgorithm::Gutmann35,
                "crypto" => algorithms::ErasureAlgorithm::CryptographicErasure,
                other => {
                    eprintln!("Unknown algorithm: {other}");
                    std::process::exit(1);
                }
            };

            let mut cleaner = system_cleaner::SystemCleaner::new();
            cleaner.discover();

            if dry_run {
                let report = cleaner.dry_run();
                println!("DRY RUN — nothing will be deleted\n");
                print_system_report(&report);
            } else {
                match cleaner.clean(&cats, algo) {
                    Ok(report) => {
                        println!("System clean complete:\n");
                        print_system_report(&report);
                    }
                    Err(e) => eprintln!("System clean failed: {e}"),
                }
            }
        }
    }
}

fn parse_categories(input: &str) -> Vec<browser_cleaner::CleanCategory> {
    use browser_cleaner::CleanCategory;
    input
        .split(',')
        .filter_map(|s| match s.trim().to_lowercase().as_str() {
            "cache" => Some(CleanCategory::Cache),
            "cookies" => Some(CleanCategory::Cookies),
            "history" => Some(CleanCategory::History),
            "sessions" => Some(CleanCategory::Sessions),
            "formdata" => Some(CleanCategory::FormData),
            "passwords" => Some(CleanCategory::Passwords),
            "downloads" => Some(CleanCategory::Downloads),
            "thumbnails" => Some(CleanCategory::Thumbnails),
            "serviceworkers" => Some(CleanCategory::ServiceWorkers),
            "indexeddb" => Some(CleanCategory::IndexedDB),
            "localstorage" => Some(CleanCategory::LocalStorage),
            "websql" => Some(CleanCategory::WebSQL),
            "logs" => Some(CleanCategory::Logs),
            "crashreports" => Some(CleanCategory::CrashReports),
            "extensions" => Some(CleanCategory::Extensions),
            "systemtemp" => Some(CleanCategory::SystemTemp),
            _ => None,
        })
        .collect()
}

fn print_browser_report(report: &browser_cleaner::CleanReport) {
    println!("  Targets found: {}", report.total_targets);
    println!("  Total size:    {}", bytesize::ByteSize(report.total_bytes));
    if !report.by_category.is_empty() {
        println!("\n  By category:");
        for (cat, bytes) in &report.by_category {
            println!("    {cat:<20} {}", bytesize::ByteSize(*bytes));
        }
    }
}

fn print_system_report(report: &system_cleaner::SystemCleanReport) {
    println!("  Targets found: {}", report.total_targets);
    println!("  Total size:    {}", bytesize::ByteSize(report.total_bytes));
    if !report.by_category.is_empty() {
        println!("\n  By category:");
        for (cat, bytes) in &report.by_category {
            println!("    {cat:<20} {}", bytesize::ByteSize(*bytes));
        }
    }
    if !report.entries.is_empty() {
        println!("\n  Details:");
        for entry in &report.entries {
            let root_marker = if entry.requires_root { " [root]" } else { "" };
            println!(
                "    {:<20} {:>10}  {}{}",
                entry.category.to_string(),
                bytesize::ByteSize(entry.size_bytes),
                entry.description,
                root_marker,
            );
        }
    }
}
