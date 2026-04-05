# CLAUDE.md — Instructions for Claude Code

## IMPORTANT: Read this first if context was compacted.

## Project: plausiden-purge
Storage sovereignty engine. App usage tracking, archival, secure data destruction.

## Key Modules:
- scanner.rs: Filesystem scanner finding unused files by atime (IMPLEMENTED)
- destroyer.rs: Multi-pass secure delete with verification (IMPLEMENTED)
- Scaffold: analyzer, archiver, config, tracker

## Integrates with:
- plausiden-engine: Backfill deleted space with synthetic data
- plausiden-inject: Platform-specific deletion targets
- plausiden-shard: Fragment encrypted archives

## CLI subcommands: scan, report, archive, destroy, usage, daemon
