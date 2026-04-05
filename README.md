# PlausiDen Purge

Storage sovereignty engine. Tracks app and file usage, archives unused data, and securely destroys files beyond NIST 800-88 standards. After deletion, plausiden-engine backfills the space with synthetic data.

## Features

- **Filesystem scanner**: Finds files unused beyond a configurable threshold
- **Secure destroyer**: Multi-pass overwrite (zeros, ones, random) with verification
- **Archive**: Compress + encrypt unused files before removal (planned)
- **Usage tracking**: Monitor which apps and files are actually used (planned)
- **Daemon mode**: Continuous storage monitoring and cleanup (planned)

## CLI

```bash
purge scan /home --unused-days 90     # Find unused files
purge destroy /path/to/file --passes 3 --verify  # Secure delete
purge report                          # Storage usage report
purge daemon                          # Run as background service
```

## License

BSL 1.1 with Apache 2.0 change date of 2030-04-04.
