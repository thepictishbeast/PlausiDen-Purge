> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept:
> - **No warranty** of any kind, express or implied.
> - **No fitness** for any particular purpose.
> - **No guarantee** of correctness, safety, or freedom from defects.
> - **Zero liability** on the maintainer for any damages — data loss,
>   security compromise, financial loss, or any consequential damages.
>
> The code is under active engineering development per the
> [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> Every commit's default verdict is **STILL BROKEN**. AVP-2 requires
> a minimum of 36 verification passes before a `SHIP-DECISION:`
> annotation may be considered. **No commit in this repository has
> reached `SHIP-DECISION:` status.**

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
