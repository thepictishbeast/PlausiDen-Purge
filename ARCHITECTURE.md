# Architecture — PlausiDen Purge

## System Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    User Interface                        │
│           CLI / GUI (Tauri, future) / Daemon             │
└──────────────────────┬──────────────────────────────────┘
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
         ┌────────┐ ┌──────┐ ┌──────────┐
         │Scanner │ │Purge │ │ Tracker  │
         │        │ │Engine│ │          │
         └───┬────┘ └──┬───┘ └────┬─────┘
             │         │          │
             ▼         ▼          ▼
       ┌──────────────────────────────────┐
       │         Algorithm Layer          │
       │                                  │
       │  ┌──────────┐ ┌──────────────┐  │
       │  │ Overwrite │ │ Crypto       │  │
       │  │ Patterns  │ │ Erasure      │  │
       │  │           │ │              │  │
       │  │ ZeroFill  │ │ Encrypt with │  │
       │  │ NIST 800  │ │ random key,  │  │
       │  │ DoD 5220  │ │ discard key, │  │
       │  │ Gutmann35 │ │ zero result  │  │
       │  └──────────┘ └──────────────┘  │
       │                                  │
       │  ┌──────────┐ ┌──────────────┐  │
       │  │ Hardware  │ │ Memory       │  │
       │  │ Commands  │ │ Scrub        │  │
       │  │           │ │              │  │
       │  │ TRIM/     │ │ Overwrite    │  │
       │  │ UNMAP     │ │ RAM pages    │  │
       │  │ NVMe      │ │ with random  │  │
       │  │ Secure    │ │ data, then   │  │
       │  │ Erase     │ │ zeroize      │  │
       │  └──────────┘ └──────────────┘  │
       └──────────────────┬───────────────┘
                          │
                          ▼
       ┌──────────────────────────────────┐
       │      plausiden-engine            │
       │  (backfill deleted space with    │
       │   synthetic data — optional)     │
       └──────────────────────────────────┘
```

## Erasure Algorithms — Technical Details

### Why Multiple Algorithms?

Different storage media require different destruction strategies:

| Storage Type | Problem | Solution |
|-------------|---------|----------|
| HDD (magnetic) | Residual magnetic patterns after overwrite | Multi-pass with specific bit patterns (Gutmann) |
| SSD (NAND flash) | Wear-leveling preserves old blocks in spare area | Cryptographic erasure + TRIM |
| NVMe | Internal controller manages block mapping | NVMe Secure Erase command |
| RAM | Cold boot attack reads data after power off | Overwrite with random + zeroize |

### Algorithm Details

#### ZeroFill (1 pass)
- Overwrites entire file with `0x00`
- Fastest. Sufficient for non-sensitive data.
- Defeated by: magnetic force microscopy on HDDs, wear-leveling on SSDs.

#### NIST 800-88 (3 passes)
- Pass 1: `0x00` (zeros)
- Pass 2: `0xFF` (ones)
- Pass 3: cryptographically random data
- Meets NIST Special Publication 800-88 Rev. 1 "Clear" standard.
- Sufficient for most use cases on HDDs.

#### DoD 5220.22-M (3 passes + verification)
- Pass 1: `0x00` → verify every byte is `0x00`
- Pass 2: `0xFF` → verify every byte is `0xFF`
- Pass 3: random data → verify file was written
- U.S. Department of Defense standard.
- The verification passes double the I/O but catch write failures.

#### Gutmann 35-Pass
- Passes 1-4: random data
- Passes 5-31: 27 specific bit patterns targeting MFM and RLL magnetic encoding
  - Designed to defeat magnetic force microscopy (MFM) by saturating all possible magnetic states
  - Patterns include: `0x55`, `0xAA`, `0x92`, `0x49`, `0x24`, etc.
  - Each pattern targets a specific bit alignment in the magnetic domain
- Passes 32-35: random data
- Originally designed in 1996 for older drive technology.
- Modern HDDs with perpendicular recording may not benefit from all 35 patterns, but the approach remains the gold standard for paranoid erasure.

#### Cryptographic Erasure
- Generate a random 256-bit ChaCha20 key
- Encrypt the entire file in-place using BLAKE3-derived keystream
- Zeroize the key material from memory
- Overwrite the ciphertext with zeros (defense in depth)
- **Why this is superior for SSDs**: Wear-leveling may preserve copies of old blocks in the SSD's spare area. With traditional overwrite, those old blocks contain the original plaintext. With cryptographic erasure, even if old blocks survive, they contain only ciphertext — which is computationally indistinguishable from random data without the (destroyed) key.

#### RAM Scrubbing
- Allocates large memory blocks
- Fills with cryptographically random data from `OsRng`
- Uses `std::hint::black_box` to prevent compiler optimization
- Zeroizes each block after writing
- Defeats cold boot attacks where RAM contents persist after power-off
- Configurable size (default: available RAM minus 256 MB safety margin)

### Storage Type Detection

On Linux, Purge reads `/sys/block/<device>/queue/rotational`:
- `1` = HDD (rotational) → recommend multi-pass overwrite
- `0` = SSD/NVMe → recommend cryptographic erasure

The detection falls back to NIST 800-88 if storage type cannot be determined.

### Post-Deletion Backfill (Planned)

After secure deletion, Purge can optionally call `plausiden-engine` to generate synthetic files that fill the freed space. This:
- Prevents analysis of "why was this space recently deleted?"
- Creates plausible deniability about what was there before
- Generates files that match the user's profile (documents, photos, downloads)

### Adversary Model

**What Purge defends against:**
- Standard file recovery tools (testdisk, photorec, foremost)
- Forensic imaging and analysis (Autopsy, EnCase, FTK)
- Deleted file metadata in filesystem journals
- Cold boot attacks (RAM scrubbing)
- Wear-leveling recovery on SSDs (cryptographic erasure)

**What Purge does NOT defend against:**
- Hardware-level NAND flash readout (chip-off attack on SSD)
- Journaling filesystem recovery of metadata (need to wipe journal too)
- Remote backups of the data (cloud sync, network drives)
- Data already exfiltrated before deletion

### Future: Hardware-Level Integration

Planned integration with low-level storage APIs:
- **Zig hardware layer**: Direct NVMe controller commands via `ioctl`
- **TRIM/UNMAP**: Inform SSD controller that blocks are no longer in use
- **ATA Secure Erase**: Full drive wipe via ATA command set
- **NVMe Format**: Controller-level format with cryptographic erase option
- **hdparm**: Interface with ATA security features
- **Flash Translation Layer bypass**: Direct NAND access (requires specialized hardware)

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | Implemented | Full algorithm support, storage detection |
| macOS | Planned | APFS secure erase, diskutil |
| Windows | Planned | NTFS, cipher /w, SDelete integration |
| Android | Planned | Scoped storage, no direct disk access without root |
| iOS | Planned | Extremely limited — sandbox restrictions |
