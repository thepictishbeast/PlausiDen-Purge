//! Secure random data generation for overwrite passes.

use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// Pattern type for overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipePattern {
    /// All zeros (0x00).
    Zeros,
    /// All ones (0xFF).
    Ones,
    /// Alternating 0x55.
    Alt55,
    /// Alternating 0xAA.
    AltAA,
    /// Cryptographically random.
    Random,
}

/// Generate fill pattern data.
pub fn generate_pattern(pattern: WipePattern, size: usize, rng: &mut impl RngCore) -> Vec<u8> {
    match pattern {
        WipePattern::Zeros => vec![0x00; size],
        WipePattern::Ones => vec![0xFF; size],
        WipePattern::Alt55 => vec![0x55; size],
        WipePattern::AltAA => vec![0xAA; size],
        WipePattern::Random => {
            let mut buf = vec![0u8; size];
            rng.fill_bytes(&mut buf);
            buf
        }
    }
}

/// Get a seeded crypto RNG.
pub fn seeded_rng(seed: u64) -> impl RngCore + CryptoRng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// Get an OS-randomness CSPRNG.
pub fn os_rng() -> impl RngCore + CryptoRng {
    ChaCha20Rng::from_entropy()
}

/// DoD 5220.22-M wipe (3 passes: zeros, ones, random).
pub fn dod_3_pass_patterns() -> Vec<WipePattern> {
    vec![WipePattern::Zeros, WipePattern::Ones, WipePattern::Random]
}

/// DoD 5220.22-M ECE wipe (7 passes).
pub fn dod_7_pass_patterns() -> Vec<WipePattern> {
    vec![
        WipePattern::Random,
        WipePattern::Random,
        WipePattern::Random,
        WipePattern::Random,
        WipePattern::Zeros,
        WipePattern::Ones,
        WipePattern::Random,
    ]
}

/// Single-pass random (modern recommendation).
pub fn single_pass_pattern() -> Vec<WipePattern> {
    vec![WipePattern::Random]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_zeros() {
        let mut rng = seeded_rng(42);
        let data = generate_pattern(WipePattern::Zeros, 100, &mut rng);
        assert_eq!(data.len(), 100);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_generate_ones() {
        let mut rng = seeded_rng(42);
        let data = generate_pattern(WipePattern::Ones, 100, &mut rng);
        assert!(data.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_generate_alt() {
        let mut rng = seeded_rng(42);
        let data = generate_pattern(WipePattern::Alt55, 100, &mut rng);
        assert!(data.iter().all(|&b| b == 0x55));
    }

    #[test]
    fn test_generate_random() {
        let mut rng = seeded_rng(42);
        let data = generate_pattern(WipePattern::Random, 1000, &mut rng);
        // Should have variance.
        let unique: std::collections::HashSet<u8> = data.iter().copied().collect();
        assert!(unique.len() > 50, "random data should have many unique bytes");
    }

    #[test]
    fn test_seeded_deterministic() {
        let mut rng1 = seeded_rng(42);
        let mut rng2 = seeded_rng(42);
        let data1 = generate_pattern(WipePattern::Random, 100, &mut rng1);
        let data2 = generate_pattern(WipePattern::Random, 100, &mut rng2);
        assert_eq!(data1, data2);
    }

    #[test]
    fn test_dod_3_pass() {
        let patterns = dod_3_pass_patterns();
        assert_eq!(patterns.len(), 3);
        assert_eq!(patterns[0], WipePattern::Zeros);
        assert_eq!(patterns[1], WipePattern::Ones);
        assert_eq!(patterns[2], WipePattern::Random);
    }

    #[test]
    fn test_dod_7_pass() {
        let patterns = dod_7_pass_patterns();
        assert_eq!(patterns.len(), 7);
    }

    #[test]
    fn test_single_pass() {
        let patterns = single_pass_pattern();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0], WipePattern::Random);
    }
}
