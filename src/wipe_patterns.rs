//! Wipe pattern library — standard shredder patterns for secure deletion.

use serde::{Deserialize, Serialize};

/// A named wipe pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipePattern {
    /// Single pass of zeros.
    Zeros,
    /// Single pass of 0xFF.
    Ones,
    /// Single pass of random data.
    Random,
    /// Specific byte value.
    Fixed(u8),
    /// DoD 5220.22-M: zeros, ones, random.
    DoD3Pass,
    /// DoD 5220.22-M ECE: 7 passes.
    DoD7Pass,
    /// Gutmann 35-pass.
    Gutmann,
    /// Schneier 7-pass.
    Schneier,
    /// VSITR 7-pass (German standard).
    Vsitr,
    /// HMG IS5 Baseline (UK).
    HmgBaseline,
    /// HMG IS5 Enhanced (UK).
    HmgEnhanced,
}

impl WipePattern {
    /// Number of passes this pattern requires.
    pub fn pass_count(&self) -> usize {
        match self {
            WipePattern::Zeros | WipePattern::Ones | WipePattern::Random
                | WipePattern::Fixed(_) | WipePattern::HmgBaseline => 1,
            WipePattern::DoD3Pass => 3,
            WipePattern::HmgEnhanced => 3,
            WipePattern::DoD7Pass => 7,
            WipePattern::Schneier => 7,
            WipePattern::Vsitr => 7,
            WipePattern::Gutmann => 35,
        }
    }

    /// Expand into a sequence of per-pass byte specifications. Random passes
    /// are represented by `PassSpec::Random`.
    pub fn expand(&self) -> Vec<PassSpec> {
        match self {
            WipePattern::Zeros => vec![PassSpec::Byte(0x00)],
            WipePattern::Ones => vec![PassSpec::Byte(0xff)],
            WipePattern::Random => vec![PassSpec::Random],
            WipePattern::Fixed(b) => vec![PassSpec::Byte(*b)],
            WipePattern::DoD3Pass => vec![
                PassSpec::Byte(0x00),
                PassSpec::Byte(0xff),
                PassSpec::Random,
            ],
            WipePattern::DoD7Pass => vec![
                PassSpec::Byte(0x00),
                PassSpec::Byte(0xff),
                PassSpec::Byte(0x00),
                PassSpec::Byte(0xff),
                PassSpec::Byte(0x00),
                PassSpec::Byte(0xff),
                PassSpec::Random,
            ],
            WipePattern::Schneier => vec![
                PassSpec::Byte(0xff),
                PassSpec::Byte(0x00),
                PassSpec::Random,
                PassSpec::Random,
                PassSpec::Random,
                PassSpec::Random,
                PassSpec::Random,
            ],
            WipePattern::Vsitr => vec![
                PassSpec::Byte(0x00),
                PassSpec::Byte(0xff),
                PassSpec::Byte(0x00),
                PassSpec::Byte(0xff),
                PassSpec::Byte(0x00),
                PassSpec::Byte(0xff),
                PassSpec::Byte(0xaa),
            ],
            WipePattern::Gutmann => {
                let mut passes = Vec::with_capacity(35);
                // Passes 1-4: random.
                for _ in 0..4 { passes.push(PassSpec::Random); }
                // Passes 5-31: deterministic patterns.
                let fixed = [
                    0x55, 0xaa, 0x92_49_24u32, 0x49_24_92, 0x24_92_49,
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                    0x92_49_24, 0x49_24_92, 0x24_92_49,
                    0x6d_b6_db, 0xb6_db_6d, 0xdb_6d_b6,
                ];
                for value in fixed {
                    passes.push(PassSpec::Word(value));
                }
                // Passes 32-35: random.
                for _ in 0..4 { passes.push(PassSpec::Random); }
                passes
            }
            WipePattern::HmgBaseline => vec![PassSpec::Byte(0x00)],
            WipePattern::HmgEnhanced => vec![
                PassSpec::Byte(0x00),
                PassSpec::Byte(0xff),
                PassSpec::Random,
            ],
        }
    }

    /// Estimated I/O cost as multiple of file size.
    pub fn io_cost(&self) -> usize {
        self.pass_count()
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            WipePattern::Zeros => "Zero fill",
            WipePattern::Ones => "One fill",
            WipePattern::Random => "Random fill",
            WipePattern::Fixed(_) => "Fixed byte",
            WipePattern::DoD3Pass => "DoD 5220.22-M (3-pass)",
            WipePattern::DoD7Pass => "DoD 5220.22-M ECE (7-pass)",
            WipePattern::Gutmann => "Gutmann (35-pass)",
            WipePattern::Schneier => "Schneier (7-pass)",
            WipePattern::Vsitr => "VSITR (7-pass)",
            WipePattern::HmgBaseline => "HMG IS5 Baseline",
            WipePattern::HmgEnhanced => "HMG IS5 Enhanced (3-pass)",
        }
    }
}

/// A single pass specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PassSpec {
    Byte(u8),
    Word(u32),
    Random,
}

/// Generate the byte block for a deterministic pass.
pub fn fill_block(spec: &PassSpec, block_size: usize) -> Option<Vec<u8>> {
    match spec {
        PassSpec::Byte(b) => Some(vec![*b; block_size]),
        PassSpec::Word(w) => {
            let mut block = Vec::with_capacity(block_size);
            let bytes = [
                ((*w >> 16) & 0xff) as u8,
                ((*w >> 8) & 0xff) as u8,
                (*w & 0xff) as u8,
            ];
            for i in 0..block_size {
                block.push(bytes[i % 3]);
            }
            Some(block)
        }
        PassSpec::Random => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_counts() {
        assert_eq!(WipePattern::Zeros.pass_count(), 1);
        assert_eq!(WipePattern::DoD3Pass.pass_count(), 3);
        assert_eq!(WipePattern::DoD7Pass.pass_count(), 7);
        assert_eq!(WipePattern::Gutmann.pass_count(), 35);
    }

    #[test]
    fn test_expand_zeros() {
        let passes = WipePattern::Zeros.expand();
        assert_eq!(passes, vec![PassSpec::Byte(0x00)]);
    }

    #[test]
    fn test_expand_dod3() {
        let passes = WipePattern::DoD3Pass.expand();
        assert_eq!(passes.len(), 3);
        assert_eq!(passes[0], PassSpec::Byte(0x00));
        assert_eq!(passes[1], PassSpec::Byte(0xff));
        assert_eq!(passes[2], PassSpec::Random);
    }

    #[test]
    fn test_expand_gutmann_35_passes() {
        let passes = WipePattern::Gutmann.expand();
        assert_eq!(passes.len(), 35);
    }

    #[test]
    fn test_expand_schneier() {
        let passes = WipePattern::Schneier.expand();
        assert_eq!(passes.len(), 7);
    }

    #[test]
    fn test_fill_byte() {
        let block = fill_block(&PassSpec::Byte(0xaa), 8).unwrap();
        assert_eq!(block, vec![0xaa; 8]);
    }

    #[test]
    fn test_fill_word() {
        let block = fill_block(&PassSpec::Word(0x92_49_24), 9).unwrap();
        assert_eq!(block.len(), 9);
    }

    #[test]
    fn test_fill_random_returns_none() {
        assert!(fill_block(&PassSpec::Random, 16).is_none());
    }

    #[test]
    fn test_io_cost() {
        assert_eq!(WipePattern::Zeros.io_cost(), 1);
        assert_eq!(WipePattern::Gutmann.io_cost(), 35);
    }

    #[test]
    fn test_label() {
        assert!(WipePattern::Gutmann.label().contains("35"));
    }

    #[test]
    fn test_vsitr_pattern() {
        let passes = WipePattern::Vsitr.expand();
        assert_eq!(passes.len(), 7);
        assert_eq!(passes[6], PassSpec::Byte(0xaa));
    }

    #[test]
    fn test_hmg_enhanced_three_passes() {
        assert_eq!(WipePattern::HmgEnhanced.pass_count(), 3);
    }
}
