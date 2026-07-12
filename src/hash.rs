//! Process-internal hashing.
//!
//! An FxHash-style word-at-a-time hasher used where hashes never leave the
//! process: the remote-write symbol interning map and the staleness
//! tracker's series identities. The predecessor (byte-at-a-time FNV-1a in
//! the tracker, SipHash in the interning map) processed one byte per
//! multiply; this folds eight. Hash-flooding resistance is irrelevant for
//! data the agent scraped itself, and values may change between binary
//! versions — nothing persists them.

#[derive(Debug, Default)]
pub(crate) struct FxHasher {
    hash: u64,
}

impl FxHasher {
    const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(Self::SEED);
    }
}

impl std::hash::Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        let (chunks, rest) = bytes.as_chunks::<8>();
        for chunk in chunks {
            self.add(u64::from_le_bytes(*chunk));
        }
        if !rest.is_empty() {
            let mut word = [0u8; 8];
            word[..rest.len()].copy_from_slice(rest);
            self.add(u64::from_le_bytes(word));
        }
        // Fold in the length so zero-padded tails stay distinct.
        self.add(bytes.len() as u64);
    }

    fn finish(&self) -> u64 {
        self.hash
    }
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher as _;

    use super::FxHasher;

    fn hash(parts: &[&[u8]]) -> u64 {
        let mut hasher = FxHasher::default();
        for part in parts {
            hasher.write(part);
        }
        hasher.finish()
    }

    #[test]
    fn distinguishes_boundaries_and_padding() {
        // Zero-padded tails must not collide with explicit zero bytes.
        assert_ne!(hash(&[b"a"]), hash(&[b"a\0"]));
        assert_ne!(hash(&[b"a"]), hash(&[b"a\0\0\0\0\0\0\0"]));
        // Same bytes, different chunk alignment.
        assert_ne!(hash(&[b"abcdefgh", b"i"]), hash(&[b"abcdefghi"]));
        // Deterministic.
        assert_eq!(hash(&[b"abcdefghi"]), hash(&[b"abcdefghi"]));
        assert_ne!(hash(&[b""]), hash(&[b"x"]));
    }
}
