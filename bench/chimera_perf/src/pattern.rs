#[derive(Debug, Clone)]
pub struct PatternStream {
    state: u64,
    word: [u8; 8],
    word_offset: usize,
}

impl PatternStream {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed,
            word: [0; 8],
            word_offset: 8,
        }
    }

    pub fn fill(&mut self, output: &mut [u8]) {
        let mut written = 0;
        while written < output.len() {
            if self.word_offset == self.word.len() {
                self.word = self.next_word().to_le_bytes();
                self.word_offset = 0;
            }
            let available = self.word.len() - self.word_offset;
            let requested = output.len() - written;
            let count = available.min(requested);
            output[written..written + count].copy_from_slice(
                &self.word[self.word_offset..self.word_offset + count],
            );
            written += count;
            self.word_offset += count;
        }
    }

    pub fn matches(&mut self, input: &[u8], scratch: &mut [u8]) -> bool {
        debug_assert!(scratch.len() >= input.len());
        let expected = &mut scratch[..input.len()];
        self.fill(expected);
        expected == input
    }

    fn next_word(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_independent_of_chunk_boundaries() {
        let mut one_shot = PatternStream::new(42);
        let mut expected = vec![0_u8; 65_537];
        one_shot.fill(&mut expected);

        let mut chunked = PatternStream::new(42);
        let mut actual = Vec::with_capacity(expected.len());
        for size in [1, 3, 7, 8, 31, 4096, 16_384, 45_567] {
            if actual.len() == expected.len() {
                break;
            }
            let count = size.min(expected.len() - actual.len());
            let start = actual.len();
            actual.resize(start + count, 0);
            chunked.fill(&mut actual[start..]);
        }
        if actual.len() < expected.len() {
            let start = actual.len();
            actual.resize(expected.len(), 0);
            chunked.fill(&mut actual[start..]);
        }

        assert_eq!(actual, expected);
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut left = [0_u8; 64];
        let mut right = [0_u8; 64];
        PatternStream::new(1).fill(&mut left);
        PatternStream::new(2).fill(&mut right);
        assert_ne!(left, right);
    }
}
