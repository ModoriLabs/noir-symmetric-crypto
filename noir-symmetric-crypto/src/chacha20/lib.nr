use super::block;

pub fn ChaCha20<let N: u32>(
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    plaintext: [u32; N]
) -> [u32; N] {
    let mut res = [0; N];
    let num_blocks = (N + 15) / 16; // Ceiling division

    for block_idx in 0..num_blocks {
        let current_counter = counter + block_idx;
        let key_stream = block::chacha20_block(key, nonce, current_counter);

        // Process up to 16 words in this block
        let start_idx = block_idx * 16;
        let end_idx = if start_idx + 16 <= N { start_idx + 16 } else { N };

        for i in start_idx..end_idx {
            let key_stream_idx = i - start_idx;
            res[i] = plaintext[i] ^ key_stream[key_stream_idx];
        }
    }

    res
}

pub use super::block::chacha20_block;
pub use super::block::ChaChaState;
pub use super::block::quarter_round;
