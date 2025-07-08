use super::block;

/// ChaCha20 encryption function for 32 u32 words (128 bytes)
pub fn ChaCha20_32(key: [u32; 8], nonce: [u32; 3], counter: u32, plaintext: [u32; 32]) -> [u32; 32] {
    let mut res = [0; 32];
    
    // Process first 16 words (64 bytes)
    let key_stream1 = block::chacha20_block(key, nonce, counter);
    for t in 0..16 {
        res[t] = plaintext[t] ^ key_stream1[t];
    }
    
    // Process second 16 words (64 bytes)
    let key_stream2 = block::chacha20_block(key, nonce, counter + 1);
    for t in 0..16 {
        res[16 + t] = plaintext[16 + t] ^ key_stream2[t];
    }
    
    res
}

// Re-export core functions
pub use super::block::chacha20_block;
pub use super::block::ChaChaState;
pub use super::block::quarter_round;