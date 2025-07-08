// Import ChaCha20 implementation
use crate::chacha20::block;

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

// Main function defines circuit inputs/outputs - equivalent to circom's component main{public [in, nonce, counter]} = ChaCha20(32, 32);
fn main(
    // Private inputs
    key: [u32; 8],             // Private key
    
    // Public inputs - equivalent to circom's public [in, nonce, counter]
    plaintext: pub [u32; 32],  // Equivalent to circom's 'in'
    nonce: pub [u32; 3],       // Equivalent to circom's 'nonce'
    counter: pub u32,          // Equivalent to circom's 'counter'
    
    // Public outputs
    ciphertext: pub [u32; 32]  // Encryption result
) {
    // Call ChaCha20 encryption function
    let computed_ciphertext = ChaCha20_32(key, nonce, counter, plaintext);
    
    // Constraint: computed ciphertext must equal provided ciphertext
    assert(computed_ciphertext == ciphertext);
}