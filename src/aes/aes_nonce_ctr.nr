// Copyright (c) 2025 tx-tomcat

use crate::aes::aes_ctr::AES_CTR;

/// AES-CTR with nonce implementation
/// N: Size of message in bytes
/// KEY_SIZE_BYTES: Size of the key in bytes (16, 24, or 32 for AES-128, AES-192, AES-256)
pub struct AES_NONCE_CTR<let N: u32, let KEY_SIZE_BYTES: u32> {
    // Private inputs
    pub key: [Field; KEY_SIZE_BYTES * 8], // Key input
    pub nonce: [Field; 12 * 8], // 12-byte nonce
    pub counter: [Field; 4 * 8], // 4-byte counter
    // Public input
    pub input: [Field; N * 8], // Input data
    pub output: [Field; N * 8], // Output data
}

impl<let N: u32, let KEY_SIZE_BYTES: u32> AES_NONCE_CTR<N, KEY_SIZE_BYTES> {
    pub fn new() -> Self {
        Self {
            key: [0; KEY_SIZE_BYTES * 8],
            nonce: [0; 12 * 8],
            counter: [0; 4 * 8],
            input: [0; N * 8],
            output: [0; N * 8],
        }
    }

    pub fn decrypt(&mut self) {
        // Create CTR cipher instance
        let mut cipher = AES_CTR::<N * 8, KEY_SIZE_BYTES>::new();

        // Set input and key
        cipher.input = self.input;
        cipher.key = self.key;

        // Set counter by combining nonce and counter
        // First copy nonce (12 bytes)
        for i in 0..(12 * 8) {
            cipher.counter[i] = self.nonce[i];
        }
        // Then copy counter (4 bytes)
        for i in 0..(4 * 8) {
            cipher.counter[i + 12 * 8] = self.counter[i];
        }

        // Process data
        cipher.encrypt();

        // Get output
        self.output = cipher.output;
    }
}
