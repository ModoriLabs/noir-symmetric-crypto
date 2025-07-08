// Copyright (c) 2025 tx-tomcat

use crate::aes::aes_encrypt::AESEncrypt;
use crate::utils::helper_functions::{Bits2Num, Num2Bits, XOR};
use super::aes_key_expansion::AES_KEY_EXPAND;

/// AES CTR mode implementation
pub struct AES_CTR<let n_bits: u32, let KEY_SIZE_BYTES: u32> {
    pub input: [Field; n_bits], // Input data
    pub counter: [Field; 128], // Counter block
    pub key: [Field; KEY_SIZE_BYTES * 8], // AES key
    pub output: [Field; n_bits], // Output data
}

impl<let n_bits: u32, let KEY_SIZE_BYTES: u32> AES_CTR<n_bits, KEY_SIZE_BYTES> {
    pub fn new() -> Self {
        Self {
            input: [0; n_bits],
            counter: [0; 128],
            key: [0; KEY_SIZE_BYTES * 8],
            output: [0; n_bits],
        }
    }

    pub fn encrypt(&mut self) {
        // Determine number of rounds based on key size
        let aes_rounds = if KEY_SIZE_BYTES == 32 {
            14
        } // AES-256
        else if KEY_SIZE_BYTES == 24 {
            12
        } // AES-192
        else {
            10
        }; // AES-128

        let msg_len = n_bits / 8;

        // Key expansion
        let mut ke = AES_KEY_EXPAND::<KEY_SIZE_BYTES>::new();
        ke.key = self.key;
        let expanded_key = ke.expand();

        // Counter block
        let mut ctr_t = self.counter;

        // Process each block
        for i in 0..(msg_len / 16) {
            // Encrypt counter
            let mut aes_encrypt = AESEncrypt::<128>::new(aes_rounds);
            aes_encrypt.input = ctr_t;
            aes_encrypt.key_schedule = expanded_key;
            aes_encrypt.encrypt();
            let ek = aes_encrypt.output;

            // XOR ciphertext with input
            for j in 0..4 {
                for k in 0..4 {
                    for l in 0..8 {
                        let mut xor = XOR::new();
                        xor.a = self.input[i * 128 + j * 32 + k * 8 + l];
                        xor.b = ek[j * 32 + k * 8 + l];
                        self.output[i * 128 + j * 32 + k * 8 + l] = xor.compute();
                    }
                }
            }

            // Increment counter
            let mut bits2num = Bits2Num::<32>::new();
            let mut num2bits = Num2Bits::<32>::new();

            // Get last 4 bytes of counter
            for j in 0..4 {
                for k in 0..8 {
                    bits2num.input[j * 8 + k] = ctr_t[(15 - j) * 8 + 7 - k];
                }
            }

            // Increment and convert back to bits
            num2bits.input = bits2num.compute() + 1;
            let num2bits_output = num2bits.compute();

            // Update counter
            for j in 0..4 {
                for k in 0..8 {
                    ctr_t[(15 - j) * 8 + k] = num2bits_output[j * 8 + 7 - k];
                }
            }
        }
    }
}

#[test]
fn test_aes_ctr() {
    // Test vectors
    let key_size = 16; // AES-128
    let mut ctr = AES_CTR::<128, 16>::new();

    // Initialize with test vectors
    for i in 0..128 {
        ctr.input[i] = 0;
        ctr.counter[i] = 0;
    }
    for i in 0..key_size * 8 {
        ctr.key[i] = 0;
    }

    // Encrypt
    ctr.encrypt();

    // Test zero input with zero key should give expected output
    // Add specific test vector assertions here
}
