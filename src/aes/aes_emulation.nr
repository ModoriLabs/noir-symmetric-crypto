// Copyright (c) 2025 tx-tomcat

use crate::aes::aes_emulation_tables::emulated_aesenc_rijndael_sbox;

/// Row shifting operation for AES
pub struct EmulatedAesencRowShifting {
    pub input: [Field; 16], // Input state array
    pub output: [Field; 16], // Output state array after row shifting
}

impl EmulatedAesencRowShifting {
    pub fn new() -> Self {
        Self { input: [0; 16], output: [0; 16] }
    }

    pub fn compute(&mut self) {
        // Byte order for ShiftRows transformation
        let byte_order = [
            0, 5, 10, 15, // row 0 (unchanged)
            4, 9, 14, 3, // row 1 (shifted by 1)
            8, 13, 2, 7, // row 2 (shifted by 2)
            12, 1, 6, 11, // row 3 (shifted by 3)
        ];

        // Apply byte permutation
        for i in 0..16 {
            self.output[i] = self.input[byte_order[i]];
        }
    }
}

/// Byte substitution operation using S-box
pub struct EmulatedAesencSubstituteBytes {
    pub input: [Field; 16], // Input state array
    pub output: [Field; 16], // Output state array after S-box substitution
}

impl EmulatedAesencSubstituteBytes {
    pub fn new() -> Self {
        Self { input: [0; 16], output: [0; 16] }
    }

    pub fn compute(&mut self) {
        // Apply S-box to each byte
        for i in 0..16 {
            self.output[i] = emulated_aesenc_rijndael_sbox(self.input[i]);
        }
    }
}
/// Helper function for state array manipulation
pub fn state_to_array(state: [[Field; 4]; 4]) -> [Field; 16] {
    let mut arr = [0; 16];
    for i in 0..4 {
        for j in 0..4 {
            arr[i * 4 + j] = state[i][j];
        }
    }
    arr
}
