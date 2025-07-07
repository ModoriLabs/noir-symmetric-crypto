// Copyright (c) 2025 tx-tomcat

use crate::aes::aes_emulation_tables::emulated_aesenc_rijndael_sbox;
use crate::utils::helper_functions::{Bits2Num, Num2Bits, XOR};

/// AES Key Expansion
pub struct AES_KEY_EXPAND<let KEY_SIZE_BYTES: u32> {
    pub key: [Field; KEY_SIZE_BYTES * 8], // Input key
}
impl<let KEY_SIZE_BYTES: u32> AES_KEY_EXPAND<KEY_SIZE_BYTES> {
    pub fn new() -> Self {
        Self { key: [0; KEY_SIZE_BYTES * 8] }
    }

    pub fn expand(&mut self) -> [Field; 1920] {
        let BITS_PER_WORD: u32 = 8;
        // Round constants
        let rcon: [[Field; 8]; 10] = [
            [0, 0, 0, 0, 0, 0, 0, 1], // 0x01
            [0, 0, 0, 0, 0, 0, 1, 0], // 0x02
            [0, 0, 0, 0, 0, 1, 0, 0], // 0x04
            [0, 0, 0, 0, 1, 0, 0, 0], // 0x08
            [0, 0, 0, 1, 0, 0, 0, 0], // 0x10
            [0, 0, 1, 0, 0, 0, 0, 0], // 0x20
            [0, 1, 0, 0, 0, 0, 0, 0], // 0x40
            [1, 0, 0, 0, 0, 0, 0, 0], // 0x80
            [0, 0, 0, 1, 1, 0, 1, 1], // 0x1b
            [0, 0, 1, 1, 0, 1, 1, 0], // 0x36
        ];

        // Calculate parameters
        let nr = if KEY_SIZE_BYTES == 32 {
            14
        } // AES-256
        else if KEY_SIZE_BYTES == 24 {
            12
        } // AES-192
        else {
            10
        }; // AES-128
        let nb = 4;
        // e.g. 128 -> 16 key bytes -> 4 words
        let nk = KEY_SIZE_BYTES / 4;
        let ks_words = nb * (nr + 1);
        let mut output: [Field; 1920] = [0; 1920]; // max for AES-256: 60 words * 32 bits = 1920 bits
        // Initialize working arrays
        let mut w: [[[Field; 8]; 4]; 60] = [[[0; 8]; 4]; 60]; // 60 is max size for AES-256

        // First Nk words are the key
        for i in 0..nk {
            for j in 0..4 {
                for k in 0..BITS_PER_WORD {
                    w[i][j][k] = self.key[((i * 4) + j) * BITS_PER_WORD + k];
                }
            }
        }

        // Expand key into remaining schedule
        for i in nk..ks_words {
            let mut temp: [[Field; 8]; 4] = [[0; 8]; 4];
            for j in 0..4 {
                temp[j] = w[i - 1][j];
            }

            if i % nk == 0 {
                // Rotate word
                let tmp_word = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = tmp_word;
            }
            if KEY_SIZE_BYTES == 32 {}
            // (i % nk == 0) => ?
            // ((KEY_SIZE_BYTES == 32) & (i % nk == 4)) => (AES-256 only)
            if (i % nk == 0) | ((KEY_SIZE_BYTES == 32) & (i % nk == 4)) {
                for j in 0..4 {
                    // S-box substitution
                    let mut bits2num = Bits2Num::<8>::new();
                    for k in 0..BITS_PER_WORD {
                        bits2num.input[k] = temp[j][BITS_PER_WORD - k - 1];
                    }
                    let s_box_in = bits2num.compute();

                    let mut num2bits = Num2Bits::<8>::new();
                    num2bits.input = emulated_aesenc_rijndael_sbox(s_box_in);
                    let num2bits_output = num2bits.compute();

                    for k in 0..BITS_PER_WORD {
                        temp[j][k] = num2bits_output[BITS_PER_WORD - k - 1];
                    }
                }
            }

            if i % nk == 0 {
                // XOR first word with round constant
                for k in 0..BITS_PER_WORD {
                    let mut xor = XOR::new();
                    xor.a = temp[0][k];
                    // @q why i / nk - 1?
                    xor.b = rcon[i / nk - 1][k];
                    temp[0][k] = xor.compute();
                }
            }

            // w[i] = temp XOR w[i-Nk]
            for j in 0..4 {
                for k in 0..BITS_PER_WORD {
                    let mut xor = XOR::new();
                    xor.a = temp[j][k];
                    xor.b = w[i - nk][j][k];
                    w[i][j][k] = xor.compute();
                }
            }
        }

        // Convert expanded key to output format
        for i in 0..ks_words {
            for j in 0..4 {
                for k in 0..BITS_PER_WORD {
                    output[(i * 4 + j) * BITS_PER_WORD + k] = w[i][j][k];
                }
            }
        }
        output
    }
}
