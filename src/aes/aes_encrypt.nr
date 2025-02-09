// Copyright (c) 2025 tx-tomcat

use crate::aes::aes_emulation::{EmulatedAesencRowShifting, EmulatedAesencSubstituteBytes};
use crate::utils::helper_functions::{Bits2Num, Num2Bits, XOR};
use super::aes_emulation_tables::emulated_aesenc_enc_table;

/// AES Encryption implementation
pub struct AESEncrypt<let N: u32> {
    pub input: [Field; 128], // Input block as bits
    pub key_schedule: [Field], // Expanded key schedule
    pub output: [Field; 128], // Output block as bits
    rounds: Field, // Number of rounds based on key size
}

impl<let N: u32> AESEncrypt<N> {
    pub fn new(rounds: Field) -> Self {
        Self { input: [0; 128], key_schedule: [], output: [0; 128], rounds }
    }
    pub fn encrypt(&mut self) {
        let mut ks_index = 0;
        let mut state = [[0; 32]; 4];
        let mut temp = [[0; 32]; 4];
        // Initial round key addition
        for i in 0..4 {
            for j in 0..32 {
                let mut xor = XOR::new();
                xor.a = self.input[i * 32 + j];
                xor.b = self.key_schedule[(i + ks_index) * 32 + j];
                state[i][j] = xor.compute();
            }
        }
        ks_index += 4;
        // Main rounds
        for _round in 0..(self.rounds as u32) - 1 {
            for j in 0..4 {
                for k in 0..4 {
                    let mut bits2num = Bits2Num::<8>::new();
                    let mut num2bits = Num2Bits::<32>::new();
                    // Convert state to bytes for s-box lookup
                    let s_tmp = state[(j + k) % 4];
                    for l in 0..8 {
                        bits2num.input[l] = s_tmp[k * 8 + 7 - l];
                    }
                    let bits2num_output = bits2num.compute();
                    // S-box lookup and table transformation
                    num2bits.input = emulated_aesenc_enc_table(k as Field, bits2num_output);
                    let num2bits_output = num2bits.compute();
                    // First column of state
                    if k == 0 {
                        for l in 0..4 {
                            for m in 0..8 {
                                let mut xor = XOR::new();
                                xor.a = num2bits_output[l * 8 + 7 - m];
                                temp[j][l * 8 + m] = xor.compute();
                            }
                        }
                    }
                    // Middle columns
                    else if k < 3 {
                        for l in 0..4 {
                            for m in 0..8 {
                                let mut xor1 = XOR::new();
                                xor1.a = temp[j][l * 8 + m];
                                xor1.b = num2bits_output[l * 8 + 7 - m];
                                let mut xor2 = XOR::new();
                                xor2.a = xor1.compute();
                                temp[j][l * 8 + m] = xor2.compute();
                            }
                        }
                    }
                    // Last column
                    else {
                        for l in 0..4 {
                            for m in 0..8 {
                                let mut xor1 = XOR::new();
                                xor1.a = temp[j][l * 8 + m];
                                xor1.b = num2bits_output[l * 8 + 7 - m];
                                let mut xor2 = XOR::new();
                                xor2.a = xor1.compute();
                                temp[j][l * 8 + m] = xor2.compute();
                            }
                        }
                    }
                }
            }
            // Add round key
            for j in 0..4 {
                for l in 0..32 {
                    let mut xor = XOR::new();
                    xor.a = temp[j][l];
                    xor.b = self.key_schedule[(j + ks_index) * 32 + l];
                    state[j][l] = xor.compute();
                }
            }
            ks_index += 4;
        }
        // Final round
        // Convert state to bytes for final transformations
        let mut s_bytes = [0; 16];
        for i in 0..4 {
            for j in 0..4 {
                let mut bits2num = Bits2Num::<8>::new();
                for k in 0..8 {
                    bits2num.input[k] = state[i][j * 8 + 7 - k];
                }
                s_bytes[i * 4 + j] = bits2num.compute();
            }
        }
        // ShiftRows
        let mut row_shifting = EmulatedAesencRowShifting::new();
        row_shifting.input = s_bytes;
        row_shifting.compute();
        // SubBytes
        let mut sub_bytes = EmulatedAesencSubstituteBytes::new();
        sub_bytes.input = row_shifting.output;
        sub_bytes.compute();
        // Convert back to bits
        for i in 0..4 {
            for j in 0..4 {
                let mut num2bits = Num2Bits::<8>::new();
                num2bits.input = sub_bytes.output[i * 4 + j];
                let num2bits_output = num2bits.compute();
                for k in 0..8 {
                    state[i][j * 8 + k] = num2bits_output[7 - k];
                }
            }
        }
        // Final AddRoundKey
        for i in 0..4 {
            for j in 0..32 {
                let mut xor = XOR::new();
                xor.a = state[i][j];
                xor.b = self.key_schedule[(i + ks_index) * 32 + j];
                self.output[i * 32 + j] = xor.compute();
            }
        }
    }
}
