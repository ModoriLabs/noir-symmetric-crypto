// Noir Symmetric Crypto Library
// This library provides implementations of symmetric cryptographic algorithms

pub mod aes;
pub mod chacha20;
pub mod utils;

// Re-export main functionality for easy access
pub use chacha20::{ChaCha20, chacha20_block, ChaChaState, quarter_round};
pub use utils::helper_functions::{XOR, Bits2Num, Num2Bits};
