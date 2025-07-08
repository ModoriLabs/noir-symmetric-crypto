pub mod block;
pub mod lib;
pub mod main;
pub mod tests;

// Re-export main functionality
pub use block::{chacha20_block, ChaChaState, quarter_round};
pub use lib::ChaCha20_32;
