pub mod block;
pub mod lib;
mod tests;
mod generic_tests;

// Re-export main functionality
pub use block::{chacha20_block, ChaChaState, quarter_round};
pub use lib::ChaCha20;
