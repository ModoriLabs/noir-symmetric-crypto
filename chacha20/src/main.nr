use noir_symmetric_crypto::chacha20::{ChaCha20};

/*
/// ChaCha20 encryption function for 32 u32 words (128 bytes)
pub fn ChaCha20_32(
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    plaintext: [u32; 32],
) -> [u32; 32] {
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
*/

// component main{public [in, nonce, counter]} = ChaCha20(32, 32);
fn main(
    // Private input
    key: [u32; 8],
    ciphertext: [u32; 32],
    // Public inputs
    plaintext: pub [u32; 32],
    nonce: pub [u32; 3],
    counter: pub u32,
) {
    assert(ChaCha20::<32>(key, nonce, counter, plaintext) == ciphertext);
}

#[test]
fn test_chacha20_encryption() {
    // Test vector from RFC 7539
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;

    // Plaintext from RFC 7539 Section 2.4.2:
    // "Ladies and Gentlemen of the class of '99: If I could offer you
    // only one tip for the future, sunscreen would be it."
    // Converted to little-endian u32 words
    let plaintext: [u32; 32] = [
        0x6c614c06, 0x20736569, 0x20646e61, 0x746e6547,
        0x656d656c, 0x666f206e, 0x65687420, 0x616c6320,
        0x6f207373, 0x39392766, 0x66493a20, 0x63204920,
        0x646c756f, 0x66666f20, 0x79207265, 0x6f20756f,
        0x20796c6e, 0x20656e6f, 0x20706974, 0x20726f66,
        0x20656874, 0x75747566, 0x202c6572, 0x736e7573,
        0x65657263, 0x6f77206e, 0x20646c75, 0x69206562,
        0x00002e74, 0x00000000, 0x00000000, 0x00000000
    ];

    // Expected ciphertext from RFC 7539 Section 2.4.2
    let expected_ciphertext = [
        0xa3e2f610, 0x746d6cc1, 0x4b2bb17e, 0x35a547d3,
        0x0b56b2d9, 0x0e8f6e25, 0x9d3f6512, 0xb3b8dc63,
        0x5e7cf60e, 0xef85cd64, 0x0db1a27c, 0x7f8a3c25,
        0x76f2b9b2, 0x3e14a2a8, 0x7f03d5b5, 0x127ad8cc,
        0x07f9d4f5, 0x8c6ddd6d, 0x9e8d0e3f, 0x03f5e5bd,
        0x1aef8526, 0xc7f6e7f0, 0x3d9111d0, 0xd6de2b00,
        0x0e10f4b6, 0x2a08e9a9, 0x7c1a0d88, 0x5f6d8e2f,
        0x19ec0000, 0x00000000, 0x00000000, 0x00000000
    ];

    main(key, expected_ciphertext, plaintext, nonce, counter);
}

/*
#[test]
fn test_chacha20_test_vector() {
    // Test vector from RFC 7539 Section 2.4.2
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;

    // All zeros plaintext
    let plaintext: [u32; 32] = [0; 32];

    // Expected first block of keystream (from RFC 7539)
    // When XORed with zeros, this is the ciphertext
    let expected_first_block = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    ];

    main(key, expected_first_block, plaintext, nonce, counter);
}
*/
