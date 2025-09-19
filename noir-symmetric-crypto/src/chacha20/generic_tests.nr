// Tests for generic ChaCha20 implementation
use super::lib::ChaCha20;

#[test]
fn test_chacha20_generic_16() {
    // Test with 16 words (64 bytes) - exactly one block
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;
    let plaintext = [
        0x4c616469, 0x65732061, 0x6e642047, 0x656e746c, 0x656d656e, 0x206f6620, 0x74686520,
        0x636c6173, 0x73206f66, 0x20273939, 0x3a204966, 0x20492063, 0x6f756c64, 0x20736179,
        0x20736f6d, 0x65746869,
    ];

    let ciphertext = ChaCha20::<16>(key, nonce, counter, plaintext);

    // Verify that we get some output (not all zeros)
    let mut all_zero = true;
    for i in 0..16 {
        if ciphertext[i] != 0 {
            all_zero = false;
        }
    }
    assert(!all_zero);
}

#[test]
fn test_chacha20_generic_32() {
    // Test with 32 words (128 bytes) - exactly two blocks
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;
    let plaintext = [
        0x4c616469, 0x65732061, 0x6e642047, 0x656e746c, 0x656d656e, 0x206f6620, 0x74686520,
        0x636c6173, 0x73206f66, 0x20273939, 0x3a204966, 0x20492063, 0x6f756c64, 0x20736179,
        0x20736f6d, 0x65746869, 0x6e672c20, 0x49207769, 0x73682049, 0x20636f75, 0x6c642073,
        0x61792069, 0x74206265, 0x74746572, 0x2e205468, 0x61742773, 0x20616c6c, 0x2c206c61,
        0x64696573, 0x20616e64, 0x2067656e, 0x746c656d,
    ];

    let ciphertext = ChaCha20::<32>(key, nonce, counter, plaintext);

    // Verify that we get some output (not all zeros)
    let mut all_zero = true;
    for i in 0..32 {
        if ciphertext[i] != 0 {
            all_zero = false;
        }
    }
    assert(!all_zero);
}

#[test]
fn test_chacha20_generic_48() {
    // Test with 48 words (192 bytes) - three blocks
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;

    // Create 48 words of test data
    let mut plaintext = [0; 48];
    for i in 0..48 {
        plaintext[i] = 0x12345678 + (i as u32);
    }

    let ciphertext = ChaCha20::<48>(key, nonce, counter, plaintext);

    // Verify that we get some output (not all zeros)
    let mut all_zero = true;
    for i in 0..48 {
        if ciphertext[i] != 0 {
            all_zero = false;
        }
    }
    assert(!all_zero);
}

#[test]
fn test_chacha20_generic_non_multiple_of_16() {
    // Test with 20 words (80 bytes) - not a multiple of 16
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;

    let mut plaintext = [0; 20];
    for i in 0..20 {
        plaintext[i] = 0xabcdef00 + (i as u32);
    }

    let ciphertext = ChaCha20::<20>(key, nonce, counter, plaintext);

    // Verify that we get some output (not all zeros)
    let mut all_zero = true;
    for i in 0..20 {
        if ciphertext[i] != 0 {
            all_zero = false;
        }
    }
    assert(!all_zero);
}

#[test]
fn test_chacha20_generic_deterministic() {
    // Test that the same input produces the same output
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;
    let plaintext = [
        0x4c616469, 0x65732061, 0x6e642047, 0x656e746c, 0x656d656e, 0x206f6620, 0x74686520,
        0x636c6173, 0x73206f66, 0x20273939, 0x3a204966, 0x20492063, 0x6f756c64, 0x20736179,
        0x20736f6d, 0x65746869,
    ];

    let ciphertext1 = ChaCha20::<16>(key, nonce, counter, plaintext);
    let ciphertext2 = ChaCha20::<16>(key, nonce, counter, plaintext);

    // Should be identical
    for i in 0..16 {
        assert(ciphertext1[i] == ciphertext2[i]);
    }
}

#[test]
fn test_chacha20_generic_counter_increment() {
    // Test that different counters produce different outputs
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let plaintext = [
        0x4c616469, 0x65732061, 0x6e642047, 0x656e746c, 0x656d656e, 0x206f6620, 0x74686520,
        0x636c6173, 0x73206f66, 0x20273939, 0x3a204966, 0x20492063, 0x6f756c64, 0x20736179,
        0x20736f6d, 0x65746869,
    ];

    let ciphertext1 = ChaCha20::<16>(key, nonce, 1, plaintext);
    let ciphertext2 = ChaCha20::<16>(key, nonce, 2, plaintext);

    // Should be different
    let mut different = false;
    for i in 0..16 {
        if ciphertext1[i] != ciphertext2[i] {
            different = true;
        }
    }
    assert(different);
}
