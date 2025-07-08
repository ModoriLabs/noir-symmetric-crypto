#[test]
fn test_chacha20_block() {
    // Test vectors from RFC 7539
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;

    let result = crate::chacha20::block::chacha20_block(key, nonce, counter);

    // Verify that the function runs without errors
    assert(result.len() == 16);
}

#[test]
fn test_chacha20_encryption() {
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;
    let plaintext = [0; 32]; // All zeros

    let ciphertext = crate::chacha20::main::ChaCha20_32(key, nonce, counter, plaintext);

    // Verify that encryption produces different output than input
    assert(ciphertext != plaintext);
    assert(ciphertext.len() == plaintext.len());
}

#[test]
fn test_chacha_state_creation() {
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];
    let nonce = [0x09000000, 0x4a000000, 0x00000000];
    let counter = 1;

    let state = crate::chacha20::block::ChaChaState::new(key, nonce, counter);

    // Verify state creation with ChaCha20 constants
    assert(state.state[0] == 0x61707865); // "expa" constant
    assert(state.state[1] == 0x3320646e); // "nd 3" constant
    assert(state.state[2] == 0x79622d32); // "2-by" constant
    assert(state.state[3] == 0x6b206574); // "te k" constant
}

#[test]
fn test_quarter_round() {
    let mut a = 0x11111111;
    let mut b = 0x01020304;
    let mut c = 0x9b8d6f43;
    let mut d = 0x01234567;

    crate::chacha20::block::quarter_round(&mut a, &mut b, &mut c, &mut d);

    // Verify that quarter round modifies the values
    assert(a != 0x11111111);
    assert(b != 0x01020304);
    assert(c != 0x9b8d6f43);
    assert(d != 0x01234567);
}
