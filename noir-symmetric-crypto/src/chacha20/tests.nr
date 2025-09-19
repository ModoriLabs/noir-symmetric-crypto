use crate::chacha20::block::{chacha20_block, quarter_round};

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
fn test_chacha20_quarter_round_example() {
    // Example from RFC 7539
    // 2.1.1.  Test Vector for the ChaCha Quarter Round
    let mut a = 0x11111111;
    let mut b = 0x01020304;
    let mut c = 0x9b8d6f43;
    let mut d = 0x01234567;

    let (a, b, c, d) = quarter_round(a, b, c, d);

    // Expected values from the example
    assert_eq(a, 0xea2a92f4);
    assert_eq(b, 0xcb1cf8ce);
    assert_eq(c, 0x4581472e);
    assert_eq(d, 0x5881c4bb);
}

// Reference: https://datatracker.ietf.org/doc/html/rfc7539#section-2.2.1
#[test]
fn test_quarter_round_test_vector() {
    // Test vector from ChaCha specification
    // Testing QUARTERROUND(2,7,8,13) operation

    // Initial state values at positions 2, 7, 8, 13
    let mut a = 0x516461b1; // position 2
    let mut b = 0x2a5f714c; // position 7
    let mut c = 0x53372767; // position 8
    let mut d = 0x3d631689; // position 13

    // Apply quarter round
    let (a, b, c, d) = quarter_round(a, b, c, d);

    // Print the results for debugging
    println("After quarter_round:");
    assert(a == 0xbdb886dc); // position 2
    assert(b == 0xcfacafd2); // position 7
    assert(c == 0xe46bea80); // position 8
    assert(d == 0xccc07c79); // position 13
}

#[test]
fn test_quarter_round_overflow() {
    // Test case where a + b would overflow u32
    let mut a = 0xFFFFFFFF; // Maximum u32 value
    let mut b = 0x00000001; // Adding 1 would overflow
    let mut c = 0x00000000;
    let mut d = 0x00000000;

    let (a, b, c, d) = quarter_round(a, b, c, d);

    // Let's trace through the operations:
    // 1. a = (0xFFFFFFFF + 0x00000001) as u32 = 0x00000000 (wraps to 0)
    // 2. d ^= a; d = 0x00000000 ^ 0x00000000 = 0x00000000
    // 3. left_rotation(d, 16); d = 0x00000000 (rotating 0 is still 0)
    //
    // 4. c = (0x00000000 + 0x00000000) as u32 = 0x00000000
    // 5. b ^= c; b = 0x00000001 ^ 0x00000000 = 0x00000001
    // 6. left_rotation(b, 12); b = 0x00001000
    //
    // 7. a = (0x00000000 + 0x00001000) as u32 = 0x00001000
    // 8. d ^= a; d = 0x00000000 ^ 0x00001000 = 0x00001000
    // 9. left_rotation(d, 8); d = 0x00100000
    //
    // 10. c = (0x00000000 + 0x00100000) as u32 = 0x00100000
    // 11. b ^= c; b = 0x00001000 ^ 0x00100000 = 0x00101000
    // 12. left_rotation(b, 7); b = 0x08080000

    assert(a == 0x00001000);
    assert(b == 0x08080000);
    assert(c == 0x00100000);
    assert(d == 0x00100000);
}

#[test]
fn test_quarter_round_large_values() {
    // Test with large values that will cause multiple overflows
    let mut a = 0xFFFFFFF0;
    let mut b = 0xFFFFFFF0;
    let mut c = 0xFFFFFFF0;
    let mut d = 0xFFFFFFF0;

    quarter_round(a, b, c, d);

    // Verify the function completes without constraint failures
    assert(true);
}

// https://www.rfc-editor.org/rfc/rfc7539.html#section-2.3.2
#[test]
fn test_chacha20_block_function() {
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
        0x1f1e1d1c,
    ];

    let nonce = [0x09000000, 0x4a000000, 0x00000000];

    let counter = 0x00000001;
    let expected_result = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
        0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
        0xe883d0cb, 0x4e3c50a2,
    ];

    let result = chacha20_block(key, nonce, counter);
    println(f"result: {result}");
    for i in 0..16 {
        assert(result[i] == expected_result[i]);
    }
}
