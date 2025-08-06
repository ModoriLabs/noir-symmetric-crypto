use dep::noir_symmetric_crypto::aes::aes_ctr::AES_CTR;

#[test]
fn test_aes_128_ctr_nist_vector_1() {
    // NIST AES-128-CTR Test Vector
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // Counter: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    // Expected Ciphertext: 874d6191b620e3261bef6864990db6ce

    let mut aes_ctr = AES_CTR::<128, 16>::new();

    // Set 128-bit key
    let key_bytes: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ];

    // Convert key to bits (MSB first)
    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr.key[index] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set counter/IV
    let counter_bytes: [u8; 16] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    ];

    // Convert counter to bits (MSB first)
    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr.counter[index] = ((counter_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set plaintext
    let plaintext_bytes: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    ];

    // Convert plaintext to bits (MSB first)
    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr.input[index] = ((plaintext_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Perform encryption
    aes_ctr.encrypt();

    // Expected ciphertext
    let expected_ciphertext_bytes: [u8; 16] = [
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
    ];

    // Verify output
    for i in 0..16 {
        for j in 0..8 {
            let expected_bit = ((expected_ciphertext_bytes[i] >> (7 - j)) & 1) as Field;
            let index = (i as u32) * 8 + (j as u32);
            assert(aes_ctr.output[index] == expected_bit);
        }
    }
}

#[test]
fn test_aes_128_ctr_zero_plaintext() {
    // Test with zero plaintext to verify keystream generation
    let mut aes_ctr = AES_CTR::<128, 16>::new();

    // Set test key
    let key_bytes: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ];

    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr.key[index] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set test counter
    let counter_bytes: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ];

    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr.counter[index] = ((counter_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set zero plaintext
    for i in 0..128 {
        aes_ctr.input[i] = 0;
    }

    // Perform encryption
    aes_ctr.encrypt();

    // Output should be the keystream (encrypted counter)
    // Verify that output is not all zeros
    let mut non_zero_count = 0;
    for i in 0..128 {
        if aes_ctr.output[i] != 0 {
            non_zero_count += 1;
        }
    }

    // At least half the bits should be non-zero (statistical property)
    assert(non_zero_count > 32);
}

#[test]
fn test_aes_128_ctr_decryption() {
    // CTR mode is symmetric - encryption and decryption are the same operation
    // Test that encrypting twice gives back the original plaintext

    let mut aes_ctr1 = AES_CTR::<128, 16>::new();
    let mut aes_ctr2 = AES_CTR::<128, 16>::new();

    // Set test key
    let key_bytes: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    ];

    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr1.key[index] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
            aes_ctr2.key[index] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set test counter
    let counter_bytes: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
    ];

    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr1.counter[index] = ((counter_bytes[i] >> (7 - j)) & 1) as Field;
            aes_ctr2.counter[index] = ((counter_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set test plaintext
    let plaintext_bytes: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    ];

    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr1.input[index] = ((plaintext_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // First encryption
    aes_ctr1.encrypt();

    // Copy ciphertext to second instance input
    for i in 0..128 {
        aes_ctr2.input[i] = aes_ctr1.output[i];
    }

    // Second encryption (which acts as decryption)
    aes_ctr2.encrypt();

    // Verify we get back the original plaintext
    for i in 0..16 {
        for j in 0..8 {
            let original_bit = ((plaintext_bytes[i] >> (7 - j)) & 1) as Field;
            let index = (i as u32) * 8 + (j as u32);
            assert(aes_ctr2.output[index] == original_bit);
        }
    }
}

// https://github.com/ModoriLabs/zk-symmetric-crypto/blob/extend-noir/circom/tests/aes-circuits.test.ts#L98
#[test]
fn test_aes_128_ctr_with_nonce_and_counter() {
    // Test based on circom test vector with separate nonce and counter
    // This simulates the GCM mode counter construction

    let mut aes_ctr = AES_CTR::<128, 16>::new();

    // Key from circom test
    let key_bytes: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // Convert key to bits
    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr.key[index] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Construct IV from nonce (12 bytes) + counter (4 bytes)
    // Nonce: 01 02 00 00 00 00 00 4a 00 00 00 09
    // Counter: 00000002 (big-endian)
    let iv_bytes: [u8; 16] = [
        0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x02,
    ];

    // Convert IV to bits
    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr.counter[index] = ((iv_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Plaintext from circom test: "Ladies aemen of " (16 bytes)
    let plaintext_bytes: [u8; 16] = [
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66,
        0x20,
    ];

    // Convert plaintext to bits
    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            aes_ctr.input[index] = ((plaintext_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Perform encryption
    aes_ctr.encrypt();

    // Expected ciphertext (computed using standard AES-128-CTR)
    let expected_ciphertext_bytes: [u8; 16] = [
        0x3d, 0xe8, 0x74, 0x91, 0x1c, 0x0b, 0xde, 0x5c, 0xc5, 0x6d, 0xe9, 0x95, 0xe6, 0x8b, 0x13,
        0xb7,
    ];

    // Verify output
    for i in 0..16 {
        for j in 0..8 {
            let expected_bit = ((expected_ciphertext_bytes[i] >> (7 - j)) & 1) as Field;
            let index = (i as u32) * 8 + (j as u32);
            assert(aes_ctr.output[index] == expected_bit);
        }
    }
}
