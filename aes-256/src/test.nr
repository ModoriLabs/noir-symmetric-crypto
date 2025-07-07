use dep::noir_symmetric_crypto::aes::aes_ctr::AES_CTR;

#[test]
fn test_aes_256_ctr_nist_vector_1() {
    // NIST AES-256-CTR Test Vector
    // Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    // Counter: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    // Expected Ciphertext: 601ec313775789a5b7a7f504bbf3d228

    let mut aes_ctr = AES_CTR::<128, 32>::new();

    // Set 256-bit key
    let key_bytes: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    ];

    // Convert key to bits (MSB first)
    for i in 0..32 {
        for j in 0..8 {
            aes_ctr.key[i * 8 + j] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
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
            aes_ctr.counter[i * 8 + j] = ((counter_bytes[i] >> (7 - j)) & 1) as Field;
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
            aes_ctr.input[i * 8 + j] = ((plaintext_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Perform encryption
    aes_ctr.encrypt();

    // Expected ciphertext
    let expected_ciphertext_bytes: [u8; 16] = [
        0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
        0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28
    ];

    // Verify output
    for i in 0..16 {
        for j in 0..8 {
            let expected_bit = ((expected_ciphertext_bytes[i] >> (7 - j)) & 1) as Field;
            assert(aes_ctr.output[i * 8 + j] == expected_bit);
        }
    }
}

#[test]
fn test_aes_256_ctr_nist_vector_2() {
    // Second NIST test vector with different plaintext block
    // Key: same as above
    // Counter: f0f1f2f3f4f5f6f7f8f9fafbfcfdff00 (incremented)
    // Plaintext: ae2d8a571e03ac9c9eb76fac45af8e51
    // Expected Ciphertext: f443e3ca4d62b59aca84e990cacaf5c5

    let mut aes_ctr = AES_CTR::<128, 32>::new();

    // Set same key
    let key_bytes: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    ];

    for i in 0..32 {
        for j in 0..8 {
            aes_ctr.key[i * 8 + j] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set counter (incremented by 1)
    let counter_bytes: [u8; 16] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x00
    ];

    for i in 0..16 {
        for j in 0..8 {
            aes_ctr.counter[i * 8 + j] = ((counter_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set plaintext
    let plaintext_bytes: [u8; 16] = [
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    ];

    for i in 0..16 {
        for j in 0..8 {
            aes_ctr.input[i * 8 + j] = ((plaintext_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Perform encryption
    aes_ctr.encrypt();

    // Expected ciphertext
    let expected_ciphertext_bytes: [u8; 16] = [
        0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
        0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5
    ];

    // Verify output
    for i in 0..16 {
        for j in 0..8 {
            let expected_bit = ((expected_ciphertext_bytes[i] >> (7 - j)) & 1) as Field;
            assert(aes_ctr.output[i * 8 + j] == expected_bit);
        }
    }
}

#[test]
fn test_aes_256_ctr_zero_plaintext() {
    // Test with zero plaintext to verify keystream generation
    let mut aes_ctr = AES_CTR::<128, 32>::new();

    // Set test key
    let key_bytes: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    ];

    for i in 0..32 {
        for j in 0..8 {
            aes_ctr.key[i * 8 + j] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set test counter
    let counter_bytes: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ];

    for i in 0..16 {
        for j in 0..8 {
            aes_ctr.counter[i * 8 + j] = ((counter_bytes[i] >> (7 - j)) & 1) as Field;
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
fn test_aes_256_ctr_decryption() {
    // CTR mode is symmetric - encryption and decryption are the same operation
    // Test that encrypting twice gives back the original plaintext

    let mut aes_ctr1 = AES_CTR::<128, 32>::new();
    let mut aes_ctr2 = AES_CTR::<128, 32>::new();

    // Set test key
    let key_bytes: [u8; 32] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    ];

    for i in 0..32 {
        for j in 0..8 {
            aes_ctr1.key[i * 8 + j] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
            aes_ctr2.key[i * 8 + j] = ((key_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set test counter
    let counter_bytes: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
    ];

    for i in 0..16 {
        for j in 0..8 {
            aes_ctr1.counter[i * 8 + j] = ((counter_bytes[i] >> (7 - j)) & 1) as Field;
            aes_ctr2.counter[i * 8 + j] = ((counter_bytes[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Set test plaintext
    let plaintext_bytes: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    ];

    for i in 0..16 {
        for j in 0..8 {
            aes_ctr1.input[i * 8 + j] = ((plaintext_bytes[i] >> (7 - j)) & 1) as Field;
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
            assert(aes_ctr2.output[i * 8 + j] == original_bit);
        }
    }
}
