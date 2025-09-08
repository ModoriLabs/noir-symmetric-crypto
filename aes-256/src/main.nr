mod test;

use dep::noir_symmetric_crypto::aes::aes_ctr::AES_CTR;

fn main(
    key: pub [u8; 32],
    counter: pub [u8; 16],
    plaintext: pub [u8; 80],
    expected_ciphertext: pub [u8; 80],
) {
    // Convert inputs from bytes to bits
    let mut key_bits: [Field; 256] = [0; 256];
    let mut counter_bits: [Field; 128] = [0; 128];
    let mut plaintext_bits: [Field; 640] = [0; 640];
    let mut expected_bits: [Field; 640] = [0; 640];

    // Convert key bytes to bits
    for i in 0..32 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            key_bits[index] = ((key[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Convert counter bytes to bits
    for i in 0..16 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            counter_bits[index] = ((counter[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Convert plaintext bytes to bits
    for i in 0..80 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            plaintext_bits[index] = ((plaintext[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Convert expected ciphertext bytes to bits
    for i in 0..80 {
        for j in 0..8 {
            let index = (i as u32) * 8 + (j as u32);
            expected_bits[index] = ((expected_ciphertext[i] >> (7 - j)) & 1) as Field;
        }
    }

    // Create AES-256-CTR instance
    let mut aes_ctr = AES_CTR::<80 * 8, 32>::new();

    // Set inputs
    aes_ctr.input = plaintext_bits;
    aes_ctr.counter = counter_bits;
    aes_ctr.key = key_bits;

    // Perform encryption
    aes_ctr.encrypt();

    // Verify the output matches expected ciphertext
    for i in 0..640 {
        assert(aes_ctr.output[i] == expected_bits[i]);
    }
}
