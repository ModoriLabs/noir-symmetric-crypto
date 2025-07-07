// Copyright (c) 2025 tx-tomcat

/// XOR operation between two Fields
pub struct XOR {
    pub a: Field,
    pub b: Field,
}

impl XOR {
    pub fn new() -> Self {
        Self { a: 0, b: 0 }
    }

    pub fn compute(&mut self) -> Field {
        let mid = self.a * self.b;
        self.a + self.b - 2 * mid
    }
}

/// Convert N bits to a number
pub struct Bits2Num<let N: u32> {
    pub input: [Field; N],
}

impl<let N: u32> Bits2Num<N> {
    pub fn new() -> Self {
        Self { input: [0; N] }
    }

    pub fn compute(&mut self) -> Field {
        let mut lc1: Field = 0;
        let mut e2: Field = 1;

        for i in 0..N {
            lc1 += self.input[i] * e2;
            e2 = e2 + e2; // Same as e2 *= 2 but matching Circom style
        }
        lc1
    }
}

/// Convert a number to N bits
pub struct Num2Bits<let n: u32> {
    pub input: Field,
}

impl<let n: u32> Num2Bits<n> {
    pub fn new() -> Self {
        Self { input: 0 }
    }

    pub fn compute(&mut self) -> [Field; n] {
        let mut output: [Field; n] = [0; n];
        let mut lc1: Field = 0;
        let mut e2: Field = 1;
        let mut remaining: u32 = self.input as u32;

        // Convert input to bits
        for i in 0..n {
            // Get the least significant bit
            let bit_u32 = remaining & 1;
            let bit = Field::from(bit_u32);
            output[i] = bit;

            // Constrain bit to be 0 or 1
            assert(output[i] * (output[i] - 1) == 0);

            // Build linear combination for verification
            lc1 += output[i] * e2;

            // Shift right by dividing by 2
            remaining = remaining / 2;
            e2 = e2 + e2;
        }

        // Constrain linear combination equals input
        assert(lc1 == self.input);
        output
    }
}

#[test]
fn test_num2bits_basic() {
    // Test 8-bit conversion of 170 (0b10101010)
    let mut num2bits = Num2Bits::<8>::new();
    num2bits.input = 170;
    // .to_le_bits() returns [u1; _]
    let result = num2bits.compute(); // [Field; 8]

    // Expected bits: [0, 1, 0, 1, 0, 1, 0, 1] (LSB first)
    assert(result[0] == 0);
    assert(result[1] == 1); // 2
    assert(result[2] == 0);
    assert(result[3] == 1); // 8
    assert(result[4] == 0);
    assert(result[5] == 1); // 32
    assert(result[6] == 0);
    assert(result[7] == 1); // 128
}

#[test]
fn test_num2bits_zero() {
    // Test conversion of 0
    let mut num2bits = Num2Bits::<8>::new();
    num2bits.input = 0;
    let result = num2bits.compute();

    // All bits should be 0
    for i in 0..8 {
        assert(result[i] == 0);
    }
}

#[test]
fn test_num2bits_max_8bit() {
    // Test conversion of 255 (0b11111111)
    let mut num2bits = Num2Bits::<8>::new();
    num2bits.input = 255;
    let result = num2bits.compute();

    // All bits should be 1
    for i in 0..8 {
        assert(result[i] == 1);
    }
}

#[test]
fn test_num2bits_power_of_two() {
    // Test conversion of 64 (0b01000000)
    let mut num2bits = Num2Bits::<8>::new();
    num2bits.input = 64;
    let result = num2bits.compute();

    // Only bit 6 should be set (LSB = bit 0)
    assert(result[0] == 0); // 2^0
    assert(result[1] == 0); // 2^1
    assert(result[2] == 0); // 2^2
    assert(result[3] == 0); // 2^3
    assert(result[4] == 0); // 2^4
    assert(result[5] == 0); // 2^5
    assert(result[6] == 1); // 2^6 = 64
    assert(result[7] == 0); // 2^7
}

#[test]
fn test_num2bits_16bit() {
    // Test 16-bit conversion of 0xABCD (43981)
    let mut num2bits = Num2Bits::<16>::new();
    num2bits.input = 43981;
    let result = num2bits.compute();

    // 0xABCD = 1010 1011 1100 1101
    // LSB first: [1,0,1,1,0,0,1,1,1,1,0,1,0,1,0,1]
    let expected = [1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1];

    for i in 0..16 {
        assert(result[i] == expected[i]);
    }
}

#[test]
fn test_num2bits_round_trip() {
    // Test that Num2Bits -> Bits2Num gives original value
    let original_value = 123;

    // Convert to bits
    let mut num2bits = Num2Bits::<8>::new();
    num2bits.input = original_value;
    let bits = num2bits.compute();

    // Convert back to number
    let mut bits2num = Bits2Num::<8>::new();
    bits2num.input = bits;
    let recovered_value = bits2num.compute();

    assert(recovered_value == original_value);
}

#[test]
fn test_bits2num_basic() {
    // Test basic Bits2Num conversion
    let mut bits2num = Bits2Num::<8>::new();
    // Set bits for 170 (0b10101010): [0,1,0,1,0,1,0,1] (LSB first)
    bits2num.input = [0, 1, 0, 1, 0, 1, 0, 1];
    let result = bits2num.compute();

    assert(result == 170);
}

#[test]
fn test_xor_operation() {
    // Test XOR operation
    let mut xor_op = XOR::new();

    // Test 0 XOR 0 = 0
    xor_op.a = 0;
    xor_op.b = 0;
    assert(xor_op.compute() == 0);

    // Test 0 XOR 1 = 1
    xor_op.a = 0;
    xor_op.b = 1;
    assert(xor_op.compute() == 1);

    // Test 1 XOR 0 = 1
    xor_op.a = 1;
    xor_op.b = 0;
    assert(xor_op.compute() == 1);

    // Test 1 XOR 1 = 0
    xor_op.a = 1;
    xor_op.b = 1;
    assert(xor_op.compute() == 0);
}

#[test]
fn test_aes_byte_values() {
    // Test with typical AES S-box values
    let test_values = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5];

    for value in test_values {
        let mut num2bits = Num2Bits::<8>::new();
        num2bits.input = value;
        let bits = num2bits.compute();

        // Convert back to verify
        let mut bits2num = Bits2Num::<8>::new();
        bits2num.input = bits;
        let recovered = bits2num.compute();

        assert(recovered == value);
    }
}
