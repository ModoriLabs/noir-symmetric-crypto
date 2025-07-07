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
        let mut remaining: Field = self.input;

        // Convert input to bits
        for i in 0..n {
            // Get the least significant bit
            let bit = remaining - (remaining / 2) * 2;
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

