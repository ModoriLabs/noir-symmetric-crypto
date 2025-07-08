/// Runs a 64-byte block of chacha20.
/// A new working state is instantiated with the key, nonce and counter.
/// Then run the `inner_block` function 10 times on the working state.
/// After the 10 rounds, the working state is added to the original state
///
/// Return: the serialized bytes of the working state (64 bytes)
pub fn chacha20_block(key: [u32; 8], nonce: [u32; 3], counter: u32) -> [u32; 16] {
    let mut state = ChaChaState::new(key, nonce, counter);
    let mut working_state = ChaChaState::new(key, nonce, counter);

    for _i in 0..10 {
        working_state.inner_block();
    }

    state.add(working_state);
    state.to_le_4bytes()
}

/// Structure that holds the chacha20 state
pub struct ChaChaState {
    pub state: [u32; 16],
}

impl ChaChaState {
    /// Instantiate a new chacha20 state with the require parameters
    pub fn new(key: [u32; 8], nonce: [u32; 3], counter: u32) -> Self {
        Self {
            state: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // Constants
                key[0], key[1],
                key[2], key[3],
                key[4], key[5],
                key[6], key[7],
                counter, nonce[0],
                nonce[1], nonce[2]
            ]
        }
    }

    /// Add two ChaChaState's together elementwise
    pub fn add(&mut self, other: Self) {
        for i in 0..16 {
            self.state[i] = (self.state[i] as u64 + other.state[i] as u64) as u32;
        }
    }

    /// Serializes the state as 4-byte little endian words
    pub fn to_le_4bytes(self) -> [u32; 16] {
        let mut res = [0; 16];
        for i in 0..16 {
            res[i] = ((self.state[i] & 0xFF) << 24)
                + ((self.state[i] & 0xFF00) << 8)
                + ((self.state[i] & 0xFF0000) >> 8)
                + ((self.state[i] & 0xFF000000) >> 24);
        }
        res
    }

    /// Runs quarter round on the working state 8 times:
    /// 0 4 8 12
    /// 1 5 9 13
    /// 2 6 10 14
    /// 3 7 11 15
    /// 0 5 10 15
    /// 1 6 11 12
    /// 2 7 8 13
    /// 3 4 9 14
    pub fn inner_block(&mut self) {
        let mut state_0 = self.state[0];
        let mut state_1 = self.state[1];
        let mut state_2 = self.state[2];
        let mut state_3 = self.state[3];
        let mut state_4 = self.state[4];
        let mut state_5 = self.state[5];
        let mut state_6 = self.state[6];
        let mut state_7 = self.state[7];
        let mut state_8 = self.state[8];
        let mut state_9 = self.state[9];
        let mut state_10 = self.state[10];
        let mut state_11 = self.state[11];
        let mut state_12 = self.state[12];
        let mut state_13 = self.state[13];
        let mut state_14 = self.state[14];
        let mut state_15 = self.state[15];

        quarter_round(&mut state_0, &mut state_4, &mut state_8, &mut state_12);
        quarter_round(&mut state_1, &mut state_5, &mut state_9, &mut state_13);
        quarter_round(&mut state_2, &mut state_6, &mut state_10, &mut state_14);
        quarter_round(&mut state_3, &mut state_7, &mut state_11, &mut state_15);
        quarter_round(&mut state_0, &mut state_5, &mut state_10, &mut state_15);
        quarter_round(&mut state_1, &mut state_6, &mut state_11, &mut state_12);
        quarter_round(&mut state_2, &mut state_7, &mut state_8, &mut state_13);
        quarter_round(&mut state_3, &mut state_4, &mut state_9, &mut state_14);

        self.state[0] = state_0;
        self.state[1] = state_1;
        self.state[2] = state_2;
        self.state[3] = state_3;
        self.state[4] = state_4;
        self.state[5] = state_5;
        self.state[6] = state_6;
        self.state[7] = state_7;
        self.state[8] = state_8;
        self.state[9] = state_9;
        self.state[10] = state_10;
        self.state[11] = state_11;
        self.state[12] = state_12;
        self.state[13] = state_13;
        self.state[14] = state_14;
        self.state[15] = state_15;
    }
}

/// Performs a quarter round of chacha20 on 4 32-byte values.
pub fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    let a_val = *a;
    let b_val = *b;
    let temp_a = (a_val as u64 + b_val as u64) as u32;
    *a = temp_a;
    *d ^= *a;
    left_rotation(d, 16);
    
    let c_val = *c;
    let d_val = *d;
    let temp_c = (c_val as u64 + d_val as u64) as u32;
    *c = temp_c;
    *b ^= *c;
    left_rotation(b, 12);
    
    let a_val2 = *a;
    let b_val2 = *b;
    let temp_a2 = (a_val2 as u64 + b_val2 as u64) as u32;
    *a = temp_a2;
    *d ^= *a;
    left_rotation(d, 8);
    
    let c_val2 = *c;
    let d_val2 = *d;
    let temp_c2 = (c_val2 as u64 + d_val2 as u64) as u32;
    *c = temp_c2;
    *b ^= *c;
    left_rotation(b, 7);
}

/// Performs a left rotation on a 32-bit value
fn left_rotation(value: &mut u32, shift: u32) {
    let shift_u8 = shift as u8;
    *value = (*value << shift_u8) | (*value >> (32 - shift_u8));
}