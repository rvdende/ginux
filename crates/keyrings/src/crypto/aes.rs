//! AES-256 (FIPS 197) in CBC mode without padding, the cipher encrypted
//! keys keep their data under ("cbc(aes)" with a 32-byte key).

/// The block and IV length in bytes.
pub(crate) const BLOCK_BYTES: usize = 16;
pub(crate) const KEY_BYTES: usize = 32;
const ROUNDS: usize = 14;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INVERSE_SBOX: [u8; 256] = {
    let mut inverse = [0_u8; 256];
    let mut index = 0;
    while index < 256 {
        inverse[SBOX[index] as usize] = index as u8;
        index += 1;
    }
    inverse
};

/// Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1.
const fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

type Block = [u8; BLOCK_BYTES];

/// An expanded AES-256 key.
pub(crate) struct Aes256 {
    round_keys: [Block; ROUNDS + 1],
}

impl Aes256 {
    pub(crate) fn new(key: &[u8; KEY_BYTES]) -> Self {
        let mut words = [[0_u8; 4]; 4 * (ROUNDS + 1)];
        for (word, bytes) in words.iter_mut().zip(key.as_chunks::<4>().0) {
            *word = *bytes;
        }
        let mut round_constant = 1_u8;
        for index in 8..words.len() {
            let mut word = words[index - 1];
            if index % 8 == 0 {
                word.rotate_left(1);
                word = word.map(|byte| SBOX[usize::from(byte)]);
                word[0] ^= round_constant;
                round_constant = multiply(round_constant, 2);
            } else if index % 8 == 4 {
                word = word.map(|byte| SBOX[usize::from(byte)]);
            }
            for (byte, previous) in word.iter_mut().zip(words[index - 8]) {
                *byte ^= previous;
            }
            words[index] = word;
        }
        let mut round_keys = [[0; BLOCK_BYTES]; ROUNDS + 1];
        for (round_key, chunk) in round_keys.iter_mut().zip(words.as_chunks::<4>().0) {
            for (bytes, word) in round_key.as_chunks_mut::<4>().0.iter_mut().zip(chunk) {
                *bytes = *word;
            }
        }
        Self { round_keys }
    }

    fn encrypt_block(&self, block: &mut Block) {
        add(block, &self.round_keys[0]);
        for round in 1..=ROUNDS {
            for byte in block.iter_mut() {
                *byte = SBOX[usize::from(*byte)];
            }
            shift_rows(block, 1);
            if round != ROUNDS {
                mix_columns(block, [2, 3, 1, 1]);
            }
            add(block, &self.round_keys[round]);
        }
    }

    fn decrypt_block(&self, block: &mut Block) {
        add(block, &self.round_keys[ROUNDS]);
        for round in (0..ROUNDS).rev() {
            shift_rows(block, 3);
            for byte in block.iter_mut() {
                *byte = INVERSE_SBOX[usize::from(*byte)];
            }
            add(block, &self.round_keys[round]);
            if round != 0 {
                mix_columns(block, [14, 11, 13, 9]);
            }
        }
    }

    /// Encrypts `data`, a whole number of blocks, in place in CBC mode.
    pub(crate) fn encrypt_cbc(&self, iv: &Block, data: &mut [u8]) {
        let mut chain = *iv;
        for chunk in data.as_chunks_mut::<BLOCK_BYTES>().0 {
            let mut block = *chunk;
            add(&mut block, &chain);
            self.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
            chain = block;
        }
    }

    /// Decrypts `data`, a whole number of blocks, in place in CBC mode.
    pub(crate) fn decrypt_cbc(&self, iv: &Block, data: &mut [u8]) {
        let mut chain = *iv;
        for chunk in data.as_chunks_mut::<BLOCK_BYTES>().0 {
            let mut block = *chunk;
            let cipher = block;
            self.decrypt_block(&mut block);
            add(&mut block, &chain);
            chunk.copy_from_slice(&block);
            chain = cipher;
        }
    }
}

fn add(block: &mut Block, key: &Block) {
    for (byte, key_byte) in block.iter_mut().zip(key) {
        *byte ^= key_byte;
    }
}

/// Rotates row r of the column-major state left by `step * r` places
/// (1 encrypts, 3 undoes it).
fn shift_rows(block: &mut Block, step: usize) {
    let state = *block;
    for row in 1..4 {
        for column in 0..4 {
            block[column * 4 + row] = state[((column + step * row) % 4) * 4 + row];
        }
    }
}

/// Multiplies each column by the circulant matrix whose first row is
/// `coefficients`.
fn mix_columns(block: &mut Block, coefficients: [u8; 4]) {
    for column in block.as_chunks_mut::<4>().0 {
        let input = [column[0], column[1], column[2], column[3]];
        for (row, output) in column.iter_mut().enumerate() {
            *output = (0..4).fold(0, |sum, index| {
                sum ^ multiply(coefficients[(index + 4 - row) % 4], input[index])
            });
        }
    }
}
