use std::{env, io};
use std::io::{Read, Write};

mod sbox;

// Key lengths in words
// static NK128: u8 = 4;
// static NK192: u8 = 6;
// static NK256: u8 = 8;

/**
    Block size in words
**/
static NB: u8 = 4;

/**
    Round constants
**/
static R_CON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10,
                          0x20, 0x40, 0x80, 0x1b, 0x36];

#[derive(Clone, Copy, Debug)]
struct Word {
    bytes: [u8; 4]
}

/**
    ???
**/
fn gf_double(a: u8) -> u8 {
    let h = (a >> 7) & 1;
    let mut b = a << 1;
    b ^= h * 0x1b;
    b &= 0xff;
    b
}

fn gf_mult(a: u8, b: u8) -> u8 {
    if b == 1 {
        return a;
    }

    let c = b % 2;
    gf_mult(gf_double(a), (b-c) / 2) ^ (c * a)
}

impl std::ops::BitXorAssign for Word {
    fn bitxor_assign(&mut self, rhs: Self) {
        for i in 0..4 {
            self.bytes[i] ^= rhs.bytes[i];
        }
    }
}

impl std::ops::BitXor for Word {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        let mut result = self.copy();
        result ^= rhs;
        result
    }
}

impl Word {
    fn copy(&self) -> Self {
        Word { bytes: self.bytes }
    }
}

/**
    Word operations
**/
impl Word {
    fn rot_word(&mut self) -> () {
        self.bytes.rotate_left(1);
    }

    fn sub_word(&mut self) -> () {
        for i in 0..4 {
            self.bytes[i] = sbox::SBOX[self.bytes[i] as usize];
        }
    }

    fn inv_sub_word(&mut self) -> () {
        for i in 0..4 {
            self.bytes[i] = sbox::INV_SBOX[self.bytes[i] as usize];
        }
    }

    // derived from c implementation on wikipedia
    fn mix_column(&mut self) -> () {
        self.bytes[0] = gf_double(self.bytes[0]) ^ self.bytes[3] ^ self.bytes[2] ^ gf_double(self.bytes[1]) ^ self.bytes[1];
        self.bytes[1] = gf_double(self.bytes[1]) ^ self.bytes[0] ^ self.bytes[3] ^ gf_double(self.bytes[2]) ^ self.bytes[2];
        self.bytes[2] = gf_double(self.bytes[2]) ^ self.bytes[1] ^ self.bytes[0] ^ gf_double(self.bytes[3]) ^ self.bytes[3];
        self.bytes[3] = gf_double(self.bytes[3]) ^ self.bytes[2] ^ self.bytes[1] ^ gf_double(self.bytes[0]) ^ self.bytes[0];
    }

    // derived from https://github.com/boppreh/aes (pure magic)
    fn inv_mix_column(&mut self) -> () {
        let u = gf_mult(self.bytes[0] ^ self.bytes[2], 4);
        let v = gf_mult(self.bytes[1] ^ self.bytes[3], 4);

        self.bytes[0] ^= u;
        self.bytes[1] ^= v;
        self.bytes[2] ^= u;
        self.bytes[3] ^= v;

        self.mix_column();
    }
}


#[derive(Clone, Copy, Debug)]
struct Block {
    // 1D array of 4x4 words
    words: [Word; 4]
}

impl std::ops::BitXor for Block {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        let mut result = self.copy();
        result ^= rhs;
        result
    }
}

impl std::ops::BitXorAssign for Block {
    fn bitxor_assign(&mut self, rhs: Self) {
        for i in 0..4 {
            self.words[i] ^= rhs.words[i];
        }
    }
}

impl Block {
    fn new(bytes: [u8; 16]) -> Self {
        let mut words: [Word; 4] = [Word { bytes: [0; 4] }; 4];

        for i in 0..16 {
            words[i / 4].bytes[i % 4] = bytes[i];
        }

        Block { words }
    }

    fn copy(&self) -> Self {
        Block { words: self.words }
    }

    fn as_bytes(&self) -> [u8; 16] {
        let mut bytes: [u8; 16] = [0; 16];

        for i in 0..16 {
            bytes[i] = self.words[i / 4].bytes[i % 4];
        }

        bytes
    }

    fn sub_bytes(self) -> () {
        for mut w in self.words {
            w.sub_word();
        }
    }

    fn inv_sub_bytes(self) -> () {
        for mut w in self.words {
            w.inv_sub_word();
        }
    }

    fn shift_rows(self) -> () {
        for mut r in self.words {
            r.bytes.rotate_left(1)
        }
    }

    fn inv_shift_rows(self) -> () {
        for mut r in self.words {
            r.bytes.rotate_right(1)
        }
    }

    fn mix_columns(self) -> () {
        for mut w in self.words {
            w.mix_column();
        }
    }

    fn inv_mix_columns(self) -> () {
        for mut w in self.words {
            w.inv_mix_column();
        }
    }

    fn add_round_key(&mut self, key: Block) -> () {
        for i in 0..4 {
            self.words[i] ^= key.words[i];
        }
    }
}

fn bytes_to_blocks(ref bytes: &[u8]) -> Vec<Block> {
    let length = bytes.len() as u8;

    // calculate padding
    let padding = 4*NB - (length % 4*NB);

    // pad bytes
    let mut padded_bytes: Vec<u8> = Vec::new();
    padded_bytes.extend_from_slice(bytes);
    padded_bytes.extend_from_slice(&vec![padding; padding as usize]);

    // convert bytes to words
    let mut words: Vec<Word> = Vec::new();
    for i in 0..padded_bytes.len() / 4 {
        words.push(
            Word { bytes: [
                padded_bytes[(4 * i) as usize],
                padded_bytes[(4 * i + 1) as usize],
                padded_bytes[(4 * i + 2) as usize],
                padded_bytes[(4 * i + 3) as usize]
            ] }
        );
    }

    // convert words to blocks
    let mut blocks: Vec<Block> = Vec::new();
    for i in 0..words.len() {
        if i % 4 == 0 {
            blocks.push(Block::new([0; 16]));
        }
        blocks[i / 4].words[i % 4] = words[i];
    }

    blocks
}

/**
    Round constant for round j
**/
fn rcon(j: u8) -> Word {
    Word { bytes: [R_CON[j as usize], 0, 0, 0] }
}

fn key_expansion(key: &[u8], nk: u8, nr: u8) -> Vec<Block> {

    // convert key to words
    let mut w: Vec<Word> = Vec::new();
    for i in 0..nk {
        w.push(
            Word { bytes: [
                key[(4 * i) as usize],
                key[(4 * i + 1) as usize],
                key[(4 * i + 2) as usize],
                key[(4 * i + 3) as usize]
            ] }
        );
    }

    // key expansion
    for i in nk..NB * (nr + 1) {
        let mut temp = w[(i - 1) as usize].copy();

        if i % nk == 0 {
            temp.rot_word();
            temp.sub_word();
            temp ^= rcon(i / nk -1);
        } else if nk > 6 && i % nk == 4 {
            temp.sub_word();
        }

        w.push(w[(i - nk) as usize] ^ temp);
    }

    // convert words to blocks
    let mut blocks: Vec<Block> = Vec::new();
    for i in 0..w.len() {
        if i % 4 == 0 {
            blocks.push(Block::new([0; 16]));
        }
        blocks[i / 4].words[i % 4] = w[i];
    }

    blocks
}

fn cipher(inblock: Block, n_rounds: u8, w: Vec<Block>) -> Block {
    let mut state = inblock;

    state.add_round_key(w[0]);

    for i in 1..n_rounds {
        state.sub_bytes();
        state.shift_rows();
        state.mix_columns();
        state.add_round_key(w[i as usize]);
    }

    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(w[n_rounds as usize]);

    state
}

fn inv_cipher(inblock: Block, n_rounds: u8, w: Vec<Block>) -> Block {
    let mut state = inblock;

    state.add_round_key(w[n_rounds as usize]);

    for i in (1..n_rounds).rev() {
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(w[i as usize]);
        state.inv_mix_columns();
    }

    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(w[0]);

    state
}

fn determine_key_length(key: &[u8]) -> (u8, u8) {
    match key.len() {
        16 => (4, 10),
        24 => (6, 12),
        32 => (8, 14),
        _ => panic!("invalid key length"),
    }
}

fn aes(inblock: Block, key: &[u8]) -> Block {
    let (nk, nr) = determine_key_length(key);

    let w = key_expansion(key, nk, nr);

    cipher(inblock, nr, w)
}

fn inv_aes(inblock: Block, key: &[u8]) -> Block {
    let (nk, nr) = determine_key_length(key);

    let w = key_expansion(key, nk, nr);

    inv_cipher(inblock, nr, w)
}

fn encrypt(bytes: &[u8], key: &[u8], iv: [u8; 16]) -> Vec<u8> {
    let blocks = bytes_to_blocks(bytes);
    let mut cipher: Vec<u8> = Vec::new();

    let mut chain = Block::new(iv);

    for block in blocks {
        chain = aes(block ^ chain, key);
        cipher.extend_from_slice(&chain.as_bytes());
    }

    cipher
}

fn decrypt(bytes: &[u8], key: &[u8], iv: [u8; 16]) -> Vec<u8> {
    let blocks = bytes_to_blocks(bytes);
    let mut plain: Vec<u8> = Vec::new();

    let mut chain = Block::new(iv);

    for block in blocks {
        plain.extend_from_slice(&(inv_aes(block, key) ^ chain).as_bytes());
        chain = block;
    }

    //remove padding
    let padding = plain[plain.len() - 1];
    plain.truncate(plain.len() - padding as usize);

    plain
}


fn main() -> io::Result<()> {
    // read input from stdin
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;

    // where do we get this from?
    let iv = [0u8; 16];

    // command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <encrypt|decrypt> <key>", args[0]);
        return Ok(())
    }

    // convert input to bytes
    let key: &[u8] = args[2].as_bytes();

    let result: Vec<u8> = match args[1].as_str() {
        "encrypt" => encrypt(&mut buffer, key, iv),
        "decrypt" => decrypt(&mut buffer, key, iv),
        _ => panic!("invalid command")
    };

    // write result to stdout
    io::stdout().write_all(&result)?;

    Ok(())
}
