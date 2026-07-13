//! Cryptographic hash functions: SHA-256, SHA-512, RIPEMD-160, HMAC.
//!
//! Pure implementations with no external crypto dependencies.
//! All algorithms implemented from scratch following FIPS 180-4 (SHA),
//! the RIPEMD-160 specification, and RFC 2104 (HMAC).

// ============================================================================
// SHA-256 (FIPS 180-4)
// ============================================================================

/// SHA-256 round constants (first 32 bits of the fractional parts of
/// the cube roots of the first 64 primes).
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values (first 32 bits of the fractional parts of
/// the square roots of the first 8 primes).
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Compute the SHA-256 hash of the input data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = SHA256_IV;
    let total_len = data.len();

    // Process complete 64-byte blocks
    let mut offset = 0;
    while offset + 64 <= data.len() {
        sha256_process_block(&mut state, &data[offset..offset + 64]);
        offset += 64;
    }

    // Pad and process remaining data
    let remaining = &data[offset..];
    let mut last_block = [0u8; 128]; // Up to 2 blocks for padding
    let rem_len = remaining.len();
    last_block[..rem_len].copy_from_slice(remaining);
    last_block[rem_len] = 0x80;

    let bit_len = (total_len as u64) * 8;

    // Check if we need one or two blocks for padding
    if rem_len + 1 + 8 <= 64 {
        // Fits in one block
        last_block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_process_block(&mut state, &last_block[..64]);
    } else {
        // Need two blocks
        last_block[120..128].copy_from_slice(&bit_len.to_be_bytes());
        sha256_process_block(&mut state, &last_block[..64]);
        sha256_process_block(&mut state, &last_block[64..128]);
    }

    // Convert state to bytes (big-endian)
    let mut output = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn sha256_process_block(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];

    // Prepare message schedule
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = s0
            .wrapping_add(w[i - 7])
            .wrapping_add(s1)
            .wrapping_add(w[i - 16]);
    }

    // Initialize working variables
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    // 64 rounds
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Add compressed chunk to running hash
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Double SHA-256: sha256(sha256(data)). Used in Bitcoin for txids, block hashes, etc.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Alias for sha256d (double SHA-256). Bitcoin convention name.
pub fn hash256(data: &[u8]) -> [u8; 32] {
    sha256d(data)
}

// ============================================================================
// SHA-512 (FIPS 180-4)
// ============================================================================

/// SHA-512 round constants (first 64 bits of the fractional parts of
/// the cube roots of the first 80 primes).
const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-512 initial hash values.
const SHA512_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Compute the SHA-512 hash of the input data.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut state = SHA512_IV;
    let total_len = data.len();

    // Process complete 128-byte blocks
    let mut offset = 0;
    while offset + 128 <= data.len() {
        sha512_process_block(&mut state, &data[offset..offset + 128]);
        offset += 128;
    }

    // Pad and process remaining data
    let remaining = &data[offset..];
    let mut last_block = [0u8; 256]; // Up to 2 blocks for padding
    let rem_len = remaining.len();
    last_block[..rem_len].copy_from_slice(remaining);
    last_block[rem_len] = 0x80;

    let bit_len = (total_len as u128) * 8;

    // Check if we need one or two blocks for padding
    if rem_len + 1 + 16 <= 128 {
        // Fits in one block: length goes at bytes 112..128
        last_block[112..128].copy_from_slice(&bit_len.to_be_bytes());
        sha512_process_block(&mut state, &last_block[..128]);
    } else {
        // Need two blocks: length goes at bytes 240..256
        last_block[240..256].copy_from_slice(&bit_len.to_be_bytes());
        sha512_process_block(&mut state, &last_block[..128]);
        sha512_process_block(&mut state, &last_block[128..256]);
    }

    // Convert state to bytes (big-endian)
    let mut output = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        output[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn sha512_process_block(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];

    // Prepare message schedule
    for i in 0..16 {
        w[i] = u64::from_be_bytes([
            block[i * 8],
            block[i * 8 + 1],
            block[i * 8 + 2],
            block[i * 8 + 3],
            block[i * 8 + 4],
            block[i * 8 + 5],
            block[i * 8 + 6],
            block[i * 8 + 7],
        ]);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = s0
            .wrapping_add(w[i - 7])
            .wrapping_add(s1)
            .wrapping_add(w[i - 16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K512[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

// ============================================================================
// RIPEMD-160
// ============================================================================

/// RIPEMD-160 initial hash values.
const RIPEMD160_IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// Left message word selection per round.
const RIPEMD160_R: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

/// Right message word selection per round.
const RIPEMD160_RH: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

/// Left rotation amounts per round.
const RIPEMD160_S: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

/// Right rotation amounts per round.
const RIPEMD160_SH: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// RIPEMD-160 boolean function for the left path.
fn ripemd160_f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j <= 15 {
        x ^ y ^ z
    } else if j <= 31 {
        (x & y) | (!x & z)
    } else if j <= 47 {
        (x | !y) ^ z
    } else if j <= 63 {
        (x & z) | (y & !z)
    } else {
        x ^ (y | !z)
    }
}

/// RIPEMD-160 left-path additive constants.
fn ripemd160_k(j: usize) -> u32 {
    if j <= 15 {
        0x00000000
    } else if j <= 31 {
        0x5a827999
    } else if j <= 47 {
        0x6ed9eba1
    } else if j <= 63 {
        0x8f1bbcdc
    } else {
        0xa953fd4e
    }
}

/// RIPEMD-160 right-path additive constants.
fn ripemd160_kh(j: usize) -> u32 {
    if j <= 15 {
        0x50a28be6
    } else if j <= 31 {
        0x5c4dd124
    } else if j <= 47 {
        0x6d703ef3
    } else if j <= 63 {
        0x7a6d76e9
    } else {
        0x00000000
    }
}

/// Compute the RIPEMD-160 hash of the input data.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut state = RIPEMD160_IV;
    let total_len = data.len();

    // Process complete 64-byte blocks
    let mut offset = 0;
    while offset + 64 <= data.len() {
        ripemd160_process_block(&mut state, &data[offset..offset + 64]);
        offset += 64;
    }

    // Pad and process remaining data (little-endian length encoding)
    let remaining = &data[offset..];
    let mut last_block = [0u8; 128];
    let rem_len = remaining.len();
    last_block[..rem_len].copy_from_slice(remaining);
    last_block[rem_len] = 0x80;

    let bit_len = (total_len as u64) * 8;

    if rem_len + 1 + 8 <= 64 {
        last_block[56..64].copy_from_slice(&bit_len.to_le_bytes());
        ripemd160_process_block(&mut state, &last_block[..64]);
    } else {
        last_block[120..128].copy_from_slice(&bit_len.to_le_bytes());
        ripemd160_process_block(&mut state, &last_block[..64]);
        ripemd160_process_block(&mut state, &last_block[64..128]);
    }

    // Convert state to bytes (little-endian)
    let mut output = [0u8; 20];
    for (i, word) in state.iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    output
}

fn ripemd160_process_block(state: &mut [u32; 5], block: &[u8]) {
    // Parse block as 16 little-endian u32 words
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    let mut al = state[0];
    let mut bl = state[1];
    let mut cl = state[2];
    let mut dl = state[3];
    let mut el = state[4];
    let mut ar = al;
    let mut br = bl;
    let mut cr = cl;
    let mut dr = dl;
    let mut er = el;

    for j in 0..80 {
        // Left round
        let t = al
            .wrapping_add(ripemd160_f(j, bl, cl, dl))
            .wrapping_add(x[RIPEMD160_R[j]])
            .wrapping_add(ripemd160_k(j))
            .rotate_left(RIPEMD160_S[j])
            .wrapping_add(el);
        al = el;
        el = dl;
        dl = cl.rotate_left(10);
        cl = bl;
        bl = t;

        // Right round
        let t = ar
            .wrapping_add(ripemd160_f(79 - j, br, cr, dr))
            .wrapping_add(x[RIPEMD160_RH[j]])
            .wrapping_add(ripemd160_kh(j))
            .rotate_left(RIPEMD160_SH[j])
            .wrapping_add(er);
        ar = er;
        er = dr;
        dr = cr.rotate_left(10);
        cr = br;
        br = t;
    }

    let t = state[1].wrapping_add(cl).wrapping_add(dr);
    state[1] = state[2].wrapping_add(dl).wrapping_add(er);
    state[2] = state[3].wrapping_add(el).wrapping_add(ar);
    state[3] = state[4].wrapping_add(al).wrapping_add(br);
    state[4] = state[0].wrapping_add(bl).wrapping_add(cr);
    state[0] = t;
}

// ============================================================================
// Composite hash functions
// ============================================================================

/// hash160: RIPEMD-160(SHA-256(data)). Used for Bitcoin addresses.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

// ============================================================================
// HMAC (RFC 2104)
// ============================================================================

/// Internal HMAC computation generic over hash function.
fn hmac<const BLOCK_SIZE: usize, const OUT_SIZE: usize>(
    key: &[u8],
    data: &[u8],
    hash_fn: fn(&[u8]) -> [u8; OUT_SIZE],
) -> [u8; OUT_SIZE] {
    // If key is longer than block size, hash it first
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed_key = hash_fn(key);
        key_block[..OUT_SIZE].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    // Remaining bytes are already zero (pad with zeros)

    // Inner hash: H((K ^ ipad) || data)
    let mut i_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        i_key_pad[i] = key_block[i] ^ 0x36;
    }
    let mut inner_msg = Vec::with_capacity(BLOCK_SIZE + data.len());
    inner_msg.extend_from_slice(&i_key_pad);
    inner_msg.extend_from_slice(data);
    let inner_hash = hash_fn(&inner_msg);

    // Outer hash: H((K ^ opad) || inner_hash)
    let mut o_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        o_key_pad[i] = key_block[i] ^ 0x5c;
    }
    let mut outer_msg = Vec::with_capacity(BLOCK_SIZE + OUT_SIZE);
    outer_msg.extend_from_slice(&o_key_pad);
    outer_msg.extend_from_slice(&inner_hash);
    hash_fn(&outer_msg)
}

/// Wrapper to adapt sha256 signature for HMAC usage.
fn sha256_wrapper(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// Wrapper to adapt sha512 signature for HMAC usage.
fn sha512_wrapper(data: &[u8]) -> [u8; 64] {
    sha512(data)
}

/// Compute HMAC-SHA256.
pub fn sha256_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac::<64, 32>(key, data, sha256_wrapper)
}

/// Compute HMAC-SHA512.
pub fn sha512_hmac(key: &[u8], data: &[u8]) -> [u8; 64] {
    hmac::<128, 64>(key, data, sha512_wrapper)
}

// ============================================================================
// PBKDF2-HMAC-SHA512 (RFC 2898)
// ============================================================================

/// Derive key material using PBKDF2 with HMAC-SHA512.
///
/// Implements RFC 2898 Section 5.2 using HMAC-SHA512 as the PRF.
/// Used by BIP39 for mnemonic-to-seed derivation.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let mut dk = Vec::with_capacity(dk_len);
    let mut block = 1u32;

    while dk.len() < dk_len {
        // U_1 = HMAC(password, salt || INT_32_BE(block))
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block.to_be_bytes());

        let mut u = sha512_hmac(password, &salt_block);
        let mut t = u;

        // U_2 .. U_c: each U_i = HMAC(password, U_{i-1}), T = U_1 XOR U_2 XOR ... XOR U_c
        for _ in 1..iterations {
            u = sha512_hmac(password, &u);
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= *ui;
            }
        }

        let remaining = dk_len - dk.len();
        dk.extend_from_slice(&t[..remaining.min(64)]);
        block += 1;
    }

    dk
}

// ============================================================================
// SHA-1 (FIPS 180-4)
// ============================================================================

/// SHA-1 initial hash values.
const SHA1_IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// Compute the SHA-1 hash of the input data.
///
/// Implemented from FIPS 180-4. Used by OP_SHA1 in the script interpreter.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state = SHA1_IV;
    let total_len = data.len();

    // Process complete 64-byte blocks
    let mut offset = 0;
    while offset + 64 <= data.len() {
        sha1_process_block(&mut state, &data[offset..offset + 64]);
        offset += 64;
    }

    // Pad and process remaining data
    let remaining = &data[offset..];
    let mut last_block = [0u8; 128];
    let rem_len = remaining.len();
    last_block[..rem_len].copy_from_slice(remaining);
    last_block[rem_len] = 0x80;

    let bit_len = (total_len as u64) * 8;

    if rem_len + 1 + 8 <= 64 {
        last_block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha1_process_block(&mut state, &last_block[..64]);
    } else {
        last_block[120..128].copy_from_slice(&bit_len.to_be_bytes());
        sha1_process_block(&mut state, &last_block[..64]);
        sha1_process_block(&mut state, &last_block[64..128]);
    }

    let mut output = [0u8; 20];
    for (i, word) in state.iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn sha1_process_block(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];

    // Prepare message schedule
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = if i <= 19 {
            ((b & c) | (!b & d), 0x5a827999u32)
        } else if i <= 39 {
            (b ^ c ^ d, 0x6ed9eba1u32)
        } else if i <= 59 {
            ((b & c) | (b & d) | (c & d), 0x8f1bbcdcu32)
        } else {
            (b ^ c ^ d, 0xca62c1d6u32)
        };

        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);

        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            hex.push_str(&format!("{b:02x}"));
        }
        hex
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // -- Test vector structures --

    #[derive(Deserialize)]
    struct Sha256Vector {
        input: String,
        expected: String,
        #[allow(dead_code)]
        source: String,
        #[serde(default)]
        r#type: Option<String>,
    }

    #[derive(Deserialize)]
    struct Sha512Vector {
        input: String,
        expected: String,
        #[allow(dead_code)]
        source: String,
    }

    #[derive(Deserialize)]
    struct Ripemd160Vector {
        input: String,
        expected: String,
        #[allow(dead_code)]
        source: String,
    }

    #[derive(Deserialize)]
    struct HmacVector {
        key: String,
        data: String,
        expected: String,
        #[allow(dead_code)]
        source: String,
        #[allow(dead_code)]
        test_case: u32,
    }

    // -- SHA-256 tests --

    #[test]
    fn test_sha256_empty() {
        let result = sha256(b"");
        assert_eq!(
            bytes_to_hex(&result),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let result = sha256(b"abc");
        assert_eq!(
            bytes_to_hex(&result),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_all_nist_vectors() {
        let data = include_str!("../../test-vectors/sha256.json");
        let vectors: Vec<Sha256Vector> = serde_json::from_str(data).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let is_double = v.r#type.as_deref() == Some("double");
            let input = v.input.as_bytes();
            let result = if is_double {
                sha256d(input)
            } else {
                sha256(input)
            };
            assert_eq!(
                bytes_to_hex(&result),
                v.expected,
                "SHA-256 vector {} failed (type={:?})",
                i,
                v.r#type
            );
        }
    }

    #[test]
    fn test_sha256_long_input() {
        // NIST test: "abcdbcdecdefdefg..." (448 bits = 56 bytes)
        let result = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            bytes_to_hex(&result),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_sha256d_abc() {
        let result = sha256d(b"abc");
        assert_eq!(
            bytes_to_hex(&result),
            "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
        );
    }

    #[test]
    fn test_hash256_is_sha256d() {
        let data = b"test data for hash256";
        assert_eq!(hash256(data), sha256d(data));
    }

    // -- SHA-512 tests --

    #[test]
    fn test_sha512_empty() {
        let result = sha512(b"");
        assert_eq!(
            bytes_to_hex(&result),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn test_sha512_abc() {
        let result = sha512(b"abc");
        assert_eq!(
            bytes_to_hex(&result),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn test_sha512_all_nist_vectors() {
        let data = include_str!("../../test-vectors/sha512.json");
        let vectors: Vec<Sha512Vector> = serde_json::from_str(data).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let result = sha512(v.input.as_bytes());
            assert_eq!(
                bytes_to_hex(&result),
                v.expected,
                "SHA-512 vector {i} failed"
            );
        }
    }

    // -- RIPEMD-160 tests --

    #[test]
    fn test_ripemd160_empty() {
        let result = ripemd160(b"");
        assert_eq!(
            bytes_to_hex(&result),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
    }

    #[test]
    fn test_ripemd160_abc() {
        let result = ripemd160(b"abc");
        assert_eq!(
            bytes_to_hex(&result),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn test_ripemd160_all_spec_vectors() {
        let data = include_str!("../../test-vectors/ripemd160.json");
        let vectors: Vec<Ripemd160Vector> = serde_json::from_str(data).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let result = ripemd160(v.input.as_bytes());
            assert_eq!(
                bytes_to_hex(&result),
                v.expected,
                "RIPEMD-160 vector {} failed (input={:?})",
                i,
                v.input
            );
        }
    }

    // -- hash160 tests --

    #[test]
    fn test_hash160_is_ripemd160_of_sha256() {
        let data = b"test data for hash160";
        let expected = ripemd160(&sha256(data));
        assert_eq!(hash160(data), expected);
    }

    #[test]
    fn test_hash160_empty() {
        let result = hash160(b"");
        let sha_first = sha256(b"");
        let expected = ripemd160(&sha_first);
        assert_eq!(result, expected);
    }

    // -- HMAC-SHA256 tests --

    #[test]
    fn test_hmac_sha256_rfc4231_vectors() {
        let data = include_str!("../../test-vectors/hmac_sha256.json");
        let vectors: Vec<HmacVector> = serde_json::from_str(data).unwrap();

        for v in &vectors {
            let key = hex_to_bytes(&v.key);
            let msg = hex_to_bytes(&v.data);
            let result = sha256_hmac(&key, &msg);
            assert_eq!(
                bytes_to_hex(&result),
                v.expected,
                "HMAC-SHA256 test case {} failed",
                v.test_case
            );
        }
    }

    // -- HMAC-SHA512 tests --

    #[test]
    fn test_hmac_sha512_rfc4231_vectors() {
        let data = include_str!("../../test-vectors/hmac_sha512.json");
        let vectors: Vec<HmacVector> = serde_json::from_str(data).unwrap();

        for v in &vectors {
            let key = hex_to_bytes(&v.key);
            let msg = hex_to_bytes(&v.data);
            let result = sha512_hmac(&key, &msg);
            assert_eq!(
                bytes_to_hex(&result),
                v.expected,
                "HMAC-SHA512 test case {} failed",
                v.test_case
            );
        }
    }

    // -- SHA-1 tests --

    #[test]
    fn test_sha1_empty() {
        let result = sha1(b"");
        assert_eq!(
            bytes_to_hex(&result),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_sha1_abc() {
        let result = sha1(b"abc");
        assert_eq!(
            bytes_to_hex(&result),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn test_sha1_longer_input() {
        let result = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            bytes_to_hex(&result),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn test_sha1_fox() {
        let result = sha1(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            bytes_to_hex(&result),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    // -- PBKDF2-HMAC-SHA512 tests --

    #[derive(Deserialize)]
    struct Pbkdf2Vector {
        password: String,
        salt: String,
        iterations: u32,
        dk_len: usize,
        expected: String,
    }

    #[test]
    fn test_pbkdf2_hmac_sha512_vectors() {
        let data = include_str!("../../test-vectors/pbkdf2_vectors.json");
        let vectors: Vec<Pbkdf2Vector> = serde_json::from_str(data).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let password = hex_to_bytes(&v.password);
            let salt = hex_to_bytes(&v.salt);
            let result = pbkdf2_hmac_sha512(&password, &salt, v.iterations, v.dk_len);
            assert_eq!(
                bytes_to_hex(&result),
                v.expected,
                "PBKDF2 vector {} failed (iterations={}, dk_len={})",
                i,
                v.iterations,
                v.dk_len
            );
        }
    }

    // -- Vector loading tests (preserved from scaffold) --

    #[test]
    fn test_vector_loading() {
        let data = include_str!("../../test-vectors/sha256.json");
        let vectors: Vec<Sha256Vector> = serde_json::from_str(data).unwrap();
        assert!(
            !vectors.is_empty(),
            "SHA256 test vectors should not be empty"
        );
        assert!(vectors.len() >= 4, "Expected at least 4 SHA256 vectors");
    }
}
