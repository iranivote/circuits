// Pure-Noir SHA-1 implementation with variable-length input support.
// SHA-1 has no blackbox opcode in Noir, so compression is done in constraints.

fn w_add(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) & 0xFFFFFFFF) as u32
}

fn rotl1(x: u32) -> u32 {
    (((x as u64) << 1) | ((x as u64) >> 31) & 0xFFFFFFFF) as u32
}

fn rotl5(x: u32) -> u32 {
    (((x as u64) << 5) | ((x as u64) >> 27) & 0xFFFFFFFF) as u32
}

fn rotl30(x: u32) -> u32 {
    (((x as u64) << 30) | ((x as u64) >> 2) & 0xFFFFFFFF) as u32
}

fn sha1_compress(state: [u32; 5], block: [u32; 16]) -> [u32; 5] {
    let mut w: [u32; 80] = [0; 80];
    for i in 0..16 {
        w[i] = block[i];
    }
    for i in 16..80 {
        w[i] = rotl1(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    // Rounds 0-19: Ch(b, c, d) = (b & c) | (~b & d)
    for i in 0..20 {
        let f: u32 = (b & c) | ((b ^ 0xFFFFFFFF) & d);
        let temp = w_add(w_add(w_add(w_add(rotl5(a), f), e), 0x5A827999), w[i]);
        e = d;
        d = c;
        c = rotl30(b);
        b = a;
        a = temp;
    }

    // Rounds 20-39: Parity(b, c, d) = b ^ c ^ d
    for _r in 0..20 {
        let i = _r + 20;
        let f: u32 = b ^ c ^ d;
        let temp = w_add(w_add(w_add(w_add(rotl5(a), f), e), 0x6ED9EBA1), w[i]);
        e = d;
        d = c;
        c = rotl30(b);
        b = a;
        a = temp;
    }

    // Rounds 40-59: Maj(b, c, d) = (b & c) | (b & d) | (c & d)
    for _r in 0..20 {
        let i = _r + 40;
        let f: u32 = (b & c) | (b & d) | (c & d);
        let temp = w_add(w_add(w_add(w_add(rotl5(a), f), e), 0x8F1BBCDC), w[i]);
        e = d;
        d = c;
        c = rotl30(b);
        b = a;
        a = temp;
    }

    // Rounds 60-79: Parity again
    for _r in 0..20 {
        let i = _r + 60;
        let f: u32 = b ^ c ^ d;
        let temp = w_add(w_add(w_add(w_add(rotl5(a), f), e), 0xCA62C1D6), w[i]);
        e = d;
        d = c;
        c = rotl30(b);
        b = a;
        a = temp;
    }

    [
        w_add(state[0], a),
        w_add(state[1], b),
        w_add(state[2], c),
        w_add(state[3], d),
        w_add(state[4], e),
    ]
}

/// SHA-1 hash of `msg[0..message_size]`. Buffer `msg` is `[u8; N]`; bytes
/// beyond `message_size` are ignored. Handles padding internally.
pub fn sha1_var<let N: u32>(msg: [u8; N], message_size: u32) -> [u8; 20] {
    assert(message_size <= N);

    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Number of 64-byte blocks in the padded message (compile-time upper bound)
    let num_blocks: u32 = (message_size + 72) / 64;
    let len_bits: u64 = (message_size as u64) * 8;
    let len_hi: u32 = ((len_bits >> 32) & 0xFFFFFFFF) as u32;
    let len_lo: u32 = (len_bits & 0xFFFFFFFF) as u32;

    for block_idx in 0..((N + 72) / 64) {
        let block_start: u32 = block_idx * 64;
        let mut block: [u32; 16] = [0; 16];

        for w in 0..16 {
            let mut word: u32 = 0;
            for b in 0..4 {
                let pos: u32 = block_start + w * 4 + b;
                // Clamp index to valid range so the array read never faults
                let safe_idx: u32 = if pos < N { pos } else { 0 };
                let raw: u32 = msg[safe_idx] as u32;
                let byte_val: u32 = if pos < message_size {
                    raw
                } else if pos == message_size {
                    0x80
                } else {
                    0
                };
                word = word * 256 + byte_val;
            }
            block[w] = word;
        }

        // Write 64-bit message length into the last two words of the final block
        block[14] = if (block_idx + 1) == num_blocks { len_hi } else { block[14] };
        block[15] = if (block_idx + 1) == num_blocks { len_lo } else { block[15] };

        h = if block_idx < num_blocks { sha1_compress(h, block) } else { h };
    }

    let mut result: [u8; 20] = [0; 20];
    for i in 0..5 {
        let bytes: [u8; 4] = (h[i] as Field).to_be_bytes();
        result[4 * i] = bytes[0];
        result[4 * i + 1] = bytes[1];
        result[4 * i + 2] = bytes[2];
        result[4 * i + 3] = bytes[3];
    }
    result
}

#[test]
fn test_sha1_abc() {
    let msg: [u8; 3] = [0x61, 0x62, 0x63]; // "abc"
    let hash = sha1_var(msg, 3);
    let expected: [u8; 20] = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    ];
    assert(hash == expected);
}

#[test]
fn test_sha1_empty_padded_buffer() {
    let msg: [u8; 64] = [0; 64];
    let hash = sha1_var(msg, 0);
    // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
    let expected: [u8; 20] = [
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
        0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
    ];
    assert(hash == expected);
}
