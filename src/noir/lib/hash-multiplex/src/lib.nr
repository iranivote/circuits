use sha1::sha1;
use sha256::sha256_var;
use sha512::{sha384, sha512};

pub global MAX_DIGEST_LEN: u32 = 64;

pub struct DigestResult {
    pub bytes: [u8; MAX_DIGEST_LEN],
    pub len: u32,
}

/// Compute a cryptographic hash of `data[0..data_len]` using the algorithm
/// selected by `hash_type`:
///   0 = SHA-1   (20 bytes)
///   1 = SHA-256  (32 bytes)
///   2 = SHA-384  (48 bytes)
///   3 = SHA-512  (64 bytes)
///
/// Returns a 64-byte buffer (zero-padded) and the actual digest length.
/// All four hash branches compile into the constraint system; only the
/// selected one produces the meaningful digest.
pub fn compute_digest<let N: u32>(data: [u8; N], data_len: u32, hash_type: u8) -> DigestResult {
    assert(hash_type <= 3, "Invalid hash_type: must be 0..3");
    let mut result = DigestResult { bytes: [0u8; MAX_DIGEST_LEN], len: 0 };

    if hash_type == 0 {
        let bounded = BoundedVec::from_parts(data, data_len);
        let h: [u8; 20] = sha1::sha1_var(bounded);
        for i in 0..20 {
            result.bytes[i] = h[i];
        }
        result.len = 20;
    } else if hash_type == 1 {
        let h: [u8; 32] = sha256_var(data, data_len);
        for i in 0..32 {
            result.bytes[i] = h[i];
        }
        result.len = 32;
    } else if hash_type == 2 {
        let bounded = BoundedVec::from_parts(data, data_len);
        let h: [u8; 48] = sha384::sha384_var(bounded);
        for i in 0..48 {
            result.bytes[i] = h[i];
        }
        result.len = 48;
    } else {
        let bounded = BoundedVec::from_parts(data, data_len);
        let h: [u8; 64] = sha512::sha512_var(bounded);
        for i in 0..64 {
            result.bytes[i] = h[i];
        }
        result.len = 64;
    }

    result
}
