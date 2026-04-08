use bignum::bignum::BigNum;
use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use bigcurve::curves::secp384r1::{Secp384r1_Fq, Secp384r1_Fr};
use bigcurve::curves::secp521r1::{Secp521r1_Fq, Secp521r1_Fr};
use ecdsa::ecdsa::{verify_secp256r1_ecdsa, verify_secp384r1_ecdsa, verify_secp521r1_ecdsa};
use hash_multiplex::compute_digest;

/// Unified ECDSA signature verifier supporting NIST P-256/P-384/P-521 curves
/// with SHA-1/256/384/512 hash algorithms.
///
/// All curve x hash branches compile into the constraint system.
/// Only the selected branch produces the actual verification result.
///
/// Inputs are padded to maximum coordinate size (P-521 = 66 bytes):
///   pub_x / pub_y: [u8; 66]
///   sig_r / sig_s:  [u8; 66]
///   data:           [u8; 1200] (max TBS / signed-attrs size)
///
/// Selectors:
///   curve_type: 0 = P-256, 1 = P-384, 2 = P-521
///   hash_type:  0 = SHA-1, 1 = SHA-256, 2 = SHA-384, 3 = SHA-512
pub fn verify_ecdsa_signature(
    pub_x: [u8; 66],
    pub_y: [u8; 66],
    sig_r: [u8; 66],
    sig_s: [u8; 66],
    data: [u8; 1200],
    data_len: u32,
    curve_type: u8,
    hash_type: u8,
) -> bool {
    let digest = compute_digest(data, data_len, hash_type);

    let mut h20: [u8; 20] = [0; 20];
    for i in 0..20 { h20[i] = digest.bytes[i]; }
    let mut h32: [u8; 32] = [0; 32];
    for i in 0..32 { h32[i] = digest.bytes[i]; }
    let mut h48: [u8; 48] = [0; 48];
    for i in 0..48 { h48[i] = digest.bytes[i]; }
    let h64 = digest.bytes;

    let mut verified = false;

    if curve_type == 0 {
        verified = verify_p256(pub_x, pub_y, sig_r, sig_s, h20, h32, h48, h64, hash_type);
    } else if curve_type == 1 {
        verified = verify_p384(pub_x, pub_y, sig_r, sig_s, h20, h32, h48, h64, hash_type);
    } else {
        verified = verify_p521(pub_x, pub_y, sig_r, sig_s, h20, h32, h48, h64, hash_type);
    }

    verified
}

fn verify_p256(
    pub_x: [u8; 66], pub_y: [u8; 66], sig_r: [u8; 66], sig_s: [u8; 66],
    h20: [u8; 20], h32: [u8; 32], h48: [u8; 48], h64: [u8; 64],
    hash_type: u8,
) -> bool {
    let mut px: [u8; 32] = [0; 32];
    let mut py: [u8; 32] = [0; 32];
    let mut r: [u8; 32] = [0; 32];
    let mut s: [u8; 32] = [0; 32];
    for i in 0..32 {
        px[i] = pub_x[i];
        py[i] = pub_y[i];
        r[i] = sig_r[i];
        s[i] = sig_s[i];
    }

    let px_fq: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(px);
    let py_fq: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(py);
    let r_fr: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(r);
    let s_fr: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(s);

    let mut verified = false;
    if hash_type == 0 { verified = verify_secp256r1_ecdsa(px_fq, py_fq, h20, (r_fr, s_fr)); }
    else if hash_type == 1 { verified = verify_secp256r1_ecdsa(px_fq, py_fq, h32, (r_fr, s_fr)); }
    else if hash_type == 2 { verified = verify_secp256r1_ecdsa(px_fq, py_fq, h48, (r_fr, s_fr)); }
    else { verified = verify_secp256r1_ecdsa(px_fq, py_fq, h64, (r_fr, s_fr)); }
    verified
}

fn verify_p384(
    pub_x: [u8; 66], pub_y: [u8; 66], sig_r: [u8; 66], sig_s: [u8; 66],
    h20: [u8; 20], h32: [u8; 32], h48: [u8; 48], h64: [u8; 64],
    hash_type: u8,
) -> bool {
    let mut px: [u8; 48] = [0; 48];
    let mut py: [u8; 48] = [0; 48];
    let mut r: [u8; 48] = [0; 48];
    let mut s: [u8; 48] = [0; 48];
    for i in 0..48 {
        px[i] = pub_x[i];
        py[i] = pub_y[i];
        r[i] = sig_r[i];
        s[i] = sig_s[i];
    }

    let px_fq: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(px);
    let py_fq: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(py);
    let r_fr: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(r);
    let s_fr: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(s);

    let mut verified = false;
    if hash_type == 0 { verified = verify_secp384r1_ecdsa(px_fq, py_fq, h20, (r_fr, s_fr)); }
    else if hash_type == 1 { verified = verify_secp384r1_ecdsa(px_fq, py_fq, h32, (r_fr, s_fr)); }
    else if hash_type == 2 { verified = verify_secp384r1_ecdsa(px_fq, py_fq, h48, (r_fr, s_fr)); }
    else { verified = verify_secp384r1_ecdsa(px_fq, py_fq, h64, (r_fr, s_fr)); }
    verified
}

fn verify_p521(
    pub_x: [u8; 66], pub_y: [u8; 66], sig_r: [u8; 66], sig_s: [u8; 66],
    h20: [u8; 20], h32: [u8; 32], h48: [u8; 48], h64: [u8; 64],
    hash_type: u8,
) -> bool {
    let px_fq: Secp521r1_Fq = Secp521r1_Fq::from_be_bytes(pub_x);
    let py_fq: Secp521r1_Fq = Secp521r1_Fq::from_be_bytes(pub_y);
    let r_fr: Secp521r1_Fr = Secp521r1_Fr::from_be_bytes(sig_r);
    let s_fr: Secp521r1_Fr = Secp521r1_Fr::from_be_bytes(sig_s);

    let mut verified = false;
    if hash_type == 0 { verified = verify_secp521r1_ecdsa(px_fq, py_fq, h20, (r_fr, s_fr)); }
    else if hash_type == 1 { verified = verify_secp521r1_ecdsa(px_fq, py_fq, h32, (r_fr, s_fr)); }
    else if hash_type == 2 { verified = verify_secp521r1_ecdsa(px_fq, py_fq, h48, (r_fr, s_fr)); }
    else { verified = verify_secp521r1_ecdsa(px_fq, py_fq, h64, (r_fr, s_fr)); }
    verified
}
