use bignum::bignum::BigNum;
use bigcurve::curves::secp192r1::{Secp192r1_Fq, Secp192r1_Fr};
use bigcurve::curves::secp224r1::{Secp224r1_Fq, Secp224r1_Fr};
use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use bigcurve::curves::secp384r1::{Secp384r1_Fq, Secp384r1_Fr};
use bigcurve::curves::secp521r1::{Secp521r1_Fq, Secp521r1_Fr};
use bigcurve::curves::brainpoolP192r1::{BrainpoolP192r1_Fq, BrainpoolP192r1_Fr};
use bigcurve::curves::brainpoolP224r1::{BrainpoolP224r1_Fq, BrainpoolP224r1_Fr};
use bigcurve::curves::brainpoolP256r1::{BrainpoolP256r1_Fq, BrainpoolP256r1_Fr};
use bigcurve::curves::brainpoolP384r1::{BrainpoolP384r1_Fq, BrainpoolP384r1_Fr};
use bigcurve::curves::brainpoolP512r1::{BrainpoolP512r1_Fq, BrainpoolP512r1_Fr};
use ecdsa::ecdsa::{
    verify_secp192r1_ecdsa, verify_secp224r1_ecdsa, verify_secp256r1_ecdsa,
    verify_secp384r1_ecdsa, verify_secp521r1_ecdsa,
    verify_brainpoolp192r1_ecdsa, verify_brainpoolp224r1_ecdsa,
    verify_brainpoolp256r1_ecdsa, verify_brainpoolp384r1_ecdsa,
    verify_brainpoolp512r1_ecdsa,
};

// -- NIST curves --

pub fn verify_nist_p192<let H: u32>(px: [u8; 24], py: [u8; 24], r: [u8; 24], s: [u8; 24], h: [u8; H]) -> bool {
    let px_fq: Secp192r1_Fq = Secp192r1_Fq::from_be_bytes(px);
    let py_fq: Secp192r1_Fq = Secp192r1_Fq::from_be_bytes(py);
    let r_fr: Secp192r1_Fr = Secp192r1_Fr::from_be_bytes(r);
    let s_fr: Secp192r1_Fr = Secp192r1_Fr::from_be_bytes(s);
    verify_secp192r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}

pub fn verify_nist_p224<let H: u32>(px: [u8; 28], py: [u8; 28], r: [u8; 28], s: [u8; 28], h: [u8; H]) -> bool {
    let px_fq: Secp224r1_Fq = Secp224r1_Fq::from_be_bytes(px);
    let py_fq: Secp224r1_Fq = Secp224r1_Fq::from_be_bytes(py);
    let r_fr: Secp224r1_Fr = Secp224r1_Fr::from_be_bytes(r);
    let s_fr: Secp224r1_Fr = Secp224r1_Fr::from_be_bytes(s);
    verify_secp224r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}

pub fn verify_nist_p256<let H: u32>(px: [u8; 32], py: [u8; 32], r: [u8; 32], s: [u8; 32], h: [u8; H]) -> bool {
    let px_fq: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(px);
    let py_fq: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(py);
    let r_fr: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(r);
    let s_fr: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(s);
    verify_secp256r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}

pub fn verify_nist_p384<let H: u32>(px: [u8; 48], py: [u8; 48], r: [u8; 48], s: [u8; 48], h: [u8; H]) -> bool {
    let px_fq: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(px);
    let py_fq: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(py);
    let r_fr: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(r);
    let s_fr: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(s);
    verify_secp384r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}

pub fn verify_nist_p521<let H: u32>(px: [u8; 66], py: [u8; 66], r: [u8; 66], s: [u8; 66], h: [u8; H]) -> bool {
    let px_fq: Secp521r1_Fq = Secp521r1_Fq::from_be_bytes(px);
    let py_fq: Secp521r1_Fq = Secp521r1_Fq::from_be_bytes(py);
    let r_fr: Secp521r1_Fr = Secp521r1_Fr::from_be_bytes(r);
    let s_fr: Secp521r1_Fr = Secp521r1_Fr::from_be_bytes(s);
    verify_secp521r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}

// -- Brainpool curves --

pub fn verify_brainpool_192r1<let H: u32>(px: [u8; 24], py: [u8; 24], r: [u8; 24], s: [u8; 24], h: [u8; H]) -> bool {
    let px_fq: BrainpoolP192r1_Fq = BrainpoolP192r1_Fq::from_be_bytes(px);
    let py_fq: BrainpoolP192r1_Fq = BrainpoolP192r1_Fq::from_be_bytes(py);
    let r_fr: BrainpoolP192r1_Fr = BrainpoolP192r1_Fr::from_be_bytes(r);
    let s_fr: BrainpoolP192r1_Fr = BrainpoolP192r1_Fr::from_be_bytes(s);
    verify_brainpoolp192r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}

pub fn verify_brainpool_224r1<let H: u32>(px: [u8; 28], py: [u8; 28], r: [u8; 28], s: [u8; 28], h: [u8; H]) -> bool {
    let px_fq: BrainpoolP224r1_Fq = BrainpoolP224r1_Fq::from_be_bytes(px);
    let py_fq: BrainpoolP224r1_Fq = BrainpoolP224r1_Fq::from_be_bytes(py);
    let r_fr: BrainpoolP224r1_Fr = BrainpoolP224r1_Fr::from_be_bytes(r);
    let s_fr: BrainpoolP224r1_Fr = BrainpoolP224r1_Fr::from_be_bytes(s);
    verify_brainpoolp224r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}

pub fn verify_brainpool_256r1<let H: u32>(px: [u8; 32], py: [u8; 32], r: [u8; 32], s: [u8; 32], h: [u8; H]) -> bool {
    let px_fq: BrainpoolP256r1_Fq = BrainpoolP256r1_Fq::from_be_bytes(px);
    let py_fq: BrainpoolP256r1_Fq = BrainpoolP256r1_Fq::from_be_bytes(py);
    let r_fr: BrainpoolP256r1_Fr = BrainpoolP256r1_Fr::from_be_bytes(r);
    let s_fr: BrainpoolP256r1_Fr = BrainpoolP256r1_Fr::from_be_bytes(s);
    verify_brainpoolp256r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}

pub fn verify_brainpool_384r1<let H: u32>(px: [u8; 48], py: [u8; 48], r: [u8; 48], s: [u8; 48], h: [u8; H]) -> bool {
    let px_fq: BrainpoolP384r1_Fq = BrainpoolP384r1_Fq::from_be_bytes(px);
    let py_fq: BrainpoolP384r1_Fq = BrainpoolP384r1_Fq::from_be_bytes(py);
    let r_fr: BrainpoolP384r1_Fr = BrainpoolP384r1_Fr::from_be_bytes(r);
    let s_fr: BrainpoolP384r1_Fr = BrainpoolP384r1_Fr::from_be_bytes(s);
    verify_brainpoolp384r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}

pub fn verify_brainpool_512r1<let H: u32>(px: [u8; 64], py: [u8; 64], r: [u8; 64], s: [u8; 64], h: [u8; H]) -> bool {
    let px_fq: BrainpoolP512r1_Fq = BrainpoolP512r1_Fq::from_be_bytes(px);
    let py_fq: BrainpoolP512r1_Fq = BrainpoolP512r1_Fq::from_be_bytes(py);
    let r_fr: BrainpoolP512r1_Fr = BrainpoolP512r1_Fr::from_be_bytes(r);
    let s_fr: BrainpoolP512r1_Fr = BrainpoolP512r1_Fr::from_be_bytes(s);
    verify_brainpoolp512r1_ecdsa(px_fq, py_fq, h, (r_fr, s_fr))
}
