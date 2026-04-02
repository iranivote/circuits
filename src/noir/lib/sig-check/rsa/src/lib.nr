use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::rsa::{
    verify_sha1_pkcs1v15, verify_sha1_pss,
    verify_sha256_pkcs1v15, verify_sha256_pss,
    verify_sha384_pkcs1v15, verify_sha384_pss,
    verify_sha512_pkcs1v15, verify_sha512_pss,
};
use common::{
    sha1_and_check_data_to_sign,
    sha256_and_check_data_to_sign,
    sha384_and_check_data_to_sign,
    sha512_and_check_data_to_sign,
};

// -- RSA-1024 (128 byte modulus, 9 limbs) --

pub fn verify_rsa1024_sha1_pkcs<let D: u32>(pk: [u8; 128], sig: [u8; 128], rp: [u8; 129], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 9] = utils::pack_be_bytes_into_u128s::<128, 9, 15>(pk);
    let redc: [u128; 9] = utils::pack_be_bytes_into_u128s::<129, 9, 15>(rp);
    let params: BigNumParams<9, 1024> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha1_and_check_data_to_sign(d, dl);
    verify_sha1_pkcs1v15::<9, 1024>(h, signature, e)
}
pub fn verify_rsa1024_sha256_pkcs<let D: u32>(pk: [u8; 128], sig: [u8; 128], rp: [u8; 129], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 9] = utils::pack_be_bytes_into_u128s::<128, 9, 15>(pk);
    let redc: [u128; 9] = utils::pack_be_bytes_into_u128s::<129, 9, 15>(rp);
    let params: BigNumParams<9, 1024> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha256_and_check_data_to_sign(d, dl);
    verify_sha256_pkcs1v15::<9, 1024>(h, signature, e)
}
pub fn verify_rsa1024_sha384_pkcs<let D: u32>(pk: [u8; 128], sig: [u8; 128], rp: [u8; 129], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 9] = utils::pack_be_bytes_into_u128s::<128, 9, 15>(pk);
    let redc: [u128; 9] = utils::pack_be_bytes_into_u128s::<129, 9, 15>(rp);
    let params: BigNumParams<9, 1024> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha384_and_check_data_to_sign(d, dl);
    verify_sha384_pkcs1v15::<9, 1024>(h, signature, e)
}
pub fn verify_rsa1024_sha512_pkcs<let D: u32>(pk: [u8; 128], sig: [u8; 128], rp: [u8; 129], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 9] = utils::pack_be_bytes_into_u128s::<128, 9, 15>(pk);
    let redc: [u128; 9] = utils::pack_be_bytes_into_u128s::<129, 9, 15>(rp);
    let params: BigNumParams<9, 1024> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha512_and_check_data_to_sign(d, dl);
    verify_sha512_pkcs1v15::<9, 1024>(h, signature, e)
}

pub fn verify_rsa1024_sha1_pss<let D: u32>(pk: [u8; 128], sig: [u8; 128], rp: [u8; 129], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 9] = utils::pack_be_bytes_into_u128s::<128, 9, 15>(pk);
    let redc: [u128; 9] = utils::pack_be_bytes_into_u128s::<129, 9, 15>(rp);
    let params: BigNumParams<9, 1024> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha1_and_check_data_to_sign(d, dl);
    verify_sha1_pss::<9, 1024>(h, signature, e, sl)
}
pub fn verify_rsa1024_sha256_pss<let D: u32>(pk: [u8; 128], sig: [u8; 128], rp: [u8; 129], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 9] = utils::pack_be_bytes_into_u128s::<128, 9, 15>(pk);
    let redc: [u128; 9] = utils::pack_be_bytes_into_u128s::<129, 9, 15>(rp);
    let params: BigNumParams<9, 1024> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha256_and_check_data_to_sign(d, dl);
    verify_sha256_pss::<9, 1024>(h, signature, e, sl)
}
pub fn verify_rsa1024_sha384_pss<let D: u32>(pk: [u8; 128], sig: [u8; 128], rp: [u8; 129], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 9] = utils::pack_be_bytes_into_u128s::<128, 9, 15>(pk);
    let redc: [u128; 9] = utils::pack_be_bytes_into_u128s::<129, 9, 15>(rp);
    let params: BigNumParams<9, 1024> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha384_and_check_data_to_sign(d, dl);
    verify_sha384_pss::<9, 1024>(h, signature, e, sl)
}
pub fn verify_rsa1024_sha512_pss<let D: u32>(pk: [u8; 128], sig: [u8; 128], rp: [u8; 129], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 9] = utils::pack_be_bytes_into_u128s::<128, 9, 15>(pk);
    let redc: [u128; 9] = utils::pack_be_bytes_into_u128s::<129, 9, 15>(rp);
    let params: BigNumParams<9, 1024> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha512_and_check_data_to_sign(d, dl);
    verify_sha512_pss::<9, 1024>(h, signature, e, sl)
}

// -- RSA-2048 (256 byte modulus, 18 limbs) --

pub fn verify_rsa2048_sha1_pkcs<let D: u32>(pk: [u8; 256], sig: [u8; 256], rp: [u8; 257], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 18] = utils::pack_be_bytes_into_u128s::<256, 18, 15>(pk);
    let redc: [u128; 18] = utils::pack_be_bytes_into_u128s::<257, 18, 15>(rp);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha1_and_check_data_to_sign(d, dl);
    verify_sha1_pkcs1v15::<18, 2048>(h, signature, e)
}
pub fn verify_rsa2048_sha256_pkcs<let D: u32>(pk: [u8; 256], sig: [u8; 256], rp: [u8; 257], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 18] = utils::pack_be_bytes_into_u128s::<256, 18, 15>(pk);
    let redc: [u128; 18] = utils::pack_be_bytes_into_u128s::<257, 18, 15>(rp);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha256_and_check_data_to_sign(d, dl);
    verify_sha256_pkcs1v15::<18, 2048>(h, signature, e)
}
pub fn verify_rsa2048_sha384_pkcs<let D: u32>(pk: [u8; 256], sig: [u8; 256], rp: [u8; 257], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 18] = utils::pack_be_bytes_into_u128s::<256, 18, 15>(pk);
    let redc: [u128; 18] = utils::pack_be_bytes_into_u128s::<257, 18, 15>(rp);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha384_and_check_data_to_sign(d, dl);
    verify_sha384_pkcs1v15::<18, 2048>(h, signature, e)
}
pub fn verify_rsa2048_sha512_pkcs<let D: u32>(pk: [u8; 256], sig: [u8; 256], rp: [u8; 257], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 18] = utils::pack_be_bytes_into_u128s::<256, 18, 15>(pk);
    let redc: [u128; 18] = utils::pack_be_bytes_into_u128s::<257, 18, 15>(rp);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha512_and_check_data_to_sign(d, dl);
    verify_sha512_pkcs1v15::<18, 2048>(h, signature, e)
}

pub fn verify_rsa2048_sha1_pss<let D: u32>(pk: [u8; 256], sig: [u8; 256], rp: [u8; 257], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 18] = utils::pack_be_bytes_into_u128s::<256, 18, 15>(pk);
    let redc: [u128; 18] = utils::pack_be_bytes_into_u128s::<257, 18, 15>(rp);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha1_and_check_data_to_sign(d, dl);
    verify_sha1_pss::<18, 2048>(h, signature, e, sl)
}
pub fn verify_rsa2048_sha256_pss<let D: u32>(pk: [u8; 256], sig: [u8; 256], rp: [u8; 257], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 18] = utils::pack_be_bytes_into_u128s::<256, 18, 15>(pk);
    let redc: [u128; 18] = utils::pack_be_bytes_into_u128s::<257, 18, 15>(rp);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha256_and_check_data_to_sign(d, dl);
    verify_sha256_pss::<18, 2048>(h, signature, e, sl)
}
pub fn verify_rsa2048_sha384_pss<let D: u32>(pk: [u8; 256], sig: [u8; 256], rp: [u8; 257], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 18] = utils::pack_be_bytes_into_u128s::<256, 18, 15>(pk);
    let redc: [u128; 18] = utils::pack_be_bytes_into_u128s::<257, 18, 15>(rp);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha384_and_check_data_to_sign(d, dl);
    verify_sha384_pss::<18, 2048>(h, signature, e, sl)
}
pub fn verify_rsa2048_sha512_pss<let D: u32>(pk: [u8; 256], sig: [u8; 256], rp: [u8; 257], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 18] = utils::pack_be_bytes_into_u128s::<256, 18, 15>(pk);
    let redc: [u128; 18] = utils::pack_be_bytes_into_u128s::<257, 18, 15>(rp);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha512_and_check_data_to_sign(d, dl);
    verify_sha512_pss::<18, 2048>(h, signature, e, sl)
}

// -- RSA-3072 (384 byte modulus, 26 limbs) --

pub fn verify_rsa3072_sha1_pkcs<let D: u32>(pk: [u8; 384], sig: [u8; 384], rp: [u8; 385], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 26] = utils::pack_be_bytes_into_u128s::<384, 26, 15>(pk);
    let redc: [u128; 26] = utils::pack_be_bytes_into_u128s::<385, 26, 15>(rp);
    let params: BigNumParams<26, 3072> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<26, 3072> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha1_and_check_data_to_sign(d, dl);
    verify_sha1_pkcs1v15::<26, 3072>(h, signature, e)
}
pub fn verify_rsa3072_sha256_pkcs<let D: u32>(pk: [u8; 384], sig: [u8; 384], rp: [u8; 385], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 26] = utils::pack_be_bytes_into_u128s::<384, 26, 15>(pk);
    let redc: [u128; 26] = utils::pack_be_bytes_into_u128s::<385, 26, 15>(rp);
    let params: BigNumParams<26, 3072> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<26, 3072> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha256_and_check_data_to_sign(d, dl);
    verify_sha256_pkcs1v15::<26, 3072>(h, signature, e)
}
pub fn verify_rsa3072_sha384_pkcs<let D: u32>(pk: [u8; 384], sig: [u8; 384], rp: [u8; 385], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 26] = utils::pack_be_bytes_into_u128s::<384, 26, 15>(pk);
    let redc: [u128; 26] = utils::pack_be_bytes_into_u128s::<385, 26, 15>(rp);
    let params: BigNumParams<26, 3072> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<26, 3072> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha384_and_check_data_to_sign(d, dl);
    verify_sha384_pkcs1v15::<26, 3072>(h, signature, e)
}
pub fn verify_rsa3072_sha512_pkcs<let D: u32>(pk: [u8; 384], sig: [u8; 384], rp: [u8; 385], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 26] = utils::pack_be_bytes_into_u128s::<384, 26, 15>(pk);
    let redc: [u128; 26] = utils::pack_be_bytes_into_u128s::<385, 26, 15>(rp);
    let params: BigNumParams<26, 3072> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<26, 3072> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha512_and_check_data_to_sign(d, dl);
    verify_sha512_pkcs1v15::<26, 3072>(h, signature, e)
}

pub fn verify_rsa3072_sha1_pss<let D: u32>(pk: [u8; 384], sig: [u8; 384], rp: [u8; 385], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 26] = utils::pack_be_bytes_into_u128s::<384, 26, 15>(pk);
    let redc: [u128; 26] = utils::pack_be_bytes_into_u128s::<385, 26, 15>(rp);
    let params: BigNumParams<26, 3072> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<26, 3072> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha1_and_check_data_to_sign(d, dl);
    verify_sha1_pss::<26, 3072>(h, signature, e, sl)
}
pub fn verify_rsa3072_sha256_pss<let D: u32>(pk: [u8; 384], sig: [u8; 384], rp: [u8; 385], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 26] = utils::pack_be_bytes_into_u128s::<384, 26, 15>(pk);
    let redc: [u128; 26] = utils::pack_be_bytes_into_u128s::<385, 26, 15>(rp);
    let params: BigNumParams<26, 3072> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<26, 3072> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha256_and_check_data_to_sign(d, dl);
    verify_sha256_pss::<26, 3072>(h, signature, e, sl)
}
pub fn verify_rsa3072_sha384_pss<let D: u32>(pk: [u8; 384], sig: [u8; 384], rp: [u8; 385], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 26] = utils::pack_be_bytes_into_u128s::<384, 26, 15>(pk);
    let redc: [u128; 26] = utils::pack_be_bytes_into_u128s::<385, 26, 15>(rp);
    let params: BigNumParams<26, 3072> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<26, 3072> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha384_and_check_data_to_sign(d, dl);
    verify_sha384_pss::<26, 3072>(h, signature, e, sl)
}
pub fn verify_rsa3072_sha512_pss<let D: u32>(pk: [u8; 384], sig: [u8; 384], rp: [u8; 385], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 26] = utils::pack_be_bytes_into_u128s::<384, 26, 15>(pk);
    let redc: [u128; 26] = utils::pack_be_bytes_into_u128s::<385, 26, 15>(rp);
    let params: BigNumParams<26, 3072> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<26, 3072> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha512_and_check_data_to_sign(d, dl);
    verify_sha512_pss::<26, 3072>(h, signature, e, sl)
}

// -- RSA-4096 (512 byte modulus, 35 limbs) --

pub fn verify_rsa4096_sha1_pkcs<let D: u32>(pk: [u8; 512], sig: [u8; 512], rp: [u8; 513], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 35] = utils::pack_be_bytes_into_u128s::<512, 35, 15>(pk);
    let redc: [u128; 35] = utils::pack_be_bytes_into_u128s::<513, 35, 15>(rp);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha1_and_check_data_to_sign(d, dl);
    verify_sha1_pkcs1v15::<35, 4096>(h, signature, e)
}
pub fn verify_rsa4096_sha256_pkcs<let D: u32>(pk: [u8; 512], sig: [u8; 512], rp: [u8; 513], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 35] = utils::pack_be_bytes_into_u128s::<512, 35, 15>(pk);
    let redc: [u128; 35] = utils::pack_be_bytes_into_u128s::<513, 35, 15>(rp);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha256_and_check_data_to_sign(d, dl);
    verify_sha256_pkcs1v15::<35, 4096>(h, signature, e)
}
pub fn verify_rsa4096_sha384_pkcs<let D: u32>(pk: [u8; 512], sig: [u8; 512], rp: [u8; 513], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 35] = utils::pack_be_bytes_into_u128s::<512, 35, 15>(pk);
    let redc: [u128; 35] = utils::pack_be_bytes_into_u128s::<513, 35, 15>(rp);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha384_and_check_data_to_sign(d, dl);
    verify_sha384_pkcs1v15::<35, 4096>(h, signature, e)
}
pub fn verify_rsa4096_sha512_pkcs<let D: u32>(pk: [u8; 512], sig: [u8; 512], rp: [u8; 513], e: u32, d: [u8; D], dl: u32) -> bool {
    let pubkey: [u128; 35] = utils::pack_be_bytes_into_u128s::<512, 35, 15>(pk);
    let redc: [u128; 35] = utils::pack_be_bytes_into_u128s::<513, 35, 15>(rp);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha512_and_check_data_to_sign(d, dl);
    verify_sha512_pkcs1v15::<35, 4096>(h, signature, e)
}

pub fn verify_rsa4096_sha1_pss<let D: u32>(pk: [u8; 512], sig: [u8; 512], rp: [u8; 513], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 35] = utils::pack_be_bytes_into_u128s::<512, 35, 15>(pk);
    let redc: [u128; 35] = utils::pack_be_bytes_into_u128s::<513, 35, 15>(rp);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha1_and_check_data_to_sign(d, dl);
    verify_sha1_pss::<35, 4096>(h, signature, e, sl)
}
pub fn verify_rsa4096_sha256_pss<let D: u32>(pk: [u8; 512], sig: [u8; 512], rp: [u8; 513], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 35] = utils::pack_be_bytes_into_u128s::<512, 35, 15>(pk);
    let redc: [u128; 35] = utils::pack_be_bytes_into_u128s::<513, 35, 15>(rp);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha256_and_check_data_to_sign(d, dl);
    verify_sha256_pss::<35, 4096>(h, signature, e, sl)
}
pub fn verify_rsa4096_sha384_pss<let D: u32>(pk: [u8; 512], sig: [u8; 512], rp: [u8; 513], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 35] = utils::pack_be_bytes_into_u128s::<512, 35, 15>(pk);
    let redc: [u128; 35] = utils::pack_be_bytes_into_u128s::<513, 35, 15>(rp);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha384_and_check_data_to_sign(d, dl);
    verify_sha384_pss::<35, 4096>(h, signature, e, sl)
}
pub fn verify_rsa4096_sha512_pss<let D: u32>(pk: [u8; 512], sig: [u8; 512], rp: [u8; 513], e: u32, d: [u8; D], dl: u32, sl: u32) -> bool {
    let pubkey: [u128; 35] = utils::pack_be_bytes_into_u128s::<512, 35, 15>(pk);
    let redc: [u128; 35] = utils::pack_be_bytes_into_u128s::<513, 35, 15>(rp);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, pubkey, redc);
    let signature: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, sig);
    let h = sha512_and_check_data_to_sign(d, dl);
    verify_sha512_pss::<35, 4096>(h, signature, e, sl)
}
