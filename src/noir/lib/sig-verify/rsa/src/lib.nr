use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::rsa::{
    verify_sha1_pkcs1v15, verify_sha1_pss,
    verify_sha256_pkcs1v15, verify_sha256_pss,
    verify_sha384_pkcs1v15, verify_sha384_pss,
    verify_sha512_pkcs1v15, verify_sha512_pss,
};
use hash_multiplex::compute_digest;

/// Unified RSA signature verifier supporting RSA-2048/3072/4096 with
/// PKCS#1 v1.5 and PSS padding, and SHA-1/256/384/512 hash algorithms.
///
/// All key-size x hash x padding branches compile into the constraint system.
/// Only the selected branch produces the actual verification result.
///
/// Inputs are padded to maximum sizes:
///   pubkey / signature: [u8; 512]  (RSA-4096 max)
///   redc_param:         [u8; 513]
///   data:               [u8; 1200] (max TBS size)
///
/// Selectors:
///   key_size:     0 = RSA-2048, 1 = RSA-3072, 2 = RSA-4096
///   hash_type:    0 = SHA-1, 1 = SHA-256, 2 = SHA-384, 3 = SHA-512
///   padding_type: 0 = PKCS#1 v1.5, 1 = PSS
pub fn verify_rsa_signature(
    pubkey: [u8; 512],
    signature: [u8; 512],
    redc_param: [u8; 513],
    exponent: u32,
    data: [u8; 1200],
    data_len: u32,
    key_size: u8,
    hash_type: u8,
    padding_type: u8,
    pss_salt_len: u32,
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

    if key_size == 0 {
        verified = verify_rsa2048(pubkey, signature, redc_param, exponent, h20, h32, h48, h64, hash_type, padding_type, pss_salt_len);
    } else if key_size == 1 {
        verified = verify_rsa3072(pubkey, signature, redc_param, exponent, h20, h32, h48, h64, hash_type, padding_type, pss_salt_len);
    } else {
        verified = verify_rsa4096(pubkey, signature, redc_param, exponent, h20, h32, h48, h64, hash_type, padding_type, pss_salt_len);
    }

    verified
}

fn verify_rsa2048(
    pubkey: [u8; 512], signature: [u8; 512], redc_param: [u8; 513], exponent: u32,
    h20: [u8; 20], h32: [u8; 32], h48: [u8; 48], h64: [u8; 64],
    hash_type: u8, padding_type: u8, pss_salt_len: u32,
) -> bool {
    let mut pk: [u8; 256] = [0; 256];
    for i in 0..256 { pk[i] = pubkey[i]; }
    let mut sig: [u8; 256] = [0; 256];
    for i in 0..256 { sig[i] = signature[i]; }
    let mut rp: [u8; 257] = [0; 257];
    for i in 0..257 { rp[i] = redc_param[i]; }

    let pk_u128: [u128; 18] = utils::pack_be_bytes_into_u128s::<256, 18, 15>(pk);
    let rp_u128: [u128; 18] = utils::pack_be_bytes_into_u128s::<257, 18, 15>(rp);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pk_u128, rp_u128);
    let sig_bn: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_be_bytes(params, sig);

    dispatch_hash_padding(h20, h32, h48, h64, sig_bn, exponent, hash_type, padding_type, pss_salt_len)
}

fn verify_rsa3072(
    pubkey: [u8; 512], signature: [u8; 512], redc_param: [u8; 513], exponent: u32,
    h20: [u8; 20], h32: [u8; 32], h48: [u8; 48], h64: [u8; 64],
    hash_type: u8, padding_type: u8, pss_salt_len: u32,
) -> bool {
    let mut pk: [u8; 384] = [0; 384];
    for i in 0..384 { pk[i] = pubkey[i]; }
    let mut sig: [u8; 384] = [0; 384];
    for i in 0..384 { sig[i] = signature[i]; }
    let mut rp: [u8; 385] = [0; 385];
    for i in 0..385 { rp[i] = redc_param[i]; }

    let pk_u128: [u128; 26] = utils::pack_be_bytes_into_u128s::<384, 26, 15>(pk);
    let rp_u128: [u128; 26] = utils::pack_be_bytes_into_u128s::<385, 26, 15>(rp);
    let params: BigNumParams<26, 3072> = BigNumParams::new(false, pk_u128, rp_u128);
    let sig_bn: RuntimeBigNum<26, 3072> = RuntimeBigNum::from_be_bytes(params, sig);

    dispatch_hash_padding(h20, h32, h48, h64, sig_bn, exponent, hash_type, padding_type, pss_salt_len)
}

fn verify_rsa4096(
    pubkey: [u8; 512], signature: [u8; 512], redc_param: [u8; 513], exponent: u32,
    h20: [u8; 20], h32: [u8; 32], h48: [u8; 48], h64: [u8; 64],
    hash_type: u8, padding_type: u8, pss_salt_len: u32,
) -> bool {
    let pk_u128: [u128; 35] = utils::pack_be_bytes_into_u128s::<512, 35, 15>(pubkey);
    let rp_u128: [u128; 35] = utils::pack_be_bytes_into_u128s::<513, 35, 15>(redc_param);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, pk_u128, rp_u128);
    let sig_bn: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, signature);

    dispatch_hash_padding(h20, h32, h48, h64, sig_bn, exponent, hash_type, padding_type, pss_salt_len)
}

fn dispatch_hash_padding<let N: u32, let MOD: u32>(
    h20: [u8; 20], h32: [u8; 32], h48: [u8; 48], h64: [u8; 64],
    sig_bn: RuntimeBigNum<N, MOD>, exponent: u32,
    hash_type: u8, padding_type: u8, pss_salt_len: u32,
) -> bool {
    let mut verified = false;

    if hash_type == 0 {
        if padding_type == 0 { verified = verify_sha1_pkcs1v15(h20, sig_bn, exponent); }
        else { verified = verify_sha1_pss(h20, sig_bn, exponent, pss_salt_len); }
    } else if hash_type == 1 {
        if padding_type == 0 { verified = verify_sha256_pkcs1v15(h32, sig_bn, exponent); }
        else { verified = verify_sha256_pss(h32, sig_bn, exponent, pss_salt_len); }
    } else if hash_type == 2 {
        if padding_type == 0 { verified = verify_sha384_pkcs1v15(h48, sig_bn, exponent); }
        else { verified = verify_sha384_pss(h48, sig_bn, exponent, pss_salt_len); }
    } else {
        if padding_type == 0 { verified = verify_sha512_pkcs1v15(h64, sig_bn, exponent); }
        else { verified = verify_sha512_pss(h64, sig_bn, exponent, pss_salt_len); }
    }

    verified
}
