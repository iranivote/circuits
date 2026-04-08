use commitment::commit_to_dsc;
use sig_verify_ecdsa::verify_ecdsa_signature;
use utils::types::Alpha3CountryCode;

fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 16],
    certificate_tags: [Field; 3],
    salt: Field,
    country: Alpha3CountryCode,
    tbs_certificate: [u8; 1200],
    tbs_len: u32,
    csc_pubkey_x: [u8; 66],
    csc_pubkey_y: [u8; 66],
    dsc_sig_r: [u8; 66],
    dsc_sig_s: [u8; 66],
    curve_type: u8,
    hash_type: u8,
    pubkey_len: u32,
) -> pub Field {
    assert(
        verify_ecdsa_signature(
            csc_pubkey_x, csc_pubkey_y, dsc_sig_r, dsc_sig_s,
            tbs_certificate, tbs_len, curve_type, hash_type,
        ),
        "CSCA ECDSA signature verification failed on TBS certificate",
    );
    let mut pubkey_concat: [u8; 132] = [0; 132];
    for i in 0..66 {
        pubkey_concat[i] = csc_pubkey_x[i];
        pubkey_concat[66 + i] = csc_pubkey_y[i];
    }
    commit_to_dsc(
        certificate_registry_root, certificate_registry_index,
        certificate_registry_hash_path, certificate_tags,
        country, tbs_certificate, tbs_len, salt, pubkey_concat, pubkey_len,
    )
}
