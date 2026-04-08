use commitment::commit_to_dsc;
use sig_verify_rsa::verify_rsa_signature;
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
    csc_pubkey: [u8; 512],
    csc_pubkey_redc_param: [u8; 513],
    dsc_signature: [u8; 512],
    exponent: u32,
    key_size: u8,
    hash_type: u8,
    padding_type: u8,
    pss_salt_len: u32,
    pubkey_len: u32,
) -> pub Field {
    assert(
        verify_rsa_signature(
            csc_pubkey, dsc_signature, csc_pubkey_redc_param, exponent,
            tbs_certificate, tbs_len, key_size, hash_type, padding_type, pss_salt_len,
        ),
        "CSCA RSA signature verification failed on TBS certificate",
    );
    commit_to_dsc(
        certificate_registry_root, certificate_registry_index,
        certificate_registry_hash_path, certificate_tags,
        country, tbs_certificate, tbs_len, salt, csc_pubkey, pubkey_len,
    )
}
