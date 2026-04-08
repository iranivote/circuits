use commitment_common::{calculate_certificate_registry_leaf, compute_merkle_root, DSC_CERT_TYPE};
use commitment_integrity_to_disclosure::commit_to_disclosure;
use data_check_integrity::{
    check_dg1_sha1, check_dg1_sha224, check_dg1_sha256, check_dg1_sha384, check_dg1_sha512,
    check_signed_attributes_sha1, check_signed_attributes_sha224,
    check_signed_attributes_sha256, check_signed_attributes_sha384,
    check_signed_attributes_sha512,
    get_dg2_hash_from_econtent_var, hash_digest_len,
};
use sig_verify_rsa::verify_rsa_signature;
use utils::types::{Alpha3CountryCode, EContentData, SaltedValue, SignedAttrsData};

fn main(
    trusted_dsc_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 16],
    certificate_tags: [Field; 3],
    salted_dg1: SaltedValue<95>,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    salted_private_nullifier: SaltedValue<32>,
    dg_hash_type: u8,
    sa_hash_type: u8,
    dsc_pubkey: [u8; 512],
    dsc_pubkey_redc_param: [u8; 513],
    sod_signature: [u8; 512],
    exponent: u32,
    key_size: u8,
    hash_type: u8,
    padding_type: u8,
    pss_salt_len: u32,
    pubkey_len: u32,
) -> pub (Field, Field) {
    let country = utils::get_issuing_country_from_mrz(salted_dg1.value);
    let country_str: Alpha3CountryCode = country.as_str_unchecked();

    let leaf = calculate_certificate_registry_leaf(
        certificate_tags,
        DSC_CERT_TYPE,
        country_str,
        dsc_pubkey,
        pubkey_len,
    );
    let computed_root = compute_merkle_root(
        leaf,
        certificate_registry_index,
        certificate_registry_hash_path,
    );
    assert(computed_root == trusted_dsc_root, "DSC public key not in trusted registry");

    // Safety: ASN.1 length parsing is unconstrained; subsequent checks constrain
    // the parsed lengths by requiring the relevant digests to be present.
    let signed_attributes_size = unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };

    let mut sa_padded: [u8; 1200] = [0; 1200];
    for i in 0..256 {
        sa_padded[i] = signed_attributes[i];
    }

    assert(
        verify_rsa_signature(
            dsc_pubkey, sod_signature, dsc_pubkey_redc_param, exponent,
            sa_padded, signed_attributes_size, key_size, hash_type, padding_type, pss_salt_len,
        ),
        "DSC RSA signature verification failed on signed attributes",
    );

    // Safety: ASN.1 length parsing is unconstrained; subsequent checks constrain
    // the parsed lengths by requiring the relevant digests to be present.
    let e_content_size = unsafe { utils::unsafe_get_asn1_element_length(e_content) };

    if dg_hash_type == 1 { check_dg1_sha1(salted_dg1.value, e_content, e_content_size); }
    else if dg_hash_type == 2 { check_dg1_sha224(salted_dg1.value, e_content, e_content_size); }
    else if dg_hash_type == 3 { check_dg1_sha256(salted_dg1.value, e_content, e_content_size); }
    else if dg_hash_type == 4 { check_dg1_sha384(salted_dg1.value, e_content, e_content_size); }
    else { check_dg1_sha512(salted_dg1.value, e_content, e_content_size); }

    if sa_hash_type == 1 { check_signed_attributes_sha1(signed_attributes, e_content, e_content_size); }
    else if sa_hash_type == 2 { check_signed_attributes_sha224(signed_attributes, e_content, e_content_size); }
    else if sa_hash_type == 3 { check_signed_attributes_sha256(signed_attributes, e_content, e_content_size); }
    else if sa_hash_type == 4 { check_signed_attributes_sha384(signed_attributes, e_content, e_content_size); }
    else { check_signed_attributes_sha512(signed_attributes, e_content, e_content_size); }

    let dg2_hash_len = hash_digest_len(dg_hash_type);
    let dg2_hash: [u8; 64] = get_dg2_hash_from_econtent_var(e_content, e_content_size, dg2_hash_len);

    commit_to_disclosure(
        0,
        0,
        salted_dg1,
        expiry_date_salt,
        dg2_hash_salt,
        dg2_hash,
        [dg_hash_type],
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
        salted_private_nullifier,
    )
}
