use commitment::commit_to_disclosure;
use data_check_integrity::{
    check_dg1_sha1, check_dg1_sha224, check_dg1_sha256, check_dg1_sha384, check_dg1_sha512,
    check_signed_attributes_sha1, check_signed_attributes_sha224,
    check_signed_attributes_sha256, check_signed_attributes_sha384,
    check_signed_attributes_sha512,
    get_dg2_hash_from_econtent_var, hash_digest_len,
};
use utils::types::{EContentData, SignedAttrsData, SaltedValue};

/// Single modular integrity-verify circuit replacing 25 SA-hash x DG-hash combinations.
///
/// Hash type identifiers (matching SHA*_IDENTIFIER constants):
///   1 = SHA-1, 2 = SHA-224, 3 = SHA-256, 4 = SHA-384, 5 = SHA-512
fn main(
    comm_in: pub Field,
    salt_in: Field,
    salted_dg1: SaltedValue<95>,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    salted_private_nullifier: SaltedValue<32>,
    dg_hash_type: u8,
    sa_hash_type: u8,
) -> pub (Field, Field) {
    let e_content_size = unsafe { utils::unsafe_get_asn1_element_length(e_content) };

    // Verify DG1 hash appears in eContent (runtime hash selection)
    if dg_hash_type == 1 { check_dg1_sha1(salted_dg1.value, e_content, e_content_size); }
    else if dg_hash_type == 2 { check_dg1_sha224(salted_dg1.value, e_content, e_content_size); }
    else if dg_hash_type == 3 { check_dg1_sha256(salted_dg1.value, e_content, e_content_size); }
    else if dg_hash_type == 4 { check_dg1_sha384(salted_dg1.value, e_content, e_content_size); }
    else { check_dg1_sha512(salted_dg1.value, e_content, e_content_size); }

    // Verify SHA(eContent) appears in signed attributes (runtime hash selection)
    if sa_hash_type == 1 { check_signed_attributes_sha1(signed_attributes, e_content, e_content_size); }
    else if sa_hash_type == 2 { check_signed_attributes_sha224(signed_attributes, e_content, e_content_size); }
    else if sa_hash_type == 3 { check_signed_attributes_sha256(signed_attributes, e_content, e_content_size); }
    else if sa_hash_type == 4 { check_signed_attributes_sha384(signed_attributes, e_content, e_content_size); }
    else { check_signed_attributes_sha512(signed_attributes, e_content, e_content_size); }

    // Extract DG2 hash from eContent (variable length based on dg_hash_type)
    let dg2_hash_len = hash_digest_len(dg_hash_type);
    let dg2_hash: [u8; 64] = get_dg2_hash_from_econtent_var(e_content, e_content_size, dg2_hash_len);
    let signed_attributes_size = unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };

    commit_to_disclosure(
        comm_in, salt_in, salted_dg1, expiry_date_salt,
        dg2_hash_salt, dg2_hash, [dg_hash_type],
        signed_attributes, signed_attributes_size as Field,
        e_content, salted_private_nullifier,
    )
}
