use common::{
    calculate_certificate_registry_leaf, compute_merkle_root,
    hash_salt_country_tbs, CSC_CERT_TYPE,
    hash_salt_country_signed_attr_dg1_e_content_private_nullifier,
    calculate_private_nullifier,
};
use utils::types::{Alpha3CountryCode, DG1Data, EContentData, SignedAttrsData};

/// DSC stage: verify the CSCA cert is in the registry, then produce an
/// output commitment that the ID-data circuit will consume.
pub fn commit_to_dsc<let TBS_SIZE: u32, let PUBKEY_SIZE: u32, let REGISTRY_HEIGHT: u32>(
    certificate_registry_root: Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; REGISTRY_HEIGHT],
    certificate_tags: [Field; 3],
    country: Alpha3CountryCode,
    tbs_certificate: [u8; TBS_SIZE],
    salt: Field,
    csc_pubkey: [u8; PUBKEY_SIZE],
) -> Field {
    let leaf = calculate_certificate_registry_leaf(
        certificate_tags,
        CSC_CERT_TYPE,
        country,
        csc_pubkey,
    );
    let computed_root = compute_merkle_root(leaf, certificate_registry_index, certificate_registry_hash_path);
    assert(computed_root == certificate_registry_root, "Certificate not in registry");

    hash_salt_country_tbs(salt, country, tbs_certificate)
}

/// ID-data stage: verify the incoming DSC commitment and produce the
/// commitment for the integrity-check stage.
pub fn commit_to_id<let TBS_SIZE: u32, let SIG_SIZE: u32>(
    comm_in: Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    tbs_certificate: [u8; TBS_SIZE],
    sod_signature: [u8; SIG_SIZE],
    signed_attributes: SignedAttrsData,
    signed_attributes_size: Field,
    e_content: EContentData,
) -> Field {
    let country = utils::get_issuing_country_from_mrz(dg1);
    let country_str: Alpha3CountryCode = country.as_str_unchecked();

    assert(
        comm_in == hash_salt_country_tbs(salt_in, country_str, tbs_certificate),
        "DSC commitment mismatch",
    );

    let private_nullifier = calculate_private_nullifier(dg1, e_content, sod_signature);

    hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
        salt_out,
        country_str,
        signed_attributes,
        signed_attributes_size,
        dg1,
        e_content,
        private_nullifier,
    )
}
