use sha1::sha1;
use sha256::{sha224_var, sha256_var};
use sha512::{sha384, sha512};
use utils::types::{DG1Data, EContentData, SignedAttrsData};
use utils::constants::ECONTENT_LENGTH;

fn get_dg1_size(dg1: DG1Data) -> u32 {
    if utils::is_id_card(dg1) { 95 } else { 93 }
}

// ---------------------------------------------------------------------------
// DG1 hash verification - assert SHA(dg1) == hash found in eContent
// ---------------------------------------------------------------------------

pub fn check_dg1_sha1(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    let dg1_size = get_dg1_size(dg1);
    let dg1_bounded = BoundedVec::from_parts(dg1, dg1_size);
    let dg1_hash: [u8; 20] = sha1::sha1_var(dg1_bounded);
    let offset = utils::find_subarray_index(dg1_hash, e_content);
    assert(offset + 20 <= e_content_size, "DG1 SHA-1 hash not found in eContent");
}

pub fn check_dg1_sha224(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    let dg1_size = get_dg1_size(dg1);
    let dg1_hash: [u8; 28] = sha224_var(dg1, dg1_size);
    let offset = utils::find_subarray_index(dg1_hash, e_content);
    assert(offset + 28 <= e_content_size, "DG1 SHA-224 hash not found in eContent");
}

pub fn check_dg1_sha256(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    let dg1_size = get_dg1_size(dg1);
    let dg1_hash: [u8; 32] = sha256_var(dg1, dg1_size);
    let offset = utils::find_subarray_index(dg1_hash, e_content);
    assert(offset + 32 <= e_content_size, "DG1 SHA-256 hash not found in eContent");
}

pub fn check_dg1_sha384(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    let dg1_size = get_dg1_size(dg1);
    let dg1_bounded = BoundedVec::from_parts(dg1, dg1_size);
    let dg1_hash: [u8; 48] = sha384::sha384_var(dg1_bounded);
    let offset = utils::find_subarray_index(dg1_hash, e_content);
    assert(offset + 48 <= e_content_size, "DG1 SHA-384 hash not found in eContent");
}

pub fn check_dg1_sha512(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    let dg1_size = get_dg1_size(dg1);
    let dg1_bounded = BoundedVec::from_parts(dg1, dg1_size);
    let dg1_hash: [u8; 64] = sha512::sha512_var(dg1_bounded);
    let offset = utils::find_subarray_index(dg1_hash, e_content);
    assert(offset + 64 <= e_content_size, "DG1 SHA-512 hash not found in eContent");
}

// ---------------------------------------------------------------------------
// Signed attributes verification - assert SHA(eContent) == hash in signedAttrs
// ---------------------------------------------------------------------------

pub fn check_signed_attributes_sha1(
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    e_content_size: u32,
) {
    let ec_bounded = BoundedVec::from_parts(e_content, e_content_size);
    let computed: [u8; 20] = sha1::sha1_var(ec_bounded);
    assert(
        utils::is_subarray_in_array(computed, signed_attributes),
        "SHA-1 eContent hash not found in signed attributes",
    );
}

pub fn check_signed_attributes_sha224(
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    e_content_size: u32,
) {
    let computed: [u8; 28] = sha224_var(e_content, e_content_size);
    assert(
        utils::is_subarray_in_array(computed, signed_attributes),
        "SHA-224 eContent hash not found in signed attributes",
    );
}

pub fn check_signed_attributes_sha256(
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    e_content_size: u32,
) {
    let computed: [u8; 32] = sha256_var(e_content, e_content_size);
    assert(
        utils::is_subarray_in_array(computed, signed_attributes),
        "SHA-256 eContent hash not found in signed attributes",
    );
}

pub fn check_signed_attributes_sha384(
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    e_content_size: u32,
) {
    let ec_bounded = BoundedVec::from_parts(e_content, e_content_size);
    let computed: [u8; 48] = sha384::sha384_var(ec_bounded);
    assert(
        utils::is_subarray_in_array(computed, signed_attributes),
        "SHA-384 eContent hash not found in signed attributes",
    );
}

pub fn check_signed_attributes_sha512(
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    e_content_size: u32,
) {
    let ec_bounded = BoundedVec::from_parts(e_content, e_content_size);
    let computed: [u8; 64] = sha512::sha512_var(ec_bounded);
    assert(
        utils::is_subarray_in_array(computed, signed_attributes),
        "SHA-512 eContent hash not found in signed attributes",
    );
}

// ---------------------------------------------------------------------------
// DG2 hash extraction from eContent
// ---------------------------------------------------------------------------

global DG2_HASH_DER_IDENTIFIER: [u8; 4] = [0x02, 0x01, 0x02, 0x04];

pub fn get_dg2_hash_from_econtent<let DG2_LEN: u32>(
    e_content: EContentData,
    e_content_size: u32,
) -> [u8; DG2_LEN] {
    let offset = utils::find_subarray_index(DG2_HASH_DER_IDENTIFIER, e_content);
    assert(offset < ECONTENT_LENGTH, "DG2 hash not found in eContent");

    let hash_size_offset = offset + DG2_HASH_DER_IDENTIFIER.len();
    let hash_size = e_content[hash_size_offset];
    assert(hash_size == (DG2_LEN as u8), "DG2 hash size mismatch");

    let hash_offset = hash_size_offset + 1;
    assert(hash_offset + DG2_LEN <= e_content_size, "DG2 hash extends beyond eContent");

    let mut hash: [u8; DG2_LEN] = [0; DG2_LEN];
    for i in 0..DG2_LEN {
        hash[i] = e_content[hash_offset + i];
    }
    hash
}
