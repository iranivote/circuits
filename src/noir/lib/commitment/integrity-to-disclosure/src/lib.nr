use common::hash_salt_dg1_dg2_hash_private_nullifier;
use utils::types::{SaltedValue, EContentData, SignedAttrsData};

/// Compute the commitment that bridges integrity check to disclosure circuits.
/// DG2 hashes come in varying sizes (20/28/32/48/64 bytes depending on hash algo).
/// We zero-pad them to 64 bytes to produce a uniform-sized commitment.
pub fn commit_to_disclosure<let DG2_HASH_SIZE: u32>(
    comm_in: Field,
    salt_in: Field,
    salted_dg1: SaltedValue<95>,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    dg2_hash: [u8; DG2_HASH_SIZE],
    dg2_hash_type: [u8; 1],
    signed_attributes: SignedAttrsData,
    signed_attributes_size: Field,
    e_content: EContentData,
    salted_private_nullifier: SaltedValue<32>,
) -> Field {
    let expiry_date = utils::get_expiry_date_from_mrz(salted_dg1.value);
    let salted_expiry = SaltedValue { salt: expiry_date_salt, value: expiry_date };

    // Pad dg2 hash to 64 bytes so the commitment is always the same shape
    let mut padded_dg2: [u8; 64] = [0; 64];
    for i in 0..DG2_HASH_SIZE {
        padded_dg2[i] = dg2_hash[i];
    }
    let salted_dg2_hash = SaltedValue { salt: dg2_hash_salt, value: padded_dg2 };
    let salted_dg2_hash_type = SaltedValue { salt: dg2_hash_salt, value: dg2_hash_type };

    hash_salt_dg1_dg2_hash_private_nullifier(
        salted_dg1,
        salted_expiry,
        salted_dg2_hash,
        salted_dg2_hash_type,
        salted_private_nullifier,
    )
}
