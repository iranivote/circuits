use commitment::nullify;
use data_check_expiry::check_expiry;
use data_check_dg11::{extract_place_of_birth, PLACE_OF_BIRTH_MAX_LENGTH};
use exclusion_check_place_of_birth::{calculate_param_commitment, check_place_of_birth_exclusion, POB_LIST_SIZE};
use utils::types::SaltedValue;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    dg11: [u8; 512],
    dg11_len: u32,
    pob_list: [[u8; PLACE_OF_BIRTH_MAX_LENGTH]; POB_LIST_SIZE],
    pob_list_lengths: [u32; POB_LIST_SIZE],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry(salted_dg1.value, current_date);
    let (pob, pob_len) = extract_place_of_birth(dg11, dg11_len);
    check_place_of_birth_exclusion(pob, pob_len, pob_list, pob_list_lengths);
    let (nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(pob_list, pob_list_lengths);
    (param_commitment, nullifier_type, nullifier)
}
