use commitment::nullify;
use compare_age::{calculate_param_commitment, compare_age};
use data_check_expiry::check_expiry;
use utils::types::SaltedValue;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    min_age_required: u8,
    max_age_required: u8,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry(salted_dg1.value, current_date);
    compare_age(salted_dg1.value, min_age_required, max_age_required, current_date);
    let (nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(min_age_required, max_age_required);
    (param_commitment, nullifier_type, nullifier)
}
