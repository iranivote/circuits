use bind::calculate_param_commitment;
use commitment::nullify;
use data_check_expiry::check_expiry_from_date;
use utils::types::SaltedValue;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    data: [u8; 509],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry_from_date(salted_expiry_date.value, current_date);
    let (nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(data);
    (param_commitment, nullifier_type, nullifier)
}
