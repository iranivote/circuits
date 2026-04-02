use poseidon::poseidon2::Poseidon2;
use utils::{
    get_nationality_from_mrz,
    types::DG1Data,
};

fn country_bytes_to_u32(bytes: [u8; 3]) -> u32 {
    (bytes[0] as u32) * 65536 + (bytes[1] as u32) * 256 + (bytes[2] as u32)
}

/// Assert that the passport holder's nationality is NOT in the provided country list.
/// The list must be sorted in ascending order.
pub fn check_nationality_exclusion(dg1: DG1Data, country_list: [u32; 200]) {
    let nationality = get_nationality_from_mrz(dg1);
    let nat_code = country_bytes_to_u32(nationality);

    for i in 0..200 {
        assert(country_list[i] != nat_code, "Nationality is in exclusion list");
    }
}

/// Assert that the passport's issuing country is NOT in the provided list.
pub fn check_issuing_country_exclusion(dg1: DG1Data, country_list: [u32; 200]) {
    let issuing = utils::get_issuing_country_from_mrz(dg1);
    let iss_code = country_bytes_to_u32(issuing);

    for i in 0..200 {
        assert(country_list[i] != iss_code, "Issuing country is in exclusion list");
    }
}

pub fn calculate_param_commitment(proof_type: Field, country_list: [u32; 200]) -> Field {
    let mut inputs: [Field; 201] = std::mem::zeroed();
    inputs[0] = proof_type;
    for i in 0..200 {
        inputs[1 + i] = country_list[i] as Field;
    }
    Poseidon2::hash(inputs, 201)
}
