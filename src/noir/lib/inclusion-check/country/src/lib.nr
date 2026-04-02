use poseidon::poseidon2::Poseidon2;
use utils::{
    get_nationality_from_mrz,
    types::DG1Data,
};

/// Convert a 3-byte ASCII country code to a u32 for comparison.
fn country_bytes_to_u32(bytes: [u8; 3]) -> u32 {
    (bytes[0] as u32) * 65536 + (bytes[1] as u32) * 256 + (bytes[2] as u32)
}

/// Assert that the passport holder's nationality IS in the provided country list.
/// The list must be sorted in ascending order (by the u32 encoding of the 3-byte code).
pub fn check_nationality_inclusion(dg1: DG1Data, country_list: [u32; 200]) {
    let nationality = get_nationality_from_mrz(dg1);
    let nat_code = country_bytes_to_u32(nationality);

    let mut found = false;
    for i in 0..200 {
        if country_list[i] == nat_code {
            found = true;
        }
    }
    assert(found, "Nationality not in inclusion list");
}

/// Assert that the passport's issuing country IS in the provided list.
pub fn check_issuing_country_inclusion(dg1: DG1Data, country_list: [u32; 200]) {
    let issuing = utils::get_issuing_country_from_mrz(dg1);
    let iss_code = country_bytes_to_u32(issuing);

    let mut found = false;
    for i in 0..200 {
        if country_list[i] == iss_code {
            found = true;
        }
    }
    assert(found, "Issuing country not in inclusion list");
}

/// Compute a parameter commitment binding the country list to the proof.
pub fn calculate_param_commitment(proof_type: Field, country_list: [u32; 200]) -> Field {
    let mut inputs: [Field; 201] = std::mem::zeroed();
    inputs[0] = proof_type;
    for i in 0..200 {
        inputs[1 + i] = country_list[i] as Field;
    }
    Poseidon2::hash(inputs, 201)
}
