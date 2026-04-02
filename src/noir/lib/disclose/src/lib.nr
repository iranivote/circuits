use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::MAX_MRZ_LENGTH,
    get_mrz_from_dg1,
    types::{DG1Data, DiscloseMask},
};

/// Apply a disclosure mask to the MRZ: for each byte, if mask[i] != 0 the
/// MRZ byte is revealed; otherwise it is zeroed out.
pub fn get_disclosed_bytes(dg1: DG1Data, mask: DiscloseMask) -> [u8; MAX_MRZ_LENGTH] {
    let mrz = get_mrz_from_dg1(dg1);
    let mut disclosed: [u8; MAX_MRZ_LENGTH] = std::mem::zeroed();
    for i in 0..MAX_MRZ_LENGTH {
        if mask[i] != 0 {
            disclosed[i] = mrz[i];
        }
    }
    disclosed
}

/// Compute a parameter commitment binding the mask and disclosed bytes to the proof.
pub fn calculate_param_commitment(
    mask: DiscloseMask,
    disclosed_bytes: [u8; MAX_MRZ_LENGTH],
) -> Field {
    let mut inputs: [Field; MAX_MRZ_LENGTH * 2] = std::mem::zeroed();
    for i in 0..MAX_MRZ_LENGTH {
        inputs[i] = mask[i] as Field;
        inputs[MAX_MRZ_LENGTH + i] = disclosed_bytes[i] as Field;
    }
    Poseidon2::hash(inputs, MAX_MRZ_LENGTH * 2)
}
