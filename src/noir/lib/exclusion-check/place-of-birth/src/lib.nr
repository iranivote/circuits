use data_check_dg11::PLACE_OF_BIRTH_MAX_LENGTH;
use poseidon::poseidon2::Poseidon2;

pub global POB_LIST_SIZE: u32 = 50;

/// Check that the place of birth does NOT match any entry in the list.
/// Comparison is case-insensitive and ignores trailing zero-padding.
pub fn check_place_of_birth_exclusion(
    pob: [u8; PLACE_OF_BIRTH_MAX_LENGTH],
    pob_len: u32,
    pob_list: [[u8; PLACE_OF_BIRTH_MAX_LENGTH]; POB_LIST_SIZE],
    pob_list_lengths: [u32; POB_LIST_SIZE],
) {
    for i in 0..POB_LIST_SIZE {
        if pob_list_lengths[i] > 0 {
            if pob_len == pob_list_lengths[i] {
                let mut matches = true;
                for j in 0..PLACE_OF_BIRTH_MAX_LENGTH {
                    if j < pob_len {
                        if to_upper(pob[j]) != to_upper(pob_list[i][j]) {
                            matches = false;
                        }
                    }
                }
                assert(!matches, "Place of birth is in exclusion list");
            }
        }
    }
}

/// Compute a parameter commitment binding the POB list to the proof.
pub fn calculate_param_commitment(
    pob_list: [[u8; PLACE_OF_BIRTH_MAX_LENGTH]; POB_LIST_SIZE],
    pob_list_lengths: [u32; POB_LIST_SIZE],
) -> Field {
    let mut inputs: [Field; POB_LIST_SIZE * 2] = std::mem::zeroed();
    for i in 0..POB_LIST_SIZE {
        inputs[i] = utils::poseidon2_hash_packed(pob_list[i], pob_list_lengths[i]);
        inputs[POB_LIST_SIZE + i] = pob_list_lengths[i] as Field;
    }
    Poseidon2::hash(inputs, POB_LIST_SIZE * 2)
}

fn to_upper(c: u8) -> u8 {
    if (c >= 97) & (c <= 122) { c - 32 } else { c }
}
