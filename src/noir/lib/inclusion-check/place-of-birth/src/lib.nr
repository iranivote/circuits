use data_check_dg11::PLACE_OF_BIRTH_MAX_LENGTH;
use poseidon::poseidon2::Poseidon2;

pub global POB_LIST_SIZE: u32 = 50;

/// Check that the place of birth matches at least one entry in the list.
/// Comparison is case-insensitive and ignores trailing zero-padding.
/// Each entry in pob_list is a zero-padded string of PLACE_OF_BIRTH_MAX_LENGTH bytes.
pub fn check_place_of_birth_inclusion(
    pob: [u8; PLACE_OF_BIRTH_MAX_LENGTH],
    pob_len: u32,
    pob_list: [[u8; PLACE_OF_BIRTH_MAX_LENGTH]; POB_LIST_SIZE],
    pob_list_lengths: [u32; POB_LIST_SIZE],
) {
    let mut found = false;
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
                if matches {
                    found = true;
                }
            }
        }
    }
    assert(found, "Place of birth not in inclusion list");
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
    // ASCII lowercase a-z: 97-122 -> 65-90
    if (c >= 97) & (c <= 122) { c - 32 } else { c }
}
