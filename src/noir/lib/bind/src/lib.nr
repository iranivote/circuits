use utils::poseidon2_hash_packed;

/// Compute a parameter commitment for arbitrary bound data (up to 509 bytes).
/// This lets a proof be tied to specific external data (e.g. an election ID).
pub fn calculate_param_commitment(data: [u8; 509]) -> Field {
    poseidon2_hash_packed(data, 509)
}
