use utils::find_subarray_index;

/// Verify that the given public key bytes appear inside the TBS certificate.
/// This ensures the DSC public key used for SOD signature verification is
/// the same key embedded in the certificate (prevents key substitution attacks).
pub fn verify_rsa_pubkey_in_tbs<let KEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey: [u8; KEY_SIZE],
    tbs_certificate: [u8; TBS_SIZE],
) {
    let idx = find_subarray_index(pubkey, tbs_certificate);
    assert(idx < TBS_SIZE, "RSA public key not found in TBS certificate");
}

/// Same check for ECDSA public keys.
pub fn verify_ecdsa_pubkey_in_tbs<let KEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey: [u8; KEY_SIZE],
    tbs_certificate: [u8; TBS_SIZE],
) {
    let idx = find_subarray_index(pubkey, tbs_certificate);
    assert(idx < TBS_SIZE, "ECDSA public key not found in TBS certificate");
}
