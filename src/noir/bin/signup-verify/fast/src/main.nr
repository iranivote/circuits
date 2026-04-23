use sha1::sha1;
use sha256::sha256_var;
use sha512::{sha384, sha512};
use schnorr::verify_signature;
use std::embedded_curve_ops::EmbeddedCurvePoint;
use commitment_common::{calculate_passport_identifier, hash_salt_dg1_dg2_hash_private_nullifier};
use utils::types::SaltedValue;

fn main(
    // --- public inputs ---
    server_pubkey_x: pub Field,
    server_pubkey_y: pub Field,

    // --- private inputs ---
    dg1: [u8; 95],
    dg1_salt: Field,
    expiry_date_salt: Field,
    dg2_hash: [u8; 64],
    dg2_hash_salt: Field,
    dg2_hash_type: u8,
    private_nullifier: [u8; 32],
    private_nullifier_salt: Field,
    schnorr_signature: [u8; 64],
    attested_dg1_hash: [u8; 64],
    dg_hash_type: u8,
) -> pub (Field, Field) {
    // DG1 is 93 bytes for passports (TD3) and 95 for ID cards (TD1)
    let dg1_size: u32 = if utils::is_id_card(dg1) { 95 } else { 93 };

    // 1. Compute DG1 hash and verify against attestation.
    //    The attested hash is always zero-padded to 64 bytes.
    //    Encoding matches utils::constants SHA*_IDENTIFIER:
    //      1 = SHA-1, 3 = SHA-256, 4 = SHA-384, 5 = SHA-512.
    //    SHA-224 (2) is not supported by fast attestation and is rejected here
    //    so that an unexpected value cannot silently degrade to SHA-256.
    if dg_hash_type == 1 {
        // SHA-1: 20 bytes, remaining 44 must be zero
        let dg1_bounded = BoundedVec::from_parts(dg1, dg1_size);
        let hash_result: [u8; 20] = sha1::sha1_var(dg1_bounded);
        for i in 0..20 {
            assert(hash_result[i] == attested_dg1_hash[i], "DG1 SHA-1 hash mismatch");
        }
        for i in 20..64 {
            assert(attested_dg1_hash[i] == 0, "SHA-1 attestation padding must be zero");
        }
    } else if dg_hash_type == 3 {
        // SHA-256: 32 bytes, remaining 32 must be zero
        let hash_result: [u8; 32] = sha256_var(dg1, dg1_size);
        for i in 0..32 {
            assert(hash_result[i] == attested_dg1_hash[i], "DG1 SHA-256 hash mismatch");
        }
        for i in 32..64 {
            assert(attested_dg1_hash[i] == 0, "SHA-256 attestation padding must be zero");
        }
    } else if dg_hash_type == 4 {
        // SHA-384: 48 bytes, remaining 16 must be zero
        let dg1_bounded = BoundedVec::from_parts(dg1, dg1_size);
        let hash_result: [u8; 48] = sha384::sha384_var(dg1_bounded);
        for i in 0..48 {
            assert(hash_result[i] == attested_dg1_hash[i], "DG1 SHA-384 hash mismatch");
        }
        for i in 48..64 {
            assert(attested_dg1_hash[i] == 0, "SHA-384 attestation padding must be zero");
        }
    } else if dg_hash_type == 5 {
        // SHA-512: 64 bytes
        let dg1_bounded = BoundedVec::from_parts(dg1, dg1_size);
        let hash_result: [u8; 64] = sha512::sha512_var(dg1_bounded);
        for i in 0..64 {
            assert(hash_result[i] == attested_dg1_hash[i], "DG1 SHA-512 hash mismatch");
        }
    } else {
        assert(false, "Unsupported dg_hash_type (expected 1=SHA-1, 3=SHA-256, 4=SHA-384, 5=SHA-512)");
    }

    // 2. Schnorr signature from the server must be valid over the 64-byte padded hash
    let server_pubkey = EmbeddedCurvePoint {
        x: server_pubkey_x,
        y: server_pubkey_y,
        is_infinite: false,
    };
    assert(
        verify_signature(server_pubkey, schnorr_signature, attested_dg1_hash),
        "Server attestation signature invalid",
    );

    // 3. Deterministic passport identifier (same as full signup circuits)
    let passport_id = calculate_passport_identifier(dg1);

    // 4. Commitment compatible with disclosure circuits (age, nationality, etc.)
    let salted_dg1 = SaltedValue { salt: dg1_salt, value: dg1 };
    let expiry_date = utils::get_expiry_date_from_mrz(dg1);
    let salted_expiry = SaltedValue { salt: expiry_date_salt, value: expiry_date };
    let salted_dg2_hash = SaltedValue { salt: dg2_hash_salt, value: dg2_hash };
    let salted_dg2_hash_type = SaltedValue { salt: dg2_hash_salt, value: [dg2_hash_type] };
    let salted_private_nullifier = SaltedValue { salt: private_nullifier_salt, value: private_nullifier };

    let commitment = hash_salt_dg1_dg2_hash_private_nullifier(
        salted_dg1,
        salted_expiry,
        salted_dg2_hash,
        salted_dg2_hash_type,
        salted_private_nullifier,
    );

    (passport_id, commitment)
}
