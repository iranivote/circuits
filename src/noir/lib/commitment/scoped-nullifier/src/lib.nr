use common::{calculate_scoped_nullifier, hash_salt_dg1_dg2_hash_private_nullifier};
use utils::{
    constants::{
        NON_SALTED_MOCK_NULLIFIER, NON_SALTED_NULLIFIER, SALTED_MOCK_NULLIFIER, SALTED_NULLIFIER,
    },
    get_issuing_country_from_mrz,
    types::SaltedValue,
};

// ZKR (Zero Knowledge Republic) is a mock country used for testing
global ZKR_COUNTRY_CODE_BYTES: [u8; 3] = [90, 75, 82];

/// Verify the integrity-to-disclosure commitment, then produce a scoped nullifier.
///
/// The nullifier is: H(private_nullifier, service_scope, service_subscope [, secret])
/// It is deterministic per passport per (scope, subscope) pair, preventing double-use
/// while remaining unlinkable across different scopes (e.g. different elections).
///
/// Returns (scoped_nullifier, nullifier_type).
pub fn nullify(
    comm_in: Field,
    salted_dg1: SaltedValue<95>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    salted_private_nullifier: SaltedValue<32>,
    service_scope: Field,
    service_subscope: Field,
    nullifier_secret: Field,
) -> (Field, Field) {
    assert(
        comm_in
            == hash_salt_dg1_dg2_hash_private_nullifier(
                salted_dg1,
                salted_expiry_date,
                salted_dg2_hash,
                salted_dg2_hash_type,
                salted_private_nullifier,
            ),
        "Commitment from integrity proof doesn't match in disclosure proof",
    );
    let scoped_nullifier = calculate_scoped_nullifier(
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );

    let mut nullifier_type = if nullifier_secret != 0 {
        SALTED_NULLIFIER
    } else {
        NON_SALTED_NULLIFIER
    };

    let issuing_country = get_issuing_country_from_mrz(salted_dg1.value);
    // Mark test-country proofs so they cannot be used in production
    if issuing_country == ZKR_COUNTRY_CODE_BYTES {
        if nullifier_secret != 0 {
            nullifier_type = SALTED_MOCK_NULLIFIER;
        } else {
            nullifier_type = NON_SALTED_MOCK_NULLIFIER;
        }
    }

    (scoped_nullifier, nullifier_type)
}
