use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::{DG1_LENGTH, ECONTENT_LENGTH, SIGNED_ATTRS_LENGTH},
    pack_be_bytes_into_fields_sized,
    poseidon2_hash_packed,
    types::{
        Alpha3CountryCode, DG1Data, EContentData, SaltedValue,
        SignedAttrsData,
    },
};

pub global CSC_CERT_TYPE: u8 = 1;
pub global DSC_CERT_TYPE: u8 = 2;

/// Normalize a DG2 hash of arbitrary length into a single field element via Poseidon2.
pub fn normalize_dg2_hash<let DG2_HASH_SIZE: u32>(dg2_hash: [u8; DG2_HASH_SIZE]) -> Field {
    poseidon2_hash_packed(dg2_hash, DG2_HASH_SIZE)
}

/// Scoped nullifier: H(private_nullifier, service_scope, service_subscope [, secret])
/// Deterministic per identity per service scope, unlinkable across scopes.
pub fn calculate_scoped_nullifier(
    salted_private_nullifier: SaltedValue<32>,
    service_scope: Field,
    service_subscope: Field,
    nullifier_secret: Field,
) -> Field {
    if salted_private_nullifier.value == [0; 32] {
        // Hidden behind salted hash; cannot derive nullifier
        0
    } else if nullifier_secret != 0 {
        Poseidon2::hash(
            [salted_private_nullifier.value[0] as Field, service_scope, service_subscope, nullifier_secret],
            4,
        )
    } else {
        Poseidon2::hash(
            [salted_private_nullifier.value[0] as Field, service_scope, service_subscope],
            3,
        )
    }
}

/// Private nullifier derived from passport-unique data: H(dg1, e_content, sod_signature).
/// This value is deterministic for a given passport and never changes.
pub fn calculate_private_nullifier<let SIG: u32>(
    dg1: DG1Data,
    e_content: EContentData,
    sod_sig: [u8; SIG],
) -> Field {
    let mut hash_inputs: [Field; (DG1_LENGTH + 30) / 31 + (ECONTENT_LENGTH + 30) / 31 + (SIG + 30) / 31] =
        std::mem::zeroed();

    let packed_dg1: [Field; (DG1_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields_sized(dg1);
    for i in 0..((DG1_LENGTH + 30) / 31) {
        hash_inputs[i] = packed_dg1[i];
    }

    let packed_e_content: [Field; (ECONTENT_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields_sized(e_content);
    for i in 0..((ECONTENT_LENGTH + 30) / 31) {
        hash_inputs[(DG1_LENGTH + 30) / 31 + i] = packed_e_content[i];
    }

    let packed_sod_sig: [Field; (SIG + 30) / 31] = pack_be_bytes_into_fields_sized(sod_sig);
    for i in 0..((SIG + 30) / 31) {
        hash_inputs[(DG1_LENGTH + 30) / 31 + ((ECONTENT_LENGTH + 30) / 31) + i] = packed_sod_sig[i];
    }

    Poseidon2::hash(
        hash_inputs,
        (DG1_LENGTH + 30) / 31 + ((ECONTENT_LENGTH + 30) / 31) + (SIG + 30) / 31,
    )
}

/// Commitment for the integrity-to-disclosure bridge.
/// H(salted_dg1, salted_expiry, salted_dg2_hash, salted_dg2_hash_type, salted_private_nullifier)
pub fn hash_salt_dg1_dg2_hash_private_nullifier(
    salted_dg1: SaltedValue<95>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    salted_private_nullifier: SaltedValue<32>,
) -> Field {
    let mut hash_inputs: [Field; 5] = std::mem::zeroed();
    hash_inputs[0] = salted_dg1.get_hash();
    hash_inputs[1] = salted_expiry_date.get_hash();
    hash_inputs[2] = salted_dg2_hash.get_hash();
    hash_inputs[3] = salted_dg2_hash_type.get_hash();
    hash_inputs[4] = salted_private_nullifier.get_hash();
    Poseidon2::hash(hash_inputs, 5)
}

/// Commitment for the DSC-to-ID bridge.
/// H(salt, country, signed_attr, signed_attr_size, dg1, e_content, private_nullifier)
pub fn hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
    salt: Field,
    country: Alpha3CountryCode,
    signed_attr: SignedAttrsData,
    signed_attr_size: Field,
    dg1: DG1Data,
    e_content: EContentData,
    private_nullifier: Field,
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();

    let mut hash_inputs: [Field; 4 + (SIGNED_ATTRS_LENGTH + 30) / 31 + ((DG1_LENGTH + 30) / 31) + ((ECONTENT_LENGTH + 30) / 31)] =
        std::mem::zeroed();
    hash_inputs[0] = salt;

    let packed_country: Field = pack_be_bytes_into_fields_sized::<3, 1>(country_bytes)[0];
    hash_inputs[1] = packed_country;

    let packed_signed_attr: [Field; (SIGNED_ATTRS_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields_sized(signed_attr);
    for i in 0..((SIGNED_ATTRS_LENGTH + 30) / 31) {
        hash_inputs[2 + i] = packed_signed_attr[i];
    }

    hash_inputs[2 + (SIGNED_ATTRS_LENGTH + 30) / 31] = signed_attr_size;

    let packed_dg1: [Field; (DG1_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields_sized(dg1);
    for i in 0..((DG1_LENGTH + 30) / 31) {
        hash_inputs[3 + (SIGNED_ATTRS_LENGTH + 30) / 31 + i] = packed_dg1[i];
    }

    let packed_e_content: [Field; (ECONTENT_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields_sized(e_content);
    for i in 0..((ECONTENT_LENGTH + 30) / 31) {
        hash_inputs[3 + (SIGNED_ATTRS_LENGTH + 30) / 31 + ((DG1_LENGTH + 30) / 31) + i] =
            packed_e_content[i];
    }
    hash_inputs[3 + (SIGNED_ATTRS_LENGTH + 30) / 31 + ((DG1_LENGTH + 30) / 31) + ((ECONTENT_LENGTH + 30) / 31)] =
        private_nullifier;

    Poseidon2::hash(
        hash_inputs,
        4 + (SIGNED_ATTRS_LENGTH + 30) / 31 + ((DG1_LENGTH + 30) / 31) + ((ECONTENT_LENGTH + 30) / 31),
    )
}

/// Commitment for the CSC-to-DSC bridge: H(salt, country, tbs_certificate)
pub fn hash_salt_country_tbs<let TBS_MAX_SIZE: u32>(
    salt: Field,
    country: Alpha3CountryCode,
    tbs: [u8; TBS_MAX_SIZE],
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut hash_inputs: [Field; 2 + ((TBS_MAX_SIZE + 30) / 31)] =
        [0; 2 + ((TBS_MAX_SIZE + 30) / 31)];
    hash_inputs[0] = salt;

    let packed_country: Field = pack_be_bytes_into_fields_sized::<3, 1>(country_bytes)[0];
    hash_inputs[1] = packed_country;

    let packed_tbs: [Field; (TBS_MAX_SIZE + 30) / 31] =
        pack_be_bytes_into_fields_sized(tbs);
    for i in 0..((TBS_MAX_SIZE + 30) / 31) {
        hash_inputs[2 + i] = packed_tbs[i];
    }

    Poseidon2::hash(hash_inputs, 2 + ((TBS_MAX_SIZE + 30) / 31))
}

/// Compute a Poseidon2 Merkle tree root from a leaf, its index, and the sibling path.
pub fn compute_merkle_root<let N: u32>(leaf: Field, index: Field, hash_path: [Field; N]) -> Field {
    let index_bits: [u1; N] = index.to_le_bits();
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bits[i] == 1;
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };
        current = Poseidon2::hash([hash_left, hash_right], 2);
    }
    current
}

/// Compute a leaf for the certificate registry Merkle tree.
pub fn calculate_certificate_registry_leaf<let N: u32>(
    tags: [Field; 3],
    cert_type: u8,
    country: Alpha3CountryCode,
    public_key: [u8; N],
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let unpacked_bytes: [u8; 4] =
        [cert_type as u8, country_bytes[0], country_bytes[1], country_bytes[2]];
    let mut hash_inputs: [Field; 4 + (N + 30) / 31] = std::mem::zeroed();
    hash_inputs[0] = tags[0];
    hash_inputs[1] = tags[1];
    hash_inputs[2] = tags[2];
    hash_inputs[3] = utils::pack_be_bytes_into_field::<4, 31>(unpacked_bytes);
    let packed_pubkey: [Field; (N + 30) / 31] = utils::pack_be_bytes_into_fields_sized(public_key);
    for i in 0..packed_pubkey.len() {
        hash_inputs[4 + i] = packed_pubkey[i] as Field;
    }
    Poseidon2::hash(hash_inputs, hash_inputs.len())
}
