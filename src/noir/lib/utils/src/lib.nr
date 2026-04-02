pub mod types;
pub mod constants;
pub mod sha1;

use types::{
    DG1Data, MRZData, MRZName, MRZDOB, MRZYOB, MRZDocumentNumber,
    MRZNationality, MRZIssuingCountry, MRZExpiryDate,
};
use constants::{
    ASCII_CODE_FOR_LESS_THAN, DG1_TO_MRZ_OFFSET, MAX_MRZ_LENGTH, YYMMDD_DATE_LENGTH,
    PASSPORT_MRZ_ISSUING_COUNTRY_INDEX, PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH,
    PASSPORT_MRZ_NAME_INDEX, PASSPORT_MRZ_NAME_LENGTH,
    PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX, PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH,
    PASSPORT_MRZ_NATIONALITY_INDEX, PASSPORT_MRZ_NATIONALITY_LENGTH,
    PASSPORT_MRZ_BIRTHDATE_INDEX, PASSPORT_MRZ_BIRTHDATE_LENGTH,
    PASSPORT_MRZ_YEAR_OF_BIRTH_LENGTH, PASSPORT_MRZ_EXPIRY_DATE_INDEX,
    ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX, ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH,
    ID_CARD_MRZ_BIRTHDATE_INDEX, ID_CARD_MRZ_BIRTHDATE_LENGTH,
    ID_CARD_MRZ_YEAR_OF_BIRTH_LENGTH, ID_CARD_MRZ_EXPIRY_DATE_INDEX,
    ID_CARD_MRZ_NATIONALITY_INDEX, ID_CARD_MRZ_NATIONALITY_LENGTH,
    ID_CARD_MRZ_NAME_INDEX, ID_CARD_MRZ_NAME_LENGTH,
};
use poseidon::poseidon2::Poseidon2;

// Germany uses "D<<" as issuing state in MRZ, but the ISO 3166 code is "DEU"
global GERMANY_PASSPORT_CODE: [u8; 3] = [68, 60, 60];
global GERMANY_ISO_CODE: [u8; 3] = [68, 69, 85];

// -- Array utilities --

pub fn get_array_slice<let N: u32, let SLICE_LEN: u32>(
    arr: [u8; N],
    start: u32,
) -> [u8; SLICE_LEN] {
    let mut slice = [0 as u8; SLICE_LEN];
    for i in 0..SLICE_LEN {
        slice[i] = arr[start + i];
    }
    slice
}

// -- Document type detection --

/// ID cards (TD1) have 95-byte DG1; passports (TD3) have 93 bytes.
/// For passports, the last 2 bytes of DG1Data are zero-padded.
pub fn is_id_card(dg1: DG1Data) -> bool {
    (dg1[93] != 0) & (dg1[94] != 0)
}

// -- MRZ extraction --

pub fn get_mrz_from_dg1(dg1: DG1Data) -> MRZData {
    let mut mrz: MRZData = std::mem::zeroed();
    for i in 0..MAX_MRZ_LENGTH {
        mrz[i] = dg1[i + DG1_TO_MRZ_OFFSET];
    }
    mrz
}

// -- Issuing country --

pub fn get_issuing_country_from_mrz(dg1: DG1Data) -> MRZIssuingCountry {
    let mrz = get_mrz_from_dg1(dg1);
    let mut country_bytes = get_array_slice::<_, PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH>(
        mrz,
        PASSPORT_MRZ_ISSUING_COUNTRY_INDEX,
    );
    if country_bytes == GERMANY_PASSPORT_CODE {
        country_bytes = GERMANY_ISO_CODE;
    }
    country_bytes
}

// -- Nationality --

pub fn get_nationality_from_mrz(dg1: DG1Data) -> MRZNationality {
    let mrz = get_mrz_from_dg1(dg1);
    let mut country_bytes: MRZNationality = std::mem::zeroed();

    if is_id_card(dg1) {
        country_bytes = get_array_slice::<_, ID_CARD_MRZ_NATIONALITY_LENGTH>(
            mrz,
            ID_CARD_MRZ_NATIONALITY_INDEX,
        );
    } else {
        country_bytes = get_array_slice::<_, PASSPORT_MRZ_NATIONALITY_LENGTH>(
            mrz,
            PASSPORT_MRZ_NATIONALITY_INDEX,
        );
    }

    if country_bytes == GERMANY_PASSPORT_CODE {
        country_bytes = GERMANY_ISO_CODE;
    }
    country_bytes
}

// -- Name --

pub fn get_name_from_mrz(dg1: DG1Data) -> MRZName {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        let mut padded: MRZName = std::mem::zeroed();
        let name = get_array_slice::<_, ID_CARD_MRZ_NAME_LENGTH>(mrz, ID_CARD_MRZ_NAME_INDEX);
        for i in 0..ID_CARD_MRZ_NAME_LENGTH {
            padded[i] = name[i];
        }
        for i in 0..(PASSPORT_MRZ_NAME_LENGTH - ID_CARD_MRZ_NAME_LENGTH) {
            padded[ID_CARD_MRZ_NAME_LENGTH + i] = ASCII_CODE_FOR_LESS_THAN;
        }
        padded
    } else {
        get_array_slice::<_, PASSPORT_MRZ_NAME_LENGTH>(mrz, PASSPORT_MRZ_NAME_INDEX)
    }
}

// -- Date of birth --

pub fn get_dob_from_mrz(dg1: DG1Data) -> MRZDOB {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_array_slice::<_, ID_CARD_MRZ_BIRTHDATE_LENGTH>(mrz, ID_CARD_MRZ_BIRTHDATE_INDEX)
    } else {
        get_array_slice::<_, PASSPORT_MRZ_BIRTHDATE_LENGTH>(mrz, PASSPORT_MRZ_BIRTHDATE_INDEX)
    }
}

pub fn get_yob_from_mrz(dg1: DG1Data) -> MRZYOB {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_array_slice::<_, ID_CARD_MRZ_YEAR_OF_BIRTH_LENGTH>(mrz, ID_CARD_MRZ_BIRTHDATE_INDEX)
    } else {
        get_array_slice::<_, PASSPORT_MRZ_YEAR_OF_BIRTH_LENGTH>(mrz, PASSPORT_MRZ_BIRTHDATE_INDEX)
    }
}

// -- Expiry date --

pub fn get_expiry_date_from_mrz(dg1: DG1Data) -> MRZExpiryDate {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_array_slice::<_, YYMMDD_DATE_LENGTH>(mrz, ID_CARD_MRZ_EXPIRY_DATE_INDEX)
    } else {
        get_array_slice::<_, YYMMDD_DATE_LENGTH>(mrz, PASSPORT_MRZ_EXPIRY_DATE_INDEX)
    }
}

// -- Document number --

pub fn get_document_number_from_mrz(dg1: DG1Data) -> MRZDocumentNumber {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_array_slice::<_, ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH>(
            mrz,
            ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX,
        )
    } else {
        get_array_slice::<_, PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH>(
            mrz,
            PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX,
        )
    }
}

// -- Byte packing --
// These functions pack byte arrays into field elements for efficient Poseidon2 hashing.
// A BN254 field can hold up to 31 bytes (248 bits).

pub fn pack_be_bytes_into_field<let NBytes: u32, let MAX_FIELD_SIZE_IN_BYTES: u32>(
    x: [u8; NBytes],
) -> Field {
    let mut result: Field = 0;
    for i in 0..NBytes {
        result *= 256;
        result += x[i] as Field;
    }
    std::as_witness(result);
    result
}

/// Pack NBytes big-endian bytes into N field elements, each holding up to 31 bytes.
/// The first field may hold fewer bytes if NBytes is not evenly divisible by 31.
pub fn pack_be_bytes_into_fields_sized<let NBytes: u32, let N: u32>(
    x: [u8; NBytes],
) -> [Field; N] {
    let max_field_bytes: u32 = 31;
    let mut result = [0 as Field; N];
    let mut limb: Field = 0;
    let mut k: u32 = 0;

    // First field may hold fewer bytes
    let first_chunk = max_field_bytes - (N * max_field_bytes - NBytes);
    for _j in 0..first_chunk {
        limb *= 256;
        limb += x[k] as Field;
        k += 1;
    }
    std::as_witness(limb);
    result[N - 1] = limb;

    for i in 1..N {
        let mut limb_inner: Field = 0;
        for _j in 0..max_field_bytes {
            limb_inner *= 256;
            limb_inner += x[k] as Field;
            k += 1;
        }
        std::as_witness(limb_inner);
        result[N - i - 1] = limb_inner;
    }
    result
}

pub fn pack_be_bytes_into_u128s<let NBytes: u32, let N: u32, let MAX_FIELD_SIZE_IN_BYTES: u32>(
    x: [u8; NBytes],
) -> [u128; N] {
    let mut result = [0 as u128; N];
    let padding: u32 = N * MAX_FIELD_SIZE_IN_BYTES - NBytes;

    for i in 0..N {
        let mut limb: Field = 0;
        for j in 0..MAX_FIELD_SIZE_IN_BYTES {
            let padded_idx = i * MAX_FIELD_SIZE_IN_BYTES + j;
            limb *= 256;
            if padded_idx >= padding {
                limb += x[padded_idx - padding] as Field;
            }
        }
        std::as_witness(limb);
        limb.assert_max_bit_size::<128>();
        result[N - 1 - i] = limb as u128;
    }
    result
}

// -- Poseidon2 hash of packed bytes --

pub fn poseidon2_hash_packed<let NUM_BYTES: u32>(padded_input: [u8; NUM_BYTES], len: u32) -> Field {
    let packed: [Field; (NUM_BYTES + 30) / 31] = pack_be_bytes_into_fields_sized(padded_input);
    let num_of_fields: u32 = (len + 31 - 1) / 31;
    Poseidon2::hash(packed, num_of_fields)
}

// -- ASN.1 DER length parser --
// Only provides a hint; the result is verified by subsequent hash checks.

pub unconstrained fn unsafe_get_asn1_element_length<let N: u32>(asn1: [u8; N]) -> u32 {
    let tag: u8 = asn1[0];
    let elem_len: u8 = asn1[1];

    assert(N >= 2, "TLV too short");
    assert((tag & 0x1F) < 0x1F, "High-tag-number form not supported");
    assert(elem_len != 0x80, "Indefinite length not supported");

    if (elem_len & 0x80) == 0 {
        // Short form
        let content_len: u32 = (elem_len & 0x7F) as u32;
        let total: u32 = 2 + content_len;
        assert(total <= N, "TLV exceeds buffer");
        total
    } else {
        // Long form
        let nlen: u32 = (elem_len & 0x7F) as u32;
        assert(nlen > 0, "Zero length-of-length");
        assert(nlen <= 4, "Length > 4 not supported");
        assert(2 + nlen <= N, "Length bytes exceed buffer");

        let mut content_len: u32 = 0;
        for i in 0..nlen {
            content_len = content_len * 256 + (asn1[2 + i] as u32);
        }
        let total: u32 = 2 + nlen + content_len;
        assert(total <= N, "TLV exceeds buffer");
        total
    }
}

// -- Subarray search --

pub fn find_subarray_index<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> u32 {
    // Safety: offset is only used as a starting point; we verify the match below
    let offset_unchecked = unsafe { find_subarray_index_unsafe(needle, haystack) };
    let mut offset = offset_unchecked;

    if (offset_unchecked < HAYSTACK_SIZE) & (offset_unchecked + NEEDLE_SIZE <= HAYSTACK_SIZE) {
        for i in 0..NEEDLE_SIZE {
            if haystack[i + offset_unchecked] != needle[i] {
                offset = HAYSTACK_SIZE;
            }
        }
    } else {
        offset = HAYSTACK_SIZE;
    }
    offset
}

pub fn is_subarray_in_array<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> bool {
    find_subarray_index(needle, haystack) < HAYSTACK_SIZE
}

unconstrained fn find_subarray_index_unsafe<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> u32 {
    let mut result = HAYSTACK_SIZE;
    if NEEDLE_SIZE == 0 {
        result = 0;
    } else if NEEDLE_SIZE <= HAYSTACK_SIZE {
        for i in 0..(HAYSTACK_SIZE - NEEDLE_SIZE + 1) {
            let mut found = true;
            for j in 0..NEEDLE_SIZE {
                if haystack[i + j] != needle[j] {
                    found = false;
                }
            }
            if found & (result == HAYSTACK_SIZE) {
                result = i;
            }
        }
    }
    result
}

// -- Integer encoding --

pub fn encode_integer_over_bytes<let NUM_BYTES: u32>(x: u32) -> [u8; NUM_BYTES] {
    let field_number = x as Field;
    let bytes: [u8; NUM_BYTES] = field_number.to_be_bytes();
    bytes
}

// -- Array split and concat --

pub fn split_array<let N: u32, let HALF: u32>(arr: [u8; N]) -> ([u8; HALF], [u8; HALF]) {
    let mut a: [u8; HALF] = [0; HALF];
    let mut b: [u8; HALF] = [0; HALF];
    for i in 0..HALF {
        a[i] = arr[i];
        b[i] = arr[HALF + i];
    }
    (a, b)
}

pub fn concat_arrays<let A: u32, let B: u32, let C: u32>(a: [u8; A], b: [u8; B]) -> [u8; C] {
    let mut result: [u8; C] = [0; C];
    for i in 0..A {
        result[i] = a[i];
    }
    for i in 0..B {
        result[A + i] = b[i];
    }
    result
}

// -- Zero-padding check --

pub fn check_zero_padding<T, let N: u32>(padded_array: [T; N], len: u32)
where
    T: Eq,
    T: Default,
{
    for i in 0..N {
        if i >= len {
            assert_eq(padded_array[i], std::mem::zeroed(), "Array is not zero-padded");
        }
    }
}
