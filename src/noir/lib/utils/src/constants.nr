// DG1 / MRZ dimensions
// Passport (TD3): DG1 = 5-byte TLV header + 88-byte MRZ = 93 bytes
// ID card  (TD1): DG1 = 5-byte TLV header + 90-byte MRZ = 95 bytes
// We use 95 as max to accommodate both; passport leaves last 2 bytes zero.
pub global DG1_MAX_LENGTH: u32 = 95;
pub global DG1_LENGTH: u32 = 95;
pub global DG1_TO_MRZ_OFFSET: u32 = 5;

// Passport MRZ is 88 chars (2 x 44), ID card MRZ is 90 chars (3 x 30).
pub global MAX_MRZ_LENGTH: u32 = 90;

// Signed attributes / eContent buffer sizes
pub global SIGNED_ATTRS_LENGTH: u32 = 256;
pub global ECONTENT_LENGTH: u32 = 512;

// Date fields
pub global YYMMDD_DATE_LENGTH: u32 = 6;

// Hash digest lengths
pub global SHA1_DIGEST_LENGTH: u32 = 20;
pub global SHA224_DIGEST_LENGTH: u32 = 28;
pub global SHA256_DIGEST_LENGTH: u32 = 32;
pub global SHA384_DIGEST_LENGTH: u32 = 48;
pub global SHA512_DIGEST_LENGTH: u32 = 64;

// Identifiers for the hash type stored alongside DG2 hash (one byte each)
pub global SHA1_IDENTIFIER: [u8; 1] = [1];
pub global SHA224_IDENTIFIER: [u8; 1] = [2];
pub global SHA256_IDENTIFIER: [u8; 1] = [3];
pub global SHA384_IDENTIFIER: [u8; 1] = [4];
pub global SHA512_IDENTIFIER: [u8; 1] = [5];

// Passport (TD3) MRZ field offsets and lengths
// ICAO 9303-4, Appendix B -- TD3 format (2 lines of 44 chars)
//
// Line 1: positions 0-43
//   [0]       Document type ('P')
//   [1]       Document subtype ('<')
//   [2..4]    Issuing state (3 chars)
//   [5..43]   Name (39 chars)
//
// Line 2: positions 44-87
//   [44..52]  Document number (9 chars)
//   [53]      Check digit
//   [54..56]  Nationality (3 chars)
//   [57..62]  Date of birth YYMMDD (6 chars)
//   [63]      Check digit
//   [64]      Sex
//   [65..70]  Expiry date YYMMDD (6 chars)
//   [71]      Check digit
//   [72..85]  Optional data (14 chars)
//   [86]      Check digit
//   [87]      Overall check digit

pub global PASSPORT_MRZ_ISSUING_COUNTRY_INDEX: u32 = 2;
pub global PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH: u32 = 3;

pub global PASSPORT_MRZ_NAME_INDEX: u32 = 5;
pub global PASSPORT_MRZ_NAME_LENGTH: u32 = 39;

pub global PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX: u32 = 44;
pub global PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH: u32 = 9;

pub global PASSPORT_MRZ_NATIONALITY_INDEX: u32 = 54;
pub global PASSPORT_MRZ_NATIONALITY_LENGTH: u32 = 3;

pub global PASSPORT_MRZ_BIRTHDATE_INDEX: u32 = 57;
pub global PASSPORT_MRZ_BIRTHDATE_LENGTH: u32 = 6;
pub global PASSPORT_MRZ_YEAR_OF_BIRTH_LENGTH: u32 = 2;

pub global PASSPORT_MRZ_EXPIRY_DATE_INDEX: u32 = 65;

// ID card (TD1) MRZ field offsets and lengths
// ICAO 9303-5, Appendix B -- TD1 format (3 lines of 30 chars)
//
// Line 1: positions 0-29
//   [0..1]    Document type
//   [2..4]    Issuing state (3 chars)
//   [5..13]   Document number (9 chars)
//   [14]      Check digit
//   [15..29]  Optional data
//
// Line 2: positions 30-59
//   [30..35]  Date of birth YYMMDD
//   [36]      Check digit
//   [37]      Sex
//   [38..43]  Expiry date YYMMDD
//   [44]      Check digit
//   [45..55]  Nationality (3 chars at 45..47) + optional data
//   [59]      Overall check digit
//
// Line 3: positions 60-89
//   [60..89]  Name (30 chars)

pub global ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX: u32 = 5;
pub global ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH: u32 = 9;

pub global ID_CARD_MRZ_BIRTHDATE_INDEX: u32 = 30;
pub global ID_CARD_MRZ_BIRTHDATE_LENGTH: u32 = 6;
pub global ID_CARD_MRZ_YEAR_OF_BIRTH_LENGTH: u32 = 2;

pub global ID_CARD_MRZ_EXPIRY_DATE_INDEX: u32 = 38;

pub global ID_CARD_MRZ_NATIONALITY_INDEX: u32 = 45;
pub global ID_CARD_MRZ_NATIONALITY_LENGTH: u32 = 3;

pub global ID_CARD_MRZ_NAME_INDEX: u32 = 60;
pub global ID_CARD_MRZ_NAME_LENGTH: u32 = 30;

// ASCII constants
pub global ASCII_CODE_FOR_LESS_THAN: u8 = 60; // '<' used as MRZ filler

// Nullifier type constants
pub global NON_SALTED_NULLIFIER: Field = 1;
pub global SALTED_NULLIFIER: Field = 2;
pub global NON_SALTED_MOCK_NULLIFIER: Field = 3;
pub global SALTED_MOCK_NULLIFIER: Field = 4;

// Proof type identifiers
pub global PROOF_TYPE_AGE: Field = 1;
pub global PROOF_TYPE_BIRTHDATE: Field = 2;
pub global PROOF_TYPE_EXPIRY: Field = 3;
pub global PROOF_TYPE_NATIONALITY_INCLUSION: Field = 4;
pub global PROOF_TYPE_NATIONALITY_EXCLUSION: Field = 5;
pub global PROOF_TYPE_ISSUING_COUNTRY_INCLUSION: Field = 6;
pub global PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION: Field = 7;
pub global PROOF_TYPE_DISCLOSE: Field = 8;
pub global PROOF_TYPE_BIND: Field = 9;
pub global PROOF_TYPE_SANCTIONS: Field = 10;
