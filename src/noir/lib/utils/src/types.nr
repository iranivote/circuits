use crate::constants::{
    DG1_MAX_LENGTH, MAX_MRZ_LENGTH, ECONTENT_LENGTH, SIGNED_ATTRS_LENGTH,
    YYMMDD_DATE_LENGTH, PASSPORT_MRZ_NAME_LENGTH, PASSPORT_MRZ_NATIONALITY_LENGTH,
    PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH, PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH,
    PASSPORT_MRZ_BIRTHDATE_LENGTH,
};
use poseidon::poseidon2::Poseidon2;

// Core data types matching ICAO 9303 passport structure
pub type DG1Data = [u8; DG1_MAX_LENGTH];
pub type MRZData = [u8; MAX_MRZ_LENGTH];
pub type EContentData = [u8; ECONTENT_LENGTH];
pub type SignedAttrsData = [u8; SIGNED_ATTRS_LENGTH];

// MRZ field types
pub type MRZName = [u8; PASSPORT_MRZ_NAME_LENGTH];
pub type MRZDOB = [u8; PASSPORT_MRZ_BIRTHDATE_LENGTH];
pub type MRZYOB = [u8; 2];
pub type MRZNationality = [u8; PASSPORT_MRZ_NATIONALITY_LENGTH];
pub type MRZIssuingCountry = [u8; PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH];
pub type MRZDocumentNumber = [u8; PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH];
pub type MRZExpiryDate = [u8; YYMMDD_DATE_LENGTH];

pub type Alpha2CountryCode = str<2>;
pub type Alpha3CountryCode = str<3>;

// Mask for selective disclosure (one bit per MRZ byte)
pub type DiscloseMask = [u8; MAX_MRZ_LENGTH];

/// A value paired with a salt, committed via Poseidon2 so the value can be
/// passed between sub-circuits without revealing it to the verifier.
pub struct SaltedValue<let N: u32> {
    pub salt: Field,
    pub value: [u8; N],
}

impl<let N: u32> SaltedValue<N> {
    pub fn from_value(salt: Field, value: [u8; N]) -> Self {
        SaltedValue { salt, value }
    }

    pub fn get_hash(self) -> Field {
        let packed: [Field; (N + 30) / 31] = crate::pack_be_bytes_into_fields_sized(self.value);
        let num_fields: u32 = (N + 30) / 31;
        let mut inputs: [Field; (N + 30) / 31 + 1] = std::mem::zeroed();
        inputs[0] = self.salt;
        for i in 0..num_fields {
            inputs[1 + i] = packed[i];
        }
        Poseidon2::hash(inputs, num_fields + 1)
    }
}
