use commitment::commit_to_id;
use sig_verify_rsa::verify_rsa_signature;
use utils::types::{DG1Data, EContentData, SignedAttrsData};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey: [u8; 512],
    dsc_pubkey_redc_param: [u8; 513],
    sod_signature: [u8; 512],
    tbs_certificate: [u8; 1200],
    tbs_len: u32,
    signed_attributes: SignedAttrsData,
    exponent: u32,
    e_content: EContentData,
    key_size: u8,
    hash_type: u8,
    padding_type: u8,
    pss_salt_len: u32,
    sig_len: u32,
    pubkey_offset_in_tbs: u32,
    pubkey_len: u32,
) -> pub Field {
    assert(pubkey_offset_in_tbs + pubkey_len <= 1200, "Pubkey offset out of TBS bounds");
    for i in 0..512 {
        if i < pubkey_len {
            assert(
                dsc_pubkey[i] == tbs_certificate[pubkey_offset_in_tbs + i],
                "RSA pubkey mismatch in TBS certificate",
            );
        }
    }

    // Safety: ASN.1 length parsing is unconstrained; the result is only used
    // to bound iteration in the constrained sig-verify and is checked there.
    let signed_attributes_size = unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };

    let mut sa_padded: [u8; 1200] = [0; 1200];
    for i in 0..256 {
        sa_padded[i] = signed_attributes[i];
    }

    assert(
        verify_rsa_signature(
            dsc_pubkey, sod_signature, dsc_pubkey_redc_param, exponent,
            sa_padded, signed_attributes_size, key_size, hash_type, padding_type, pss_salt_len,
        ),
        "DSC RSA signature verification failed on signed attributes",
    );

    commit_to_id(
        comm_in, salt_in, salt_out, dg1, tbs_certificate, tbs_len,
        sod_signature, sig_len, signed_attributes,
        signed_attributes_size as Field, e_content,
    )
}
