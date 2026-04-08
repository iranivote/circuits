use commitment::commit_to_id;
use sig_verify_ecdsa::verify_ecdsa_signature;
use utils::types::{DG1Data, EContentData, SignedAttrsData};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey_x: [u8; 66],
    dsc_pubkey_y: [u8; 66],
    sod_sig_r: [u8; 66],
    sod_sig_s: [u8; 66],
    tbs_certificate: [u8; 1200],
    tbs_len: u32,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    curve_type: u8,
    hash_type: u8,
    sig_len: u32,
    pubkey_offset_in_tbs: u32,
    pubkey_len: u32,
) -> pub Field {
    let mut pubkey_concat: [u8; 132] = [0; 132];
    for i in 0..66 {
        pubkey_concat[i] = dsc_pubkey_x[i];
        pubkey_concat[66 + i] = dsc_pubkey_y[i];
    }
    assert(pubkey_offset_in_tbs + pubkey_len <= 1200, "Pubkey offset out of TBS bounds");
    for i in 0..132 {
        if i < pubkey_len {
            assert(
                pubkey_concat[i] == tbs_certificate[pubkey_offset_in_tbs + i],
                "ECDSA pubkey mismatch in TBS certificate",
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
        verify_ecdsa_signature(
            dsc_pubkey_x, dsc_pubkey_y, sod_sig_r, sod_sig_s,
            sa_padded, signed_attributes_size, curve_type, hash_type,
        ),
        "DSC ECDSA signature verification failed on signed attributes",
    );

    let mut sig_concat: [u8; 132] = [0; 132];
    for i in 0..66 {
        sig_concat[i] = sod_sig_r[i];
        sig_concat[66 + i] = sod_sig_s[i];
    }

    commit_to_id(
        comm_in, salt_in, salt_out, dg1, tbs_certificate, tbs_len,
        sig_concat, sig_len, signed_attributes,
        signed_attributes_size as Field, e_content,
    )
}
