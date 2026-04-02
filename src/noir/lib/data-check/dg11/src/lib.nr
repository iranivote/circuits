use sha256::sha256_var;

// ICAO 9303-10: DG11 Additional Personal Details
// Tag 0x5F42 = Place of Birth (two-byte tag: 0x5F, 0x42)
global DG11_TAG_PLACE_OF_BIRTH_HI: u8 = 0x5F;
global DG11_TAG_PLACE_OF_BIRTH_LO: u8 = 0x42;

pub global DG11_MAX_LENGTH: u32 = 512;
pub global PLACE_OF_BIRTH_MAX_LENGTH: u32 = 64;

/// Extract the Place of Birth field from DG11 by scanning for tag 0x5F42.
/// Returns (place_of_birth_bytes, actual_length).
pub fn extract_place_of_birth(
    dg11: [u8; DG11_MAX_LENGTH],
    dg11_len: u32,
) -> ([u8; PLACE_OF_BIRTH_MAX_LENGTH], u32) {
    // Safety: scanning is done unconstrained; the result is verified by
    // checking DG11's hash against eContent
    let (offset, pob_len) = unsafe { find_pob_tag(dg11, dg11_len) };

    assert(offset + pob_len <= dg11_len, "POB field exceeds DG11 bounds");
    assert(pob_len <= PLACE_OF_BIRTH_MAX_LENGTH, "POB too long");

    // Verify the tag bytes at the found offset
    assert(dg11[offset - 2 - length_encoding_size(pob_len)] == DG11_TAG_PLACE_OF_BIRTH_HI, "Tag hi mismatch");
    assert(dg11[offset - 1 - length_encoding_size(pob_len)] == DG11_TAG_PLACE_OF_BIRTH_LO, "Tag lo mismatch");

    let mut pob: [u8; PLACE_OF_BIRTH_MAX_LENGTH] = [0; PLACE_OF_BIRTH_MAX_LENGTH];
    for i in 0..PLACE_OF_BIRTH_MAX_LENGTH {
        if i < pob_len {
            pob[i] = dg11[offset + i];
        }
    }
    (pob, pob_len)
}

fn length_encoding_size(len: u32) -> u32 {
    if len < 128 { 1 } else if len < 256 { 2 } else { 3 }
}

unconstrained fn find_pob_tag(
    dg11: [u8; DG11_MAX_LENGTH],
    dg11_len: u32,
) -> (u32, u32) {
    let mut content_offset: u32 = 0;
    let mut content_len: u32 = 0;
    let mut found = false;

    let mut i: u32 = 0;
    // Skip the outer DG11 tag + length
    if dg11_len > 2 {
        // Skip tag byte
        i = 1;
        // Parse outer length
        if (dg11[i] & 0x80) != 0 {
            let nlen = (dg11[i] & 0x7F) as u32;
            i += 1 + nlen;
        } else {
            i += 1;
        }
    }

    // Scan for 0x5F42 tag
    for _iter in 0..256 {
        if (i + 2 < dg11_len) & !found {
            if (dg11[i] == DG11_TAG_PLACE_OF_BIRTH_HI) & (dg11[i + 1] == DG11_TAG_PLACE_OF_BIRTH_LO) {
                // Found the tag, parse length
                let len_byte = dg11[i + 2];
                if (len_byte & 0x80) == 0 {
                    content_len = len_byte as u32;
                    content_offset = i + 3;
                } else if (len_byte & 0x7F) == 1 {
                    content_len = dg11[i + 3] as u32;
                    content_offset = i + 4;
                } else {
                    content_len = (dg11[i + 3] as u32) * 256 + (dg11[i + 4] as u32);
                    content_offset = i + 5;
                }
                found = true;
            } else {
                // Skip this TLV element
                if dg11[i] == 0x5F {
                    // Two-byte tag
                    let len_byte = dg11[i + 2];
                    if (len_byte & 0x80) == 0 {
                        i += 3 + (len_byte as u32);
                    } else if (len_byte & 0x7F) == 1 {
                        i += 4 + (dg11[i + 3] as u32);
                    } else {
                        let elen = (dg11[i + 3] as u32) * 256 + (dg11[i + 4] as u32);
                        i += 5 + elen;
                    }
                } else {
                    // Single-byte tag
                    let len_byte = dg11[i + 1];
                    if (len_byte & 0x80) == 0 {
                        i += 2 + (len_byte as u32);
                    } else if (len_byte & 0x7F) == 1 {
                        i += 3 + (dg11[i + 2] as u32);
                    } else {
                        let elen = (dg11[i + 2] as u32) * 256 + (dg11[i + 3] as u32);
                        i += 4 + elen;
                    }
                }
            }
        }
    }
    assert(found, "Place of Birth tag (0x5F42) not found in DG11");
    (content_offset, content_len)
}

/// Verify SHA-256(DG11) matches the expected hash.
/// The expected hash comes from eContent (verified separately in integrity check).
pub fn check_dg11_sha256(
    dg11: [u8; DG11_MAX_LENGTH],
    dg11_len: u32,
    expected_hash: [u8; 32],
) {
    let computed = sha256_var(dg11, dg11_len);
    assert(computed == expected_hash, "DG11 SHA-256 hash mismatch");
}
