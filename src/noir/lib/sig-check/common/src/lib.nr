use sha1::sha1;
use sha256::sha256_var;
use sha512::{sha384, sha512};

pub fn sha256_and_check_data_to_sign<let DATA_LEN: u32>(
    data: [u8; DATA_LEN],
    data_len: u32,
) -> [u8; 32] {
    sha256_var(data, data_len)
}

pub fn sha1_and_check_data_to_sign<let DATA_LEN: u32>(
    data: [u8; DATA_LEN],
    data_len: u32,
) -> [u8; 20] {
    let bounded = BoundedVec::from_parts(data, data_len);
    sha1::sha1_var(bounded)
}

pub fn sha384_and_check_data_to_sign<let DATA_LEN: u32>(
    data: [u8; DATA_LEN],
    data_len: u32,
) -> [u8; 48] {
    let bounded = BoundedVec::from_parts(data, data_len);
    sha384::sha384_var(bounded)
}

pub fn sha512_and_check_data_to_sign<let DATA_LEN: u32>(
    data: [u8; DATA_LEN],
    data_len: u32,
) -> [u8; 64] {
    let bounded = BoundedVec::from_parts(data, data_len);
    sha512::sha512_var(bounded)
}
