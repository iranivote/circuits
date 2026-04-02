/// Compare two YYMMDD dates encoded as ASCII byte arrays.
/// Returns true if date_a is before date_b.
pub fn is_date_before(date_a: [u8; 6], date_b: [u8; 6]) -> bool {
    let mut a_val: u32 = 0;
    let mut b_val: u32 = 0;
    for i in 0..6 {
        a_val = a_val * 100 + (date_a[i] as u32 - 48);
        b_val = b_val * 100 + (date_b[i] as u32 - 48);
    }
    a_val < b_val
}
