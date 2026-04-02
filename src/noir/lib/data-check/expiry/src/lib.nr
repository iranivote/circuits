use utils::{
    get_expiry_date_from_mrz,
    types::DG1Data,
};

/// Convert a YYMMDD MRZ date (ASCII digits) to a Unix-ish timestamp (seconds since epoch).
/// The YY is interpreted as 20YY for passport expiry (all active passports expire after 2000).
fn mrz_date_to_timestamp(date_bytes: [u8; 6]) -> u64 {
    let ascii_zero: u64 = 48;
    let yy = (date_bytes[0] as u64 - ascii_zero) * 10 + (date_bytes[1] as u64 - ascii_zero);
    let mm = (date_bytes[2] as u64 - ascii_zero) * 10 + (date_bytes[3] as u64 - ascii_zero);
    let dd = (date_bytes[4] as u64 - ascii_zero) * 10 + (date_bytes[5] as u64 - ascii_zero);

    let year = 2000 + yy;
    // Approximate days since epoch (Jan 1 1970).
    // Exact leap-year handling is not critical here because a few-day error
    // is acceptable for expiry checking. The same approximation is used by ZKPassport.
    let days = (year - 1970) * 365 + (year - 1969) / 4 + (mm - 1) * 30 + dd;
    days * 86400
}

/// Assert that the passport (from DG1) has not expired relative to `current_date` (unix timestamp).
pub fn check_expiry(dg1: DG1Data, current_date: u64) {
    let expiry_bytes = get_expiry_date_from_mrz(dg1);
    let expiry_ts = mrz_date_to_timestamp(expiry_bytes);
    assert(current_date < expiry_ts, "Passport has expired");
}

/// Same check but takes the expiry date bytes directly (for use from salted values).
pub fn check_expiry_from_date(expiry_bytes: [u8; 6], current_date: u64) {
    let expiry_ts = mrz_date_to_timestamp(expiry_bytes);
    assert(current_date < expiry_ts, "Passport has expired");
}
