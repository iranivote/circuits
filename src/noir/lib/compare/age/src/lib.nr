use poseidon::poseidon2::Poseidon2;
use utils::{
    get_dob_from_mrz,
    types::DG1Data,
};

/// Compare the passport holder's age against min/max bounds.
///
/// Extracts date of birth from MRZ, computes age relative to `current_date`
/// (unix timestamp in seconds), and asserts:
///   - age >= min_age_required
///   - age <= max_age_required (only if max_age_required > 0)
pub fn compare_age(
    dg1: DG1Data,
    min_age_required: u8,
    max_age_required: u8,
    current_date: u64,
) {
    let dob = get_dob_from_mrz(dg1);
    let ascii_zero: u64 = 48;

    let birth_yy = (dob[0] as u64 - ascii_zero) * 10 + (dob[1] as u64 - ascii_zero);
    let birth_mm = (dob[2] as u64 - ascii_zero) * 10 + (dob[3] as u64 - ascii_zero);
    let birth_dd = (dob[4] as u64 - ascii_zero) * 10 + (dob[5] as u64 - ascii_zero);

    // YY interpretation: >= 30 means 19XX, < 30 means 20XX
    // (someone born in 2030+ is unlikely to be voting any time soon)
    let birth_year = if birth_yy >= 30 { 1900 + birth_yy } else { 2000 + birth_yy };

    // Extract current date components from timestamp
    // Approximate: we use the same simplification as the expiry check
    let days_since_epoch = current_date / 86400;
    let approx_year = 1970 + days_since_epoch / 365;
    let day_in_year = days_since_epoch - (approx_year - 1970) * 365 - (approx_year - 1969) / 4;
    let approx_month = day_in_year / 30 + 1;
    let approx_day = day_in_year - (approx_month - 1) * 30;

    // Calculate age: subtract one year if birthday hasn't occurred yet this year
    let mut age = approx_year - birth_year;
    let birthday_not_yet = (approx_month < birth_mm)
        | ((approx_month == birth_mm) & (approx_day < birth_dd));
    if birthday_not_yet {
        age -= 1;
    }

    assert(age >= min_age_required as u64, "Below minimum age requirement");
    if max_age_required > 0 {
        assert(age <= max_age_required as u64, "Above maximum age requirement");
    }
}

/// Compute a parameter commitment binding the age bounds to the proof.
pub fn calculate_param_commitment(min_age_required: u8, max_age_required: u8) -> Field {
    Poseidon2::hash([min_age_required as Field, max_age_required as Field], 2)
}
