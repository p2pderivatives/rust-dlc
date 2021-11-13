use crate::OracleNumericInfo;

pub(crate) fn same_num_digits_oracle_numeric_infos(
    nb_oracles: usize,
    nb_digits: usize,
    base: usize,
) -> OracleNumericInfo {
    OracleNumericInfo {
        nb_digits: std::iter::repeat(nb_digits).take(nb_oracles).collect(),
        base,
    }
}

pub(crate) fn get_variable_oracle_numeric_infos(
    nb_digits: &[usize],
    base: usize,
) -> OracleNumericInfo {
    OracleNumericInfo {
        base,
        nb_digits: nb_digits.to_vec(),
    }
}
