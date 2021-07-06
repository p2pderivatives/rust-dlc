const APPROXIMATE_CET_VBYTES: u64 = 190;
const APPROXIMATE_CLOSING_VBYTES: u64 = 168;

pub fn get_common_fee(fee_rate: u64) -> u64 {
    (APPROXIMATE_CET_VBYTES + APPROXIMATE_CLOSING_VBYTES) * fee_rate
}

pub fn get_half_common_fee(fee_rate: u64) -> u64 {
    let common_fee = get_common_fee(fee_rate);
    (common_fee as f64 / 2_f64).ceil() as u64
}

mod tests {
    // use dlc::digit_decomposition::pad_range_payouts;
    // use dlc::RangePayout;

    // fn s_curve_test() {
    //     let mut outcomes = Vec::<RangePayout>::new();
    //     const NB_PAYOUTS: usize = 100;
    //     for i in 0..(NB_PAYOUTS as usize) {
    //         outcomes.push(RangePayout {
    //             start: (NB_PAYOUTS as usize) + i,
    //             count: 1,
    //             payout: payouts[i].clone(),
    //         })
    //     }
    //     let outcomes = pad_range_payouts(outcomes, base, nb_digits);
    // }
}
