use bitcoin::Txid;
#[cfg(not(feature = "fuzztarget"))]
use secp256k1_zkp::rand::{thread_rng, Rng, RngCore};

const APPROXIMATE_CET_VBYTES: u64 = 190;
const APPROXIMATE_CLOSING_VBYTES: u64 = 168;

pub fn get_common_fee(fee_rate: u64) -> u64 {
    (APPROXIMATE_CET_VBYTES + APPROXIMATE_CLOSING_VBYTES) * fee_rate
}

pub fn get_half_common_fee(fee_rate: u64) -> u64 {
    let common_fee = get_common_fee(fee_rate);
    (common_fee as f64 / 2_f64).ceil() as u64
}

#[cfg(not(feature = "fuzztarget"))]
pub(crate) fn get_new_serial_id() -> u64 {
    thread_rng().next_u64()
}

#[cfg(feature = "fuzztarget")]
pub(crate) fn get_new_serial_id() -> u64 {
    use rand_chacha::rand_core::RngCore;
    use rand_chacha::rand_core::SeedableRng;
    rand_chacha::ChaCha8Rng::from_seed([0u8; 32]).next_u64()
}

#[cfg(not(feature = "fuzztarget"))]
pub(crate) fn get_new_temporary_id() -> [u8; 32] {
    thread_rng().gen::<[u8; 32]>()
}

#[cfg(feature = "fuzztarget")]
pub(crate) fn get_new_temporary_id() -> [u8; 32] {
    use rand_chacha::rand_core::RngCore;
    use rand_chacha::rand_core::SeedableRng;
    let mut res = [0u8; 32];
    rand_chacha::ChaCha8Rng::from_seed([0u8; 32]).fill_bytes(&mut res);
    res
}

pub(crate) fn compute_id(
    fund_tx_id: Txid,
    fund_output_index: u16,
    temporary_id: &[u8; 32],
) -> [u8; 32] {
    let mut res = [0; 32];
    for i in 0..32 {
        res[i] = fund_tx_id[31 - i] ^ temporary_id[i];
    }
    res[30] ^= ((fund_output_index >> 8) & 0xff) as u8;
    res[31] ^= (fund_output_index & 0xff) as u8;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_computation_test() {
        let transaction = bitcoin_test_utils::tx_from_string("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020000ffffffff0101000000000000000000000000");
        let output_index = 1;
        let temporary_id = [34u8; 32];
        let expected_id = bitcoin_test_utils::str_to_hex(
            "81db60dcbef10a2d0cb92cb78400a96ee6a9b6da785d0230bdabf1e18a2d6ffb",
        );

        let id = compute_id(transaction.txid(), output_index, &temporary_id);

        assert_eq!(expected_id, id);
    }
}
