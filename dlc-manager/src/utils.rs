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
