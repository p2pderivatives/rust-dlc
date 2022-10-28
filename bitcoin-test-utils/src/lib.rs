//! Utility functions to be used only in tests.

extern crate bitcoin;
extern crate bitcoincore_rpc;
extern crate bitcoincore_rpc_json;

use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::Transaction;
use std::fmt::Write;

pub mod rpc_helpers;

/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
#[allow(clippy::result_unit_err)] // This is just a test util
pub fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err(());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return Err(()),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}

/// Transforms an hex string to a Vec<u8>.
/// Panics if the string is not valid hex.
pub fn str_to_hex(hex_str: &str) -> Vec<u8> {
    let mut hex = Vec::<u8>::new();
    hex.resize(hex_str.len() / 2, 0);
    from_hex(hex_str, &mut hex).unwrap();
    hex
}

/// Serialize a transaction to an lower hex string.
pub fn tx_to_string(tx: &Transaction) -> String {
    let mut writer = Vec::new();
    tx.consensus_encode(&mut writer).unwrap();
    let mut serialized = String::new();
    for x in writer {
        write!(&mut serialized, "{:02x}", x).unwrap();
    }
    serialized
}

/// Deserialize an hex string to a bitcoin transaction.
/// Panics if given invalid hex or data.
pub fn tx_from_string(tx_str: &str) -> Transaction {
    let tx_hex = str_to_hex(tx_str);
    Transaction::consensus_decode(&mut tx_hex.as_slice()).unwrap()
}
