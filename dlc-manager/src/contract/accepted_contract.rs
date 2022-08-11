//! # AcceptedContract

use super::offered_contract::OfferedContract;
use super::{AdaptorInfo, FundingInputInfo};
use bitcoin::Txid;
use dlc::{DlcTransactions, PartyParams};
use secp256k1_zkp::EcdsaAdaptorSignature;
use secp256k1_zkp::Signature;

use std::fmt::Write as _;

/// An AcceptedContract represents a contract in the accepted state.
#[derive(Clone)]
pub struct AcceptedContract {
    /// The offered contract that was accepted.
    pub offered_contract: OfferedContract,
    /// The parameters of the accepting party.
    pub accept_params: PartyParams,
    /// The funding inputs provided by the accepting party.
    pub funding_inputs: Vec<FundingInputInfo>,
    /// The adaptor information for the contract storing information about
    /// the relation between adaptor signatures and outcomes.
    pub adaptor_infos: Vec<AdaptorInfo>,
    /// The adaptor signatures of the accepting party. Note that the accepting
    /// party does not keep them thus an option is used.
    pub adaptor_signatures: Option<Vec<EcdsaAdaptorSignature>>,
    /// The signature for the refund transaction from the accepting party.
    pub accept_refund_signature: Signature,
    /// The bitcoin set of bitcoin transactions for the contract.
    pub dlc_transactions: DlcTransactions,
}

impl AcceptedContract {
    /// Returns the contract id for the contract computed as specified here:
    /// <https://github.com/discreetlogcontracts/dlcspecs/blob/master/Protocol.md#requirements-2>
    pub fn get_contract_id(&self) -> [u8; 32] {
        compute_contract_id(
            self.dlc_transactions.fund.txid(),
            self.dlc_transactions.get_fund_output_index() as u16,
            self.offered_contract.id,
        )
    }

    /// Utility function to get the contract id as a string.
    pub fn get_contract_id_string(&self) -> String {
        let mut string_id = String::with_capacity(32 * 2 + 2);
        string_id.push_str("0x");
        let id = self.get_contract_id();
        for i in &id {
            write!(string_id, "{:02x}", i).unwrap();
        }

        string_id
    }
}

fn compute_contract_id(
    fund_tx_id: Txid,
    fund_ouput_index: u16,
    temporary_contract_id: [u8; 32],
) -> [u8; 32] {
    let mut res = [0; 32];
    for i in 0..32 {
        res[i] = fund_tx_id[31 - i] ^ temporary_contract_id[i];
    }
    res[30] ^= ((fund_ouput_index >> 8) & 0xff) as u8;
    res[31] ^= (fund_ouput_index & 0xff) as u8;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_id_computation_test() {
        let transaction = bitcoin_test_utils::tx_from_string("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020000ffffffff0101000000000000000000000000");
        let output_index = 1;
        let temporary_contract_id = [34u8; 32];
        let expected_contract_id = bitcoin_test_utils::str_to_hex(
            "81db60dcbef10a2d0cb92cb78400a96ee6a9b6da785d0230bdabf1e18a2d6ffb",
        );

        let contract_id =
            compute_contract_id(transaction.txid(), output_index, temporary_contract_id);

        assert_eq!(expected_contract_id, contract_id);
    }
}
