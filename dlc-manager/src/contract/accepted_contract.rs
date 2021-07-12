//! # AcceptedContract

use super::offered_contract::OfferedContract;
use super::{AdaptorInfo, FundingInputInfo};
use dlc::{DlcTransactions, PartyParams};
use secp256k1_zkp::EcdsaAdaptorSignature;
use secp256k1_zkp::Signature;

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
    /// https://github.com/discreetlogcontracts/dlcspecs/blob/master/Protocol.md#requirements-2
    pub fn get_contract_id(&self) -> [u8; 32] {
        let fund_output_index = self.dlc_transactions.get_fund_output_index();
        let contract_id_vec: Vec<_> = self
            .dlc_transactions
            .fund
            .txid()
            .as_ref()
            .iter()
            .zip(
                std::iter::repeat(&(0 as u8))
                    .take(28)
                    .chain((fund_output_index as u32).to_be_bytes().iter()),
            )
            .zip(self.offered_contract.id.iter())
            .map(|((x, y), z)| x ^ y ^ z)
            .collect();

        let mut contract_id = [0u8; 32];

        for i in 0..32 {
            contract_id[i] = contract_id_vec[i];
        }

        contract_id
    }

    /// Utility function to get the contract id as a string.
    pub fn get_contract_id_string(&self) -> String {
        let mut string_id = String::with_capacity(32 * 2 + 2);
        string_id.push_str("0x");
        let id = self.get_contract_id();
        for i in &id {
            string_id.push_str(&std::format!("{:02x}", i));
        }

        string_id
    }
}
