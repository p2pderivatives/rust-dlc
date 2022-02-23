//! # AcceptedContract

use super::offered_contract::OfferedContract;
use super::{AdaptorInfo, FundingInputInfo};
use dlc::{DlcTransactions, PartyParams};
use dlc_messages::{AcceptDlc, CetAdaptorSignature, CetAdaptorSignatures};
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
    /// <https://github.com/discreetlogcontracts/dlcspecs/blob/master/Protocol.md#requirements-2>
    pub fn get_contract_id(&self) -> [u8; 32] {
        crate::utils::compute_id(
            self.dlc_transactions.fund.txid(),
            self.dlc_transactions.get_fund_output_index() as u16,
            &self.offered_contract.id,
        )
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

    pub(crate) fn get_accept_contract_msg(
        &self,
        ecdsa_adaptor_signatures: Vec<EcdsaAdaptorSignature>,
    ) -> AcceptDlc {
        AcceptDlc {
            temporary_contract_id: self.offered_contract.id,
            accept_collateral: self.accept_params.collateral,
            funding_pubkey: self.accept_params.fund_pubkey,
            payout_spk: self.accept_params.payout_script_pubkey.clone(),
            payout_serial_id: self.accept_params.payout_serial_id,
            funding_inputs: self.funding_inputs.iter().map(|x| x.into()).collect(),
            change_spk: self.accept_params.change_script_pubkey.clone(),
            change_serial_id: self.accept_params.change_serial_id,
            cet_adaptor_signatures: CetAdaptorSignatures {
                ecdsa_adaptor_signatures: ecdsa_adaptor_signatures
                    .into_iter()
                    .map::<CetAdaptorSignature, _>(|x| CetAdaptorSignature { signature: x })
                    .collect(),
            },
            refund_signature: self.accept_refund_signature,
            negotiation_fields: None,
        }
    }
}
