//! #

use bitcoin::{Script, Transaction, Txid};
use dlc::PartyParams;
use dlc_messages::oracle_msgs::OracleAttestation;
use lightning::ln::chan_utils::CounterpartyCommitmentSecrets;
use secp256k1_zkp::{EcdsaAdaptorSignature, PublicKey, Signature};

use crate::{ChannelId, ContractId};

use super::party_points::PartyBasePoints;

macro_rules! typed_enum {
    (
        $(#[$outer:meta])*
        pub enum $name:ident
        {
            $( #[$inner:meta]
                $vname:ident $({
                    $(
                        #[$inner_block:meta]
                        $field_name:ident : $field_type_name:ident$(<$param:ident>)?,
                    )*
                })?,
            )*
        },
        $(#[$type_meta:meta])*
        $type_name:ident,
    ) => {
        $(#[$outer])*
        pub enum $name {
            $( #[$inner]
                $vname $({
                    $(
                        #[$inner_block]
                        $field_name : $field_type_name$(<$param>)?,
                    )*
                })?,
            )*
        }

        impl $name {
            /// Returns whether the variant is of the given type.
            pub fn is_of_type(&self, t: &$type_name) -> bool {
                match t {
                    $(
                        $type_name::$vname => {
                            if let $name::$vname { .. } = self {
                                return true;
                            }
                            return false;
                        },
                    )*
                }
            }

            /// Returns the type associated with the variant.
            pub fn get_type(&self) -> $type_name {
                match self {
                    $(
                        $name::$vname {..} => $type_name::$vname,
                    )*
                }
            }
        }

        $(#[$type_meta])*
        pub enum $type_name {
            $(
                ///Type for [$name::$vname].
                $vname,
            )*
        }
    }
}

typed_enum!(
    #[derive(PartialEq, Clone, Debug)]
    ///
    pub enum SignedChannelState {
        ///
        Established {
            ///
            signed_contract_id: ContractId,
            ///
            counter_buffer_adaptor_signature: EcdsaAdaptorSignature,
            ///
            own_buffer_adaptor_signature: EcdsaAdaptorSignature,
            ///
            buffer_transaction: Transaction,
            ///
            is_offer: bool,
        },
        ///
        SettledOffered {
            ///
            counter_payout: u64,
            ///
            next_per_update_point: PublicKey,
        },
        ///
        SettledReceived {
            ///
            own_payout: u64,
            ///
            counter_next_per_update_point: PublicKey,
        },
        ///
        SettledAccepted {
            ///
            counter_next_per_update_point: PublicKey,
            ///
            own_next_per_update_point: PublicKey,
            ///
            own_settle_adaptor_signature: EcdsaAdaptorSignature,
            ///
            settle_tx: Transaction,
        },
        ///
        SettledConfirmed {
            ///
            settle_tx: Transaction,
            ///
            counter_settle_adaptor_signature: EcdsaAdaptorSignature,
            ///
            counter_next_per_update_point: PublicKey,
            ///
            own_next_per_update_point: PublicKey,
            ///
            own_settle_adaptor_signature: EcdsaAdaptorSignature,
        },
        ///
        Settled {
            ///
            settle_tx: Transaction,
            ///
            counter_settle_adaptor_signature: EcdsaAdaptorSignature,
            ///
            own_settle_adaptor_signature: EcdsaAdaptorSignature,
        },
        ///
        RenewOffered {
            ///
            offered_contract_id: ContractId,
            ///
            counter_payout: u64,
            ///
            offer_next_per_update_point: PublicKey,
            ///
            is_offer: bool,
        },
        ///
        RenewAccepted {
            ///
            contract_id: ContractId,
            ///
            offer_per_update_point: PublicKey,
            ///
            accept_per_update_point: PublicKey,
            ///
            buffer_transaction: Transaction,
            ///
            buffer_script_pubkey: Script,
            ///
            accept_buffer_adaptor_signature: EcdsaAdaptorSignature,
        },
        ///
        RenewConfirmed {
            ///
            contract_id: ContractId,
            ///
            offer_per_update_point: PublicKey,
            ///
            accept_per_update_point: PublicKey,
            ///
            buffer_transaction: Transaction,
            ///
            buffer_script_pubkey: Script,
            ///
            offer_buffer_adaptor_signature: EcdsaAdaptorSignature,
            ///
            accept_buffer_adaptor_signature: EcdsaAdaptorSignature,
        },
        ///
        Closing {
            ///
            buffer_tx: Transaction,
            ///
            signed_cet: Transaction,
            ///
            contract_id: ContractId,
            ///
            attestations: Vec<OracleAttestation>,
        },
        ///
        SettleClosing {},
        ///
        Closed,
        ///
        CounterClosed,
        ///
        ClosedPunished {
            ///
            punishment_txid: Txid,
        },
        ///
        CollaborativeCloseOffered {
            ///
            counter_payout: u64,
            ///
            offer_signature: Signature,
            ///
            close_tx: Transaction,
        },
        ///
        CollaborativelyClosed,
    },
    ///
    SignedChannelStateType,
);

///
#[derive(Clone)]
pub struct SignedChannel {
    ///
    pub channel_id: ChannelId,
    ///
    pub counter_party: PublicKey,
    ///
    pub temporary_channel_id: ChannelId,
    ///
    pub own_params: PartyParams,
    ///
    pub own_points: PartyBasePoints,
    ///
    pub own_per_update_point: PublicKey,
    ///
    pub own_per_update_seed: PublicKey,
    ///
    pub counter_points: PartyBasePoints,
    ///
    pub counter_per_update_point: PublicKey,
    ///
    pub counter_params: PartyParams,
    ///
    pub state: SignedChannelState,
    ///
    pub update_idx: u64,
    ///
    pub fund_tx: Transaction,
    ///
    pub fund_script_pubkey: Script,
    ///
    pub fund_output_index: usize,
    ///
    pub roll_back_state: Option<SignedChannelState>,
    ///
    pub counter_party_commitment_secrets: CounterpartyCommitmentSecrets,
    ///
    pub fee_rate_per_vb: u64,
}
