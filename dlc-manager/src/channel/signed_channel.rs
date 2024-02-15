//! # A channel is considered signed once the local party has signed the funding
//! transaction inputs. This module contains the model for a signed channel,
//! the possible states in which it can be as well as methods to work with it.

use bitcoin::{Script, Transaction};
use dlc::PartyParams;
use lightning::ln::{chan_utils::CounterpartyCommitmentSecrets, ChannelId};
use secp256k1_zkp::{ecdsa::Signature, EcdsaAdaptorSignature, PublicKey};

use crate::{ContractId, DlcChannelId, ReferenceId};

use super::party_points::PartyBasePoints;

macro_rules! typed_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident
        {
            $( $(#[$inner:meta])*
                $vname:ident $({
                    $(
                        $(#[$inner_block:meta])*
                        $field_name:ident : $field_type_name:ident$(<$param:ident>)?,
                    )*
                })?,
            )*
        },
        $(#[$type_meta:meta])*
        $type_name:ident,
    ) => {
        $(#[$meta])*
        pub enum $name {
            $( $(#[$inner])*
                $vname $({
                    $(
                        $(#[$inner_block])*
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

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                match self {
                    $(
                        $name::$vname {..} => f.write_str(stringify!($vname)),
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
    #[derive(Eq, PartialEq, Clone, Debug)]
    /// Contains the possible states in which a [`SignedChannel`] can be.
    pub enum SignedChannelState {
        /// A [`SignedChannel`] is in `Established` state when a contract is fully
        /// setup inside the channel.
        Established {
            /// The [`crate::ContractId`] of the contract currently setup in the
            /// channel.
            signed_contract_id: ContractId,
            /// The adaptor signature created by the counter party for the buffer
            /// transaction.
            counter_buffer_adaptor_signature: EcdsaAdaptorSignature,
            /// The adaptor signature created by the local party for the buffer
            /// transaction.
            own_buffer_adaptor_signature: EcdsaAdaptorSignature,
            /// The buffer transaction for the current channel state.
            buffer_transaction: Transaction,
            /// Whether the local party is the one that initiated the latest channel
            /// state change.
            is_offer: bool,
            /// The total amount of collateral in the channel
            total_collateral: u64,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `SettledOffered` state when the local party
        /// has sent a [`dlc_messages::channel::SettleOffer`] message.
        SettledOffered {
            /// The payout that was proposed to the counter party.
            counter_payout: u64,
            /// The per update point that the local party would use for the next
            /// channel state.
            next_per_update_point: PublicKey,
            /// The UNIX epoch at which the counter party will be considered
            /// unresponsive and the channel will be forced closed.
            timeout: u64,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `SettledReceived` state when the local party
        /// has received a [`dlc_messages::channel::SettleOffer`] message.
        SettledReceived {
            /// The payout that was proposed to the local party to settle the channel.
            own_payout: u64,
            /// The payout that was proposed to the counter party.
            counter_payout: u64,
            /// The per update point to be used by the counter party for the setup
            /// of the next channel state.
            counter_next_per_update_point: PublicKey,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `SettledAccepted` state when the local party
        /// has sent a [`dlc_messages::channel::SettleAccept`] message.
        SettledAccepted {
            /// The per update point to be used by the counter party for the setup
            /// of the next channel state.
            counter_next_per_update_point: PublicKey,
            /// The per update point to be used by the local party for the setup
            /// of the next channel state.
            own_next_per_update_point: PublicKey,
            /// The adaptor signature for the settle transaction generated by the
            /// local party.
            own_settle_adaptor_signature: EcdsaAdaptorSignature,
            /// The settle transaction.
            settle_tx: Transaction,
            /// The UNIX epoch at which the counter party will be considered
            /// unresponsive and the channel will be forced closed.
            timeout: u64,
            /// The payout to the local party after settling the channel.
            own_payout: u64,
            /// The payout that was proposed to the counter party.
            counter_payout: u64,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `SettledConfirmed` state when the local party
        /// has sent a [`dlc_messages::channel::SettleConfirm`] message.
        SettledConfirmed {
            /// The settle transaction.
            settle_tx: Transaction,
            /// The adaptor signature for the settle transaction generated by the
            /// counter party.
            counter_settle_adaptor_signature: EcdsaAdaptorSignature,
            /// The per update point to be used by the counter party for the setup
            /// of the next channel state.
            counter_next_per_update_point: PublicKey,
            /// The per update point to be used by the local party for the setup
            /// of the next channel state.
            own_next_per_update_point: PublicKey,
            /// The adaptor signature for the settle transaction generated by the
            /// local party.
            own_settle_adaptor_signature: EcdsaAdaptorSignature,
            /// The UNIX epoch at which the counter party will be considered
            /// unresponsive and the channel will be forced closed.
            timeout: u64,
            /// The payout to the local party after settling the channel.
            own_payout: u64,
            /// The payout that was proposed to the counter party.
            counter_payout: u64,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `Settled` state when the local party
        /// has all the necessary information to close the channel with the last
        /// agreed upon settled state.
        Settled {
            /// The settle transaction that can be used to close the channel.
            settle_tx: Transaction,
            /// The adaptor signature for the settle transaction generated by the
            /// counter party.
            counter_settle_adaptor_signature: EcdsaAdaptorSignature,
            /// The adaptor signature for the settle transaction generated by the
            /// local party.
            own_settle_adaptor_signature: EcdsaAdaptorSignature,
            /// The amount the local party holds in the channel.
            own_payout: u64,
            /// The amount the counter party holds in the channel.
            counter_payout: u64,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `RenewOffered` state when the local party
        /// has sent or received a [`dlc_messages::channel::RenewOffer`] message.
        RenewOffered {
            /// The temporary [`crate::ContractId`] of the offered contract.
            offered_contract_id: ContractId,
            /// The payout offered to settle the previous channel state.
            counter_payout: u64,
            /// The per update point to be used by the offer party for the setup
            /// of the next channel state.
            offer_next_per_update_point: PublicKey,
            /// Indicates whether the local party offered the renewal or not.
            is_offer: bool,
            /// The UNIX epoch at which the counter party will be considered
            /// unresponsive and the channel will be forced closed.
            timeout: u64,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `RenewAccepted` state when the local party
        /// has sent a [`dlc_messages::channel::RenewAccept`] message.
        RenewAccepted {
            /// The [`crate::ContractId`] of the offered contract.
            contract_id: ContractId,
            /// The per update point to be used by the offer party for the setup
            /// of the next channel state.
            offer_per_update_point: PublicKey,
            /// The per update point to be used by the accept party for the setup
            /// of the next channel state.
            accept_per_update_point: PublicKey,
            /// The buffer transaction.
            buffer_transaction: Transaction,
            /// The buffer transaction script pubkey.
            buffer_script_pubkey: Script,
            /// The UNIX epoch at which the counter party will be considered
            /// unresponsive and the channel will be forced closed.
            timeout: u64,
            /// The payout to the local party attributed for closing the previous state.
            own_payout: u64,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `RenewConfirmed` state when the local party
        /// has sent a [`dlc_messages::channel::RenewConfirm`] message.
        RenewConfirmed {
            /// The [`crate::ContractId`] of the offered contract.
            contract_id: ContractId,
            /// The per update point to be used by the offer party for the setup
            /// of the next channel state.
            offer_per_update_point: PublicKey,
            /// The per update point to be used by the accept party for the setup
            /// of the next channel state.
            accept_per_update_point: PublicKey,
            /// The buffer transaction.
            buffer_transaction: Transaction,
            /// The buffer transaction script pubkey.
            buffer_script_pubkey: Script,
            /// The adaptor signature for the buffer transaction generated by
            /// the offer party.
            offer_buffer_adaptor_signature: EcdsaAdaptorSignature,
            /// The UNIX epoch at which the counter party will be considered
            /// unresponsive and the channel will be forced closed.
            timeout: u64,
            /// The payout to the local party attributed for closing the previous state.
            own_payout: u64,
            /// The total amount of collateral in the channel.
            total_collateral: u64,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// Finalize the renewal of the contract within a DLC channel.
        RenewFinalized {
            /// The [`crate::ContractId`] of the offered contract.
            contract_id: ContractId,
            /// The previous per update point that was used by the offer party for the previous
            /// state of the channel.
            prev_offer_per_update_point: PublicKey,
            /// The buffer transaction.
            buffer_transaction: Transaction,
            /// The buffer transaction script pubkey.
            buffer_script_pubkey: Script,
            /// The adaptor signature for the buffer transaction generated by
            /// the offer party.
            offer_buffer_adaptor_signature: EcdsaAdaptorSignature,
            /// The adaptor signature for the buffer transaction generated by
            /// the accept party.
            accept_buffer_adaptor_signature: EcdsaAdaptorSignature,
            /// The UNIX epoch at which the counter party will be considered
            /// unresponsive and the channel will be forced closed.
            timeout: u64,
            /// The payout to the local party attributed for closing the previous state.
            own_payout: u64,
            /// The total amount of collateral in the channel.
            total_collateral: u64,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `Closing` state when the local party
        /// has broadcast a buffer transaction and is waiting to finalize the
        /// closing of a the channel by broadcasting a CET.
        Closing {
            /// The buffer transaction that was broadcast.
            buffer_transaction: Transaction,
            /// The [`crate::ContractId`] of the contract that was used to close
            /// the channel.
            contract_id: ContractId,
            /// Whether the local party initiated the closing of the channel.
            is_initiator: bool,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
        /// A [`SignedChannel`] is in `CollaborativeCloseOffered` state when the local party
        /// has sent a [`dlc_messages::channel::CollaborativeCloseOffer`] message.
        CollaborativeCloseOffered {
            /// The payout offered to the counter party to close the channel.
            counter_payout: u64,
            /// The signature of the local party for the closing transaction.
            offer_signature: Signature,
            /// The closing transaction.
            close_tx: Transaction,
            /// The UNIX epoch at which the counter party will be considered
            /// unresponsive and the channel will be forced closed.
            timeout: u64,
            /// Indicates whether the local party offered the collaborative close or not.
            is_offer: bool,
            /// The reference id set by the api user.
            reference_id: Option<ReferenceId>,
        },
    },
    /// Enum automatically generated associating a number to each signed channel
    /// state.
    SignedChannelStateType,
);

impl SignedChannel {
    /// Returns the contract id associated with the channel if in a state where
    /// a contract is established or under establishment.
    pub fn get_contract_id(&self) -> Option<ContractId> {
        self.state.get_contract_id()
    }
}

impl SignedChannelState {
    fn get_contract_id(&self) -> Option<ContractId> {
        match &self {
            SignedChannelState::Established {
                signed_contract_id, ..
            } => Some(*signed_contract_id),
            SignedChannelState::RenewOffered {
                offered_contract_id,
                ..
            } => Some(*offered_contract_id),
            SignedChannelState::RenewAccepted { contract_id, .. } => Some(*contract_id),
            SignedChannelState::RenewConfirmed { contract_id, .. } => Some(*contract_id),
            SignedChannelState::RenewFinalized { contract_id, .. } => Some(*contract_id),
            SignedChannelState::Closing { contract_id, .. } => Some(*contract_id),
            _ => None,
        }
    }
}

/// A channel that had a successful setup.
#[derive(Clone)]
pub struct SignedChannel {
    /// The [`DlcChannelId`] for the channel.
    pub channel_id: DlcChannelId,
    /// The [`secp256k1_zkp::PublicKey`] of the counter party's node.
    pub counter_party: PublicKey,
    /// The temporary [`DlcChannelId`] for the channel.
    pub temporary_channel_id: DlcChannelId,
    /// The contract setup parameters for the local party.
    pub own_params: PartyParams,
    /// The base points used for channel updates and revocation by the local party.
    pub own_points: PartyBasePoints,
    /// The current per update point of the local party.
    pub own_per_update_point: PublicKey,
    /// The image of the seed used by the local party to derive all per update
    /// points (Will be `None` on the accept party side.)
    pub own_per_update_seed: PublicKey,
    /// The base points used for channel updates and revocation by the remote party.
    pub counter_points: PartyBasePoints,
    /// The current per update point of the remote party.
    pub counter_per_update_point: PublicKey,
    /// The contract setup parameters for the remote party.
    pub counter_params: PartyParams,
    /// The current state of the channel.
    pub state: SignedChannelState,
    /// The update index of the channel (starts at `(1 << 48) - 1` and decreases).
    pub update_idx: u64,
    /// The fund transaction for the channel.
    pub fund_tx: Transaction,
    /// The script pubkey for the funding output.
    pub fund_script_pubkey: Script,
    /// The vout of the funding output.
    pub fund_output_index: usize,
    /// The latest "stable" state in which the channel was (if already in a "stable")
    /// state, is `None`.
    pub roll_back_state: Option<SignedChannelState>,
    /// Structure storing the previous commitment secrets from the counter party.
    pub counter_party_commitment_secrets: CounterpartyCommitmentSecrets,
    /// The current fee rate to be used to create transactions.
    pub fee_rate_per_vb: u64,
    /// Whether this channel is embedded within a Lightning Network channel.
    pub sub_channel_id: Option<ChannelId>,
}

impl SignedChannel {
    /// Return whether this channel is part of an LN/DLC sub channel.
    pub fn is_sub_channel(&self) -> bool {
        self.sub_channel_id.is_some()
    }
}
