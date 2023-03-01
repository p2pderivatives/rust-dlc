//! #ContractInput

use crate::error::Error;

use super::ContractDescriptor;
use secp256k1_zkp::XOnlyPublicKey;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Oracle information required for the initial creation of a contract.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OracleInput {
    /// The set of public keys for each of the used oracles.
    pub public_keys: Vec<XOnlyPublicKey>,
    /// The id of the event being used for the contract. Note that at the moment
    /// a single event id is used, while multiple ids would be preferable.
    pub event_id: String,
    /// The number of oracles that need to provide attestations satisfying the
    /// contract conditions to be able to close the contract.
    pub threshold: u16,
}

impl OracleInput {
    /// Checks whether the data within the struct is consistent.
    pub fn validate(&self) -> Result<(), Error> {
        if self.public_keys.is_empty() {
            return Err(Error::InvalidParameters(
                "OracleInput must have at least one public key.".to_string(),
            ));
        }

        if self.threshold > self.public_keys.len() as u16 {
            return Err(Error::InvalidParameters(
                "Threshold cannot be larger than number of oracles.".to_string(),
            ));
        }

        Ok(())
    }
}

/// Represents the contract specifications.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct ContractInputInfo {
    /// The contract conditions.
    pub contract_descriptor: ContractDescriptor,
    /// The oracle information.
    pub oracles: OracleInput,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains all the information necessary for the initialization of a DLC.
pub struct ContractInput {
    /// The collateral for the offering party.
    pub offer_collateral: u64,
    /// The collateral for the accepting party.
    pub accept_collateral: u64,
    /// The fee rate used to construct the transactions.
    pub fee_rate: u64,
    /// The set of contract that make up the DLC (a single DLC can be based
    /// on multiple contracts).
    pub contract_infos: Vec<ContractInputInfo>,
}

impl ContractInput {
    /// Validate the contract input parameters
    pub fn validate(&self) -> Result<(), Error> {
        if self.contract_infos.is_empty() {
            return Err(Error::InvalidParameters(
                "Need at least one contract info".to_string(),
            ));
        }

        for contract_info in &self.contract_infos {
            contract_info.oracles.validate()?;
        }

        dlc::util::validate_fee_rate(self.fee_rate)
            .map_err(|_| Error::InvalidParameters("Fee rate too high.".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use dlc::{EnumerationPayout, Payout};
    use secp256k1_zkp::{KeyPair, SECP256K1};

    use crate::contract::enum_descriptor::EnumDescriptor;

    use super::*;

    fn get_base_input() -> ContractInput {
        ContractInput {
            offer_collateral: 1000000,
            accept_collateral: 2000000,
            fee_rate: 1234,
            contract_infos: vec![ContractInputInfo {
                contract_descriptor: ContractDescriptor::Enum(EnumDescriptor {
                    outcome_payouts: vec![
                        EnumerationPayout {
                            outcome: "A".to_string(),
                            payout: Payout {
                                offer: 3000000,
                                accept: 0,
                            },
                        },
                        EnumerationPayout {
                            outcome: "B".to_string(),
                            payout: Payout {
                                offer: 0,
                                accept: 3000000,
                            },
                        },
                    ],
                }),
                oracles: OracleInput {
                    public_keys: vec![
                        XOnlyPublicKey::from_keypair(&KeyPair::from_secret_key(
                            SECP256K1,
                            &secp256k1_zkp::ONE_KEY,
                        ))
                        .0,
                    ],
                    event_id: "1234".to_string(),
                    threshold: 1,
                },
            }],
        }
    }

    #[test]
    fn valid_contract_input_is_valid() {
        let input = get_base_input();
        input.validate().expect("the contract input to be valid.");
    }

    #[test]
    fn no_contract_info_contract_input_is_not_valid() {
        let mut input = get_base_input();
        input.contract_infos.clear();
        input
            .validate()
            .expect_err("the contract input to be invalid.");
    }

    #[test]
    fn invalid_fee_rate_contract_input_is_not_valid() {
        let mut input = get_base_input();
        input.fee_rate = 251 * 25;
        input
            .validate()
            .expect_err("the contract input to be invalid.");
    }

    #[test]
    fn no_public_keys_oracle_input_contract_input_is_not_valid() {
        let mut input = get_base_input();
        input.contract_infos[0].oracles.public_keys.clear();
        input
            .validate()
            .expect_err("the contract input to be invalid.");
    }

    #[test]
    fn invalid_oracle_info_threshold_oracle_input_contract_input_is_not_valid() {
        let mut input = get_base_input();
        input.contract_infos[0].oracles.threshold = 2;
        input
            .validate()
            .expect_err("the contract input to be invalid.");
    }
}
