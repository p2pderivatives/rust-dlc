//! #ContractInfo

use super::utils::get_majority_combination;
use super::AdaptorInfo;
use super::ContractDescriptor;
use bitcoin::{Script, Transaction};
use dlc::{OracleInfo, Payout};
use dlc_messages::oracle_msgs::OracleAnnouncement;
use dlc_trie::combination_iterator::CombinationIterator;
use dlc_trie::{DlcTrie, RangeInfo};
use secp256k1_zkp::{All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey};

/// Contains information about the contract conditions and oracles used.
#[derive(Clone, Debug)]
pub struct ContractInfo {
    /// The descriptor for the contract
    pub contract_descriptor: ContractDescriptor,
    /// The oracle announcements used for the contract.
    pub oracle_announcements: Vec<OracleAnnouncement>,
    /// How many oracles are required to provide a compatible outcome to be able
    /// to close the contract.
    pub threshold: usize,
}

impl ContractInfo {
    /// Get the payouts associated with the contract.
    pub fn get_payouts(&self, total_collateral: u64) -> Vec<Payout> {
        match &self.contract_descriptor {
            ContractDescriptor::Enum(e) => e.get_payouts(),
            ContractDescriptor::Numerical(n) => n.get_payouts(total_collateral),
        }
    }

    /// Utility function returning a set of OracleInfo created using the set
    /// of oracle announcements defined for the contract.
    pub fn get_oracle_infos(&self) -> Vec<OracleInfo> {
        self.oracle_announcements.iter().map(|x| x.into()).collect()
    }

    /// Uses the provided AdaptorInfo and SecretKey to generate the set of
    /// adaptor signatures for the contract.
    pub fn get_adaptor_signatures(
        &self,
        secp: &Secp256k1<All>,
        adaptor_info: &AdaptorInfo,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
    ) -> Result<Vec<EcdsaAdaptorSignature>, dlc::Error> {
        let oracle_infos = self.get_oracle_infos();
        match adaptor_info {
            AdaptorInfo::Enum => match &self.contract_descriptor {
                ContractDescriptor::Enum(e) => e.get_adaptor_signatures(
                    secp,
                    &oracle_infos,
                    self.threshold,
                    cets,
                    fund_privkey,
                    funding_script_pubkey,
                    fund_output_value,
                ),
                _ => unreachable!(),
            },
            AdaptorInfo::Numerical(trie) => trie.sign(
                secp,
                fund_privkey,
                funding_script_pubkey,
                fund_output_value,
                cets,
                &oracle_infos,
            ),
            AdaptorInfo::NumericalWithDifference(trie) => trie.sign(
                secp,
                fund_privkey,
                funding_script_pubkey,
                fund_output_value,
                cets,
                &oracle_infos,
            ),
        }
    }

    /// Generate the AdaptorInfo for the contract while verifying the provided
    /// set of adaptor signatures.
    pub fn verify_and_get_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        total_collateral: u64,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_sigs: &[EcdsaAdaptorSignature],
        adaptor_sig_start: usize,
    ) -> Result<(AdaptorInfo, usize), dlc::Error> {
        let oracle_infos = self.get_oracle_infos();
        match &self.contract_descriptor {
            ContractDescriptor::Enum(e) => Ok(e.verify_and_get_adaptor_info(
                secp,
                &oracle_infos,
                self.threshold,
                fund_pubkey,
                funding_script_pubkey,
                fund_output_value,
                cets,
                adaptor_sigs,
                adaptor_sig_start,
            )?),
            ContractDescriptor::Numerical(n) => Ok(n.verify_and_get_adaptor_info(
                secp,
                total_collateral,
                fund_pubkey,
                funding_script_pubkey,
                fund_output_value,
                self.threshold,
                &oracle_infos,
                cets,
                adaptor_sigs,
                adaptor_sig_start,
            )?),
        }
    }

    /// Tries to find a match in the given adaptor info for the given outcomes.
    pub fn get_range_info_for_outcome(
        &self,
        adaptor_info: &AdaptorInfo,
        outcomes: &[(usize, &Vec<String>)],
        adaptor_sig_start: usize,
    ) -> Result<Option<(Vec<(usize, usize)>, RangeInfo)>, crate::error::Error> {
        let get_digits_outcome = |input: &[String]| -> Result<Vec<usize>, crate::error::Error> {
            input
                .iter()
                .map(|x| {
                    x.parse::<usize>()
                        .or(Err(crate::error::Error::InvalidParameters))
                })
                .collect::<Result<Vec<usize>, crate::error::Error>>()
        };

        match adaptor_info {
            AdaptorInfo::Enum => match &self.contract_descriptor {
                ContractDescriptor::Enum(e) => e.get_range_info_for_outcome(
                    self.oracle_announcements.len(),
                    self.threshold,
                    outcomes,
                    adaptor_sig_start,
                ),
                _ => unreachable!(),
            },
            AdaptorInfo::Numerical(n) => {
                let (s_outcomes, actual_combination) = get_majority_combination(outcomes)?;
                let digits_outcome = get_digits_outcome(&s_outcomes)?;

                let res = n
                    .digit_trie
                    .look_up(&digits_outcome)
                    .ok_or(crate::error::Error::InvalidState)?;

                let sufficient_combination: Vec<_> = actual_combination
                    .into_iter()
                    .take(self.threshold)
                    .collect();
                let position =
                    CombinationIterator::new(self.oracle_announcements.len(), self.threshold)
                        .get_index_for_combination(&sufficient_combination)
                        .ok_or(crate::error::Error::InvalidState)?;
                Ok(Some((
                    sufficient_combination
                        .iter()
                        .map(|x| (*x, res[0].path.len()))
                        .collect(),
                    res[0].value[position].clone(),
                )))
            }
            AdaptorInfo::NumericalWithDifference(n) => {
                let res = n
                    .multi_trie
                    .look_up(
                        &outcomes
                            .iter()
                            .map(|(x, path)| Ok((*x, get_digits_outcome(path)?)))
                            .collect::<Result<Vec<(usize, Vec<usize>)>, crate::error::Error>>()?,
                    )
                    .ok_or(crate::error::Error::InvalidParameters)?;
                Ok(Some((
                    res.path.iter().map(|(x, y)| (*x, y.len())).collect(),
                    res.value.clone(),
                )))
            }
        }
    }

    /// Verifies the given adaptor signatures are valid with respect to the given
    /// adaptor info.
    pub fn verify_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_sigs: &[EcdsaAdaptorSignature],
        adaptor_sig_start: usize,
        adaptor_info: &AdaptorInfo,
    ) -> Result<usize, dlc::Error> {
        let oracle_infos = self.get_oracle_infos();
        match &self.contract_descriptor {
            ContractDescriptor::Enum(e) => Ok(e.verify_adaptor_info(
                secp,
                &oracle_infos,
                self.threshold,
                fund_pubkey,
                funding_script_pubkey,
                fund_output_value,
                cets,
                adaptor_sigs,
                adaptor_sig_start,
            )?),
            _ => match adaptor_info {
                AdaptorInfo::Enum => unreachable!(),
                AdaptorInfo::Numerical(trie) => trie.verify(
                    secp,
                    fund_pubkey,
                    funding_script_pubkey,
                    fund_output_value,
                    adaptor_sigs,
                    cets,
                    &oracle_infos,
                ),
                AdaptorInfo::NumericalWithDifference(trie) => trie.verify(
                    secp,
                    fund_pubkey,
                    funding_script_pubkey,
                    fund_output_value,
                    adaptor_sigs,
                    cets,
                    &oracle_infos,
                ),
            },
        }
    }

    /// Generate the adaptor info and adaptor signatures for the contract.
    pub fn get_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        total_collateral: u64,
        fund_priv_key: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_index_start: usize,
    ) -> Result<(AdaptorInfo, Vec<EcdsaAdaptorSignature>), dlc::Error> {
        let oracle_infos = self.get_oracle_infos();
        match &self.contract_descriptor {
            ContractDescriptor::Enum(e) => Ok(e.get_adaptor_info(
                secp,
                &oracle_infos,
                self.threshold,
                fund_priv_key,
                funding_script_pubkey,
                fund_output_value,
                cets,
            )?),
            ContractDescriptor::Numerical(n) => Ok(n.get_adaptor_info(
                secp,
                total_collateral,
                fund_priv_key,
                funding_script_pubkey,
                fund_output_value,
                self.threshold,
                &oracle_infos,
                cets,
                adaptor_index_start,
            )?),
        }
    }
}
