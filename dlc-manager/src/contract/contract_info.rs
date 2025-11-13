//! #ContractInfo

use super::AdaptorInfo;
use super::ContractDescriptor;
use crate::error::Error;
use bitcoin::hashes::Hash;
use bitcoin::Amount;
use bitcoin::Script;
use bitcoin::ScriptBuf;
use dlc::{OracleInfo, Payout};
use dlc_messages::oracle_msgs::{EventDescriptor, OracleAnnouncement};
use dlc_trie::RangeInfo;
use secp256k1_zkp::{All, Message, PublicKey, Secp256k1, Verification};

pub(super) type OracleIndexAndPrefixLength = Vec<(usize, usize)>;

/// Contains information about the contract conditions and oracles used.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "use-serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
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
    pub fn get_payouts(&self, total_collateral: Amount) -> Result<Vec<Payout>, Error> {
        match &self.contract_descriptor {
            ContractDescriptor::Enum(e) => Ok(e.get_payouts()),
            ContractDescriptor::Numerical(n) => n.get_payouts(total_collateral),
        }
    }

    /// Validate that the descriptor covers all possible outcomes that can be attested
    /// by the oracle(s).
    pub fn validate(&self) -> Result<(), Error> {
        if self.oracle_announcements.is_empty() {
            return Err(Error::InvalidState(
                "ContractInfo doesn't contain any announcement.".to_string(),
            ));
        }

        self.contract_descriptor
            .validate(&self.oracle_announcements)
    }

    /// Utility function returning a set of OracleInfo created using the set
    /// of oracle announcements defined for the contract.
    pub fn get_oracle_infos(&self) -> Vec<OracleInfo> {
        self.oracle_announcements.iter().map(|x| x.into()).collect()
    }

    /// Generate the script for the taproot tree
    pub fn get_scripts(
        &self,
        secp: &Secp256k1<All>,
        total_collateral: Amount,
        offer_spk: &Script,
        accept_spk: &Script,
        index_start: usize,
    ) -> Result<(AdaptorInfo, Vec<ScriptBuf>), Error> {
        match &self.contract_descriptor {
            ContractDescriptor::Enum(e) => Ok((
                AdaptorInfo::Enum,
                e.get_scripts(
                    secp,
                    offer_spk,
                    accept_spk,
                    &self.get_oracle_infos(),
                    self.threshold,
                )?,
            )),
            ContractDescriptor::Numerical(n) => Ok(n.get_scripts(
                offer_spk,
                accept_spk,
                total_collateral,
                &self.precompute_points(secp)?,
                index_start,
                self.threshold,
            )?),
        }
    }

    /// Tries to find a match in the given adaptor info for the given outcomes.
    pub fn get_range_info_for_outcome(
        &self,
        adaptor_info: &AdaptorInfo,
        outcomes: &[(usize, &Vec<String>)],
        adaptor_sig_start: usize,
    ) -> Option<(OracleIndexAndPrefixLength, RangeInfo)> {
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
                let res = n.look_up(&outcomes_to_digits(outcomes))?;
                Some((
                    res.1.iter().map(|(x, y)| (*x, y.len())).collect(),
                    res.0.clone(),
                ))
            }
            AdaptorInfo::NumericalWithDifference(n) => {
                let res = n.multi_trie.look_up(&outcomes_to_digits(outcomes))?;

                Some((
                    res.1.iter().map(|(x, y)| (*x, y.len())).collect(),
                    res.0.clone(),
                ))
            }
        }
    }

    fn precompute_points<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<Vec<Vec<PublicKey>>>, Error> {
        self.oracle_announcements
            .iter()
            .map(|x| {
                let pubkey = &x.oracle_public_key;
                let nonces = &x.oracle_event.oracle_nonces;
                match &x.oracle_event.event_descriptor {
                    EventDescriptor::DigitDecompositionEvent(d) => {
                        let base = d.base as usize;
                        let nb_digits = d.nb_digits as usize;
                        if nb_digits != nonces.len() {
                            return Err(Error::InvalidParameters(
                                "Number of digits and nonces must be equal".to_string(),
                            ));
                        }
                        let mut d_points = Vec::with_capacity(nb_digits);
                        for nonce in nonces {
                            let mut points = Vec::with_capacity(base);
                            for j in 0..base {
                                let hash =
                                    bitcoin::hashes::sha256::Hash::hash(j.to_string().as_bytes())
                                        .to_byte_array();
                                let msg = Message::from_digest(hash);
                                let sig_point = dlc::secp_utils::schnorrsig_compute_sig_point(
                                    secp, pubkey, nonce, &msg,
                                )?;
                                points.push(sig_point);
                            }
                            d_points.push(points);
                        }
                        Ok(d_points)
                    }
                    _ => Err(Error::InvalidParameters(
                        "Expected digit decomposition event.".to_string(),
                    )),
                }
            })
            .collect::<Result<Vec<Vec<Vec<PublicKey>>>, Error>>()
    }
}

fn get_digits_outcome(input: &[String]) -> Result<Vec<usize>, crate::error::Error> {
    input
        .iter()
        .map(|x| {
            x.parse::<usize>().map_err(|_| {
                crate::error::Error::InvalidParameters(
                    "Invalid outcome, {} is not a valid number.".to_string(),
                )
            })
        })
        .collect::<Result<Vec<usize>, crate::error::Error>>()
}

fn outcomes_to_digits(outcomes: &[(usize, &Vec<String>)]) -> Vec<(usize, Vec<usize>)> {
    outcomes
        .iter()
        .filter_map(|(x, path)| Some((*x, get_digits_outcome(path).ok()?)))
        .collect()
}
