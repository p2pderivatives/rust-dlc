use crate::dlc::dlc_trie::DlcTrie;
use crate::payout_curve::{PayoutFunction, RoundingIntervals};
use bitcoin::{Address, Script, Transaction};
use dlc::combination_iterator::CombinationIterator;
use dlc::multi_oracle_trie::MultiOracleTrie;
use dlc::multi_oracle_trie_with_diff::MultiOracleTrieWithDiff;
use dlc::{
    DlcTransactions, EnumerationPayout, OracleInfo, PartyParams, Payout, RangeInfo, RangePayout,
};
use dlc_messages::oracle_msgs::OracleAnnouncement;
use dlc_messages::{AcceptDlc, FundingInput, FundingSignatures, SignDlc};
use secp256k1::ecdsa_adaptor::{AdaptorProof, AdaptorSignature};
use secp256k1::schnorrsig::PublicKey as SchnorrPublicKey;
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Signature, Signing};

#[derive(Clone)]
pub enum Contract {
    Offered(OfferedContract),
    Accepted(AcceptedContract),
    Signed(SignedContract),
    Confirmed(SignedContract),
    Closed(ClosedContract),
    Refunded(SignedContract),
    FailedAccept(FailedAcceptContract),
    FailedSign(FailedSignContract),
}

//TMP CODE
impl std::fmt::Debug for Contract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Contract::Offered(_) => "offered",
            Contract::Accepted(_) => "accepted",
            Contract::Signed(_) => "signed",
            Contract::Confirmed(_) => "confirmed",
            Contract::Closed(_) => "closed",
            Contract::Refunded(_) => "refunded",
            Contract::FailedAccept(_) => "failed accept",
            Contract::FailedSign(_) => "failed sign",
        };
        f.debug_struct("Contract")
            .field("state", &value.to_string())
            .finish()
    }
}

impl Contract {
    pub fn get_id(&self) -> crate::daemon::ContractId {
        match self {
            Contract::Offered(o) => o.id,
            Contract::Accepted(o) => o.get_contract_id(),
            Contract::Signed(o) | Contract::Confirmed(o) | Contract::Refunded(o) => {
                o.accepted_contract.get_contract_id()
            }
            Contract::Closed(c) => c.signed_contract.accepted_contract.get_contract_id(),
            Contract::FailedAccept(c) => c.offered_contract.id,
            Contract::FailedSign(c) => c.accepted_contract.get_contract_id(),
        }
    }

    pub fn get_temporary_id(&self) -> crate::daemon::ContractId {
        match self {
            Contract::Offered(o) => o.id,
            Contract::Accepted(o) => o.offered_contract.id,
            Contract::Signed(o) | Contract::Confirmed(o) | Contract::Refunded(o) => {
                o.accepted_contract.offered_contract.id
            }
            Contract::Closed(o) => o.signed_contract.accepted_contract.offered_contract.id,
            Contract::FailedAccept(c) => c.offered_contract.id,
            Contract::FailedSign(c) => c.accepted_contract.offered_contract.id,
        }
    }
}

pub enum OracleRequest {
    SingleOracleRequest(SingleOracleRequest),
    MultiOracleRequest(MultiOracleRequest),
}

pub struct SingleOracleRequest {
    pub oracle_id: SchnorrPublicKey,
    pub event_id: String,
}

pub struct MultiOracleRequest {
    pub event_id: String,
    pub oracle_ids: Vec<SchnorrPublicKey>,
    pub threshold: usize,
    pub max_error_exp: usize,
    pub min_support_exp: usize,
}

#[derive(Debug)]
pub struct OracleView {
    pub public_keys: Vec<SchnorrPublicKey>,
    pub event_id: String,
    pub threshold: u16,
    // pub params: Option<OracleParamsV0>,
}

pub struct ContractViewInfo {
    pub contract_descriptor: ContractDescriptor,
    pub oracles: OracleView,
}

pub struct ContractView {
    // pub counter_party: String,
    pub offer_collateral: u64,
    pub accept_collateral: u64,
    pub maturity_time: u32,
    pub fee_rate: u64,
    pub contract_infos: Vec<ContractViewInfo>,
}

#[derive(Clone)]
pub struct OfferedContract {
    pub id: [u8; 32],
    pub is_offer_party: bool,
    pub contract_info: Vec<ContractInfo>,
    pub offer_params: PartyParams,
    pub total_collateral: u64,
    pub funding_inputs_info: Vec<FundingInputInfo>,
    pub fund_output_serial_id: u64,
    pub fee_rate_per_vb: u64,
    pub contract_maturity_bound: u32,
    pub contract_timeout: u32,
}

pub struct CounterPartyInfo {
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct FundingInputInfo {
    pub funding_input: FundingInput,
    pub address: Option<Address>,
}

#[derive(Clone)]
pub struct AcceptedContract {
    pub offered_contract: OfferedContract,
    pub accept_params: PartyParams,
    pub funding_inputs: Vec<FundingInputInfo>,
    pub adaptor_infos: Vec<AdaptorInfo>,
    pub adaptor_signatures: Option<Vec<(AdaptorSignature, AdaptorProof)>>,
    pub accept_refund_signature: Signature,
    pub dlc_transactions: DlcTransactions,
}

impl AcceptedContract {
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

#[derive(Clone)]
pub struct SignedContract {
    pub accepted_contract: AcceptedContract,
    pub adaptor_signatures: Option<Vec<(AdaptorSignature, AdaptorProof)>>,
    pub offer_refund_signature: Signature,
    pub funding_signatures: FundingSignatures,
}

#[derive(Clone)]
pub struct FailedAcceptContract {
    pub offered_contract: OfferedContract,
    pub accept_message: AcceptDlc,
    pub error_message: String,
}

#[derive(Clone)]
pub struct FailedSignContract {
    pub accepted_contract: AcceptedContract,
    pub sign_message: SignDlc,
    pub error_message: String,
}

#[derive(Clone)]
pub struct ClosedContract {
    pub signed_contract: SignedContract,
}

#[derive(Clone, Debug)]
pub struct ContractInfo {
    pub contract_descriptor: ContractDescriptor,
    pub oracle_announcements: Vec<OracleAnnouncement>,
    pub threshold: usize,
}

impl ContractInfo {
    pub fn get_payouts(&self, total_collateral: u64) -> Vec<Payout> {
        match &self.contract_descriptor {
            ContractDescriptor::Enum(e) => e.get_payouts(),
            ContractDescriptor::Numerical(n) => n.get_payouts(total_collateral),
        }
    }

    pub fn get_oracle_infos(&self) -> Vec<OracleInfo> {
        self.oracle_announcements.iter().map(|x| x.into()).collect()
    }

    pub fn get_adaptor_signatures(
        &self,
        secp: &Secp256k1<All>,
        adaptor_info: &AdaptorInfo,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
    ) -> Result<Vec<(AdaptorSignature, AdaptorProof)>, dlc::Error> {
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

    pub fn verify_and_get_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        total_collateral: u64,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_sigs: &[(AdaptorSignature, AdaptorProof)],
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

    pub fn get_range_info_for_outcome(
        &self,
        adaptor_info: &AdaptorInfo,
        outcomes: &[(usize, &Vec<String>)],
        adaptor_sig_start: usize,
    ) -> Result<Option<(Vec<(usize, usize)>, RangeInfo)>, crate::daemon::Error> {
        let get_digits_outcome = |input: &[String]| -> Result<Vec<usize>, crate::daemon::Error> {
            input
                .iter()
                .map(|x| {
                    x.parse::<usize>()
                        .or(Err(crate::daemon::Error::InvalidParameters))
                })
                .collect::<Result<Vec<usize>, crate::daemon::Error>>()
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
                    .ok_or(crate::daemon::Error::InvalidState)?;

                let sufficient_combination: Vec<_> = actual_combination
                    .into_iter()
                    .take(self.threshold)
                    .collect();
                let position =
                    CombinationIterator::new(self.oracle_announcements.len(), self.threshold)
                        .get_index_for_combination(&sufficient_combination)
                        .ok_or(crate::daemon::Error::InvalidState)?;
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
                            .collect::<Result<Vec<(usize, Vec<usize>)>, crate::daemon::Error>>()?,
                    )
                    .ok_or(crate::daemon::Error::InvalidParameters)?;
                Ok(Some((
                    res.path.iter().map(|(x, y)| (*x, y.len())).collect(),
                    res.value.clone(),
                )))
            }
        }
    }

    pub fn verify_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_sigs: &[(AdaptorSignature, AdaptorProof)],
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

    pub fn get_adaptor_info<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        total_collateral: u64,
        fund_priv_key: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_index_start: usize,
    ) -> Result<(AdaptorInfo, Vec<(AdaptorSignature, AdaptorProof)>), dlc::Error> {
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

#[derive(Clone)]
pub enum AdaptorInfo {
    Enum,
    Numerical(MultiOracleTrie),
    NumericalWithDifference(MultiOracleTrieWithDiff),
}

#[derive(Clone, Debug)]
pub enum ContractDescriptor {
    Enum(EnumDescriptor),
    Numerical(NumericalDescriptor),
}

impl ContractDescriptor {
    pub fn get_oracle_params(&self) -> Option<DifferenceParams> {
        match self {
            ContractDescriptor::Enum(_) => None,
            ContractDescriptor::Numerical(n) => n.difference_params.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EnumDescriptor {
    pub outcome_payouts: Vec<EnumerationPayout>,
}

fn get_majority_combination(
    outcomes: &[(usize, &Vec<String>)],
) -> Result<(Vec<String>, Vec<usize>), crate::daemon::Error> {
    let mut hash_set: std::collections::HashMap<Vec<String>, Vec<usize>> =
        std::collections::HashMap::new();

    for outcome in outcomes {
        let index = outcome.0;
        let outcome_value = outcome.1;

        if let Some(index_set) = hash_set.get_mut(outcome_value) {
            index_set.push(index);
        } else {
            let index_set = vec![index];
            hash_set.insert(outcome_value.to_vec(), index_set);
        }
    }

    if hash_set.len() == 0 {
        return Err(crate::daemon::Error::InvalidParameters);
    }

    let mut values: Vec<_> = hash_set.into_iter().collect();
    values.sort_by(|x, y| x.1.len().partial_cmp(&y.1.len()).unwrap());
    Ok(values.remove(values.len() - 1))
}

impl EnumDescriptor {
    pub fn get_payouts(&self) -> Vec<Payout> {
        self.outcome_payouts
            .iter()
            .map(|x| x.payout.clone())
            .collect()
    }

    pub fn get_range_info_for_outcome(
        &self,
        nb_oracles: usize,
        threshold: usize,
        outcomes: &[(usize, &Vec<String>)],
        adaptor_sig_start: usize,
    ) -> Result<Option<(Vec<(usize, usize)>, RangeInfo)>, crate::daemon::Error> {
        if outcomes.len() < threshold {
            return Ok(None);
        }

        let filtered_outcomes: Vec<(usize, &Vec<String>)> = outcomes
            .into_iter()
            .filter(|x| x.1.len() == 1)
            .cloned()
            .collect();
        let (mut outcome, mut actual_combination) = get_majority_combination(&filtered_outcomes)?;
        let outcome = outcome.remove(0);

        if actual_combination.len() < threshold {
            return Ok(None);
        }

        actual_combination.truncate(threshold);

        let pos = self
            .outcome_payouts
            .iter()
            .position(|x| x.outcome == outcome)
            .ok_or(crate::daemon::Error::InvalidParameters)?;

        let combinator = CombinationIterator::new(nb_oracles, threshold);
        let mut comb_pos = 0;
        let mut comb_count = 0;

        for (i, combination) in combinator.enumerate() {
            if combination == actual_combination {
                comb_pos = i;
            }
            comb_count += 1;
        }

        let range_info = RangeInfo {
            cet_index: pos,
            adaptor_index: comb_count * pos + comb_pos + adaptor_sig_start,
        };

        Ok(Some((
            actual_combination.iter().map(|x| (*x, 1)).collect(),
            range_info,
        )))
    }

    pub fn verify_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_sigs: &[(AdaptorSignature, AdaptorProof)],
        adaptor_sig_start: usize,
    ) -> Result<usize, dlc::Error> {
        let mut adaptor_sig_index = adaptor_sig_start;
        let mut callback =
            |adaptor_point: &PublicKey, cet_index: usize| -> Result<(), dlc::Error> {
                println!("ADAPTOR SIG INDEX: {}", adaptor_sig_index);
                let sig = adaptor_sigs[adaptor_sig_index];
                adaptor_sig_index += 1;
                dlc::verify_cet_adaptor_sig_from_point(
                    secp,
                    &sig.0,
                    &sig.1,
                    &cets[cet_index],
                    &adaptor_point,
                    fund_pubkey,
                    funding_script_pubkey,
                    fund_output_value,
                )?;
                Ok(())
            };

        self.iter_outcomes(secp, oracle_infos, threshold, &mut callback)?;

        Ok(adaptor_sig_index)
    }

    pub fn verify_and_get_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_sigs: &[(AdaptorSignature, AdaptorProof)],
        adaptor_sig_start: usize,
    ) -> Result<(AdaptorInfo, usize), dlc::Error> {
        let adaptor_sig_index = self.verify_adaptor_info(
            secp,
            oracle_infos,
            threshold,
            fund_pubkey,
            funding_script_pubkey,
            fund_output_value,
            cets,
            adaptor_sigs,
            adaptor_sig_start,
        )?;

        Ok((AdaptorInfo::Enum, adaptor_sig_index))
    }

    pub fn get_adaptor_info<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
    ) -> Result<(AdaptorInfo, Vec<(AdaptorSignature, AdaptorProof)>), dlc::Error> {
        let adaptor_sigs = self.get_adaptor_signatures(
            secp,
            oracle_infos,
            threshold,
            cets,
            fund_privkey,
            funding_script_pubkey,
            fund_output_value,
        )?;

        Ok((AdaptorInfo::Enum, adaptor_sigs))
    }

    pub fn get_adaptor_signatures<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        cets: &[Transaction],
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
    ) -> Result<Vec<(AdaptorSignature, AdaptorProof)>, dlc::Error> {
        let mut adaptor_sigs = Vec::new();
        let mut callback =
            |adaptor_point: &PublicKey, cet_index: usize| -> Result<(), dlc::Error> {
                println!("ADAPTOR INDEX: {}", adaptor_sigs.len());
                let sig = dlc::create_cet_adaptor_sig_from_point(
                    secp,
                    &cets[cet_index],
                    &adaptor_point,
                    fund_privkey,
                    funding_script_pubkey,
                    fund_output_value,
                )?;
                adaptor_sigs.push(sig);
                Ok(())
            };

        self.iter_outcomes(secp, oracle_infos, threshold, &mut callback)?;

        Ok(adaptor_sigs)
    }

    fn iter_outcomes<C: Signing, F>(
        &self,
        secp: &Secp256k1<C>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        callback: &mut F,
    ) -> Result<(), dlc::Error>
    where
        F: FnMut(&PublicKey, usize) -> Result<(), dlc::Error>,
    {
        let messages: Vec<Vec<Vec<Message>>> = self
            .outcome_payouts
            .iter()
            .map(|x| {
                let message = vec![Message::from_hashed_data::<
                    secp256k1::bitcoin_hashes::sha256::Hash,
                >(x.outcome.as_bytes())];
                std::iter::repeat(message).take(threshold).collect()
            })
            .collect();
        let combination_iter = CombinationIterator::new(oracle_infos.len(), threshold);
        let combinations: Vec<Vec<usize>> = combination_iter.collect();

        for (i, outcome_messages) in messages.iter().enumerate() {
            for selector in &combinations {
                let cur_oracle_infos: Vec<_> = oracle_infos
                    .iter()
                    .enumerate()
                    .filter_map(|(i, x)| {
                        if selector.contains(&i) {
                            Some(x.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                let adaptor_point = dlc::get_adaptor_point_from_oracle_info(
                    secp,
                    &cur_oracle_infos,
                    &outcome_messages,
                )?;
                callback(&adaptor_point, i)?;
            }
        }

        Ok(())
    }
}

//TODO(tibo): Do we need this or can it be taken from oracle info directly?
#[derive(Clone, Debug)]
pub struct NumericalEventInfo {
    pub base: usize,
    pub nb_digits: usize,
    pub unit: String,
}

#[derive(Clone, Debug)]
pub struct DifferenceParams {
    pub max_error_exp: usize,
    pub min_support_exp: usize,
    pub maximize_coverage: bool,
}

#[derive(Clone, Debug)]
// Todo(tibo): redundancy with oracle view, needs fix
pub struct NumericalDescriptor {
    pub payout_function: PayoutFunction,
    pub rounding_intervals: RoundingIntervals,
    pub info: NumericalEventInfo,
    pub difference_params: Option<DifferenceParams>,
}

impl NumericalDescriptor {
    pub fn get_range_payouts(&self, total_collateral: u64) -> Vec<RangePayout> {
        self.payout_function
            .to_range_payouts(total_collateral, &self.rounding_intervals)
    }

    pub fn get_payouts(&self, total_collateral: u64) -> Vec<Payout> {
        self.get_range_payouts(total_collateral)
            .iter()
            .map(|x| x.payout.clone())
            .collect()
    }

    pub fn verify_and_get_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        total_collateral: u64,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        threshold: usize,
        oracle_infos: &[OracleInfo],
        cets: &[Transaction],
        adaptor_pairs: &[(AdaptorSignature, AdaptorProof)],
        adaptor_index_start: usize,
    ) -> Result<(AdaptorInfo, usize), dlc::Error> {
        match &self.difference_params {
            Some(params) => {
                let mut multi_trie = MultiOracleTrieWithDiff::new(
                    self.info.base,
                    oracle_infos.len(),
                    threshold,
                    self.info.nb_digits,
                    params.min_support_exp,
                    params.max_error_exp,
                );
                let index = multi_trie.generate_verify(
                    secp,
                    fund_pubkey,
                    funding_script_pubkey,
                    fund_output_value,
                    &self.get_range_payouts(total_collateral),
                    cets,
                    oracle_infos,
                    adaptor_pairs,
                    adaptor_index_start,
                )?;
                Ok((AdaptorInfo::NumericalWithDifference(multi_trie), index))
            }
            None => {
                let mut trie = MultiOracleTrie::new(
                    self.info.base,
                    oracle_infos.len(),
                    threshold,
                    self.info.nb_digits,
                );
                let index = trie.generate_verify(
                    secp,
                    fund_pubkey,
                    funding_script_pubkey,
                    fund_output_value,
                    &self.get_range_payouts(total_collateral),
                    cets,
                    oracle_infos,
                    adaptor_pairs,
                    adaptor_index_start,
                )?;
                Ok((AdaptorInfo::Numerical(trie), index))
            }
        }
    }

    pub fn get_adaptor_info<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        total_collateral: u64,
        fund_priv_key: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        threshold: usize,
        oracle_infos: &[OracleInfo],
        cets: &[Transaction],
        adaptor_index_start: usize,
    ) -> Result<(AdaptorInfo, Vec<(AdaptorSignature, AdaptorProof)>), dlc::Error> {
        match &self.difference_params {
            Some(params) => {
                let mut multi_trie = MultiOracleTrieWithDiff::new(
                    self.info.base,
                    oracle_infos.len(),
                    threshold,
                    self.info.nb_digits,
                    params.min_support_exp,
                    params.max_error_exp,
                );
                let adaptor_pairs = multi_trie.generate_sign(
                    secp,
                    fund_priv_key,
                    funding_script_pubkey,
                    fund_output_value,
                    &self.get_range_payouts(total_collateral),
                    cets,
                    oracle_infos,
                    adaptor_index_start,
                )?;
                Ok((
                    AdaptorInfo::NumericalWithDifference(multi_trie),
                    adaptor_pairs,
                ))
            }

            None => {
                let mut trie = MultiOracleTrie::new(
                    self.info.base,
                    oracle_infos.len(),
                    threshold,
                    self.info.nb_digits,
                );
                let sigs = trie.generate_sign(
                    secp,
                    &fund_priv_key,
                    &funding_script_pubkey,
                    fund_output_value,
                    &self.get_range_payouts(total_collateral),
                    cets,
                    oracle_infos,
                    adaptor_index_start,
                )?;
                Ok((AdaptorInfo::Numerical(trie), sigs))
            }
        }
    }
}
