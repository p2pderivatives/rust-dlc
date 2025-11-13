//! # This module contains static functions to update the state of a DLC.

use std::ops::Deref;

use bitcoin::psbt::Psbt;
use bitcoin::{consensus::Decodable, Transaction, Witness};
use bitcoin::{Address, Amount, Network, ScriptBuf};
use dlc::opcat_utils::create_dlc_tx;
use dlc::{signatures_to_secret, PartyParams};
use dlc_messages::FundingInput;
use dlc_messages::{
    oracle_msgs::{OracleAnnouncement, OracleAttestation},
    AcceptDlc, FundingSignature, FundingSignatures, OfferDlc, SignDlc, WitnessElement,
};
use secp256k1_zkp::Keypair;
use secp256k1_zkp::{All, PublicKey, Secp256k1, Signing};

use crate::{
    contract::{
        accepted_contract::AcceptedContract, contract_info::ContractInfo,
        contract_input::ContractInput, offered_contract::OfferedContract,
        signed_contract::SignedContract, AdaptorInfo,
    },
    conversion_utils::get_tx_input_infos,
    error::Error,
    Blockchain, ContractSigner, ContractSignerProvider, Time, Wallet,
};

/// Creates an [`OfferedContract`] and [`OfferDlc`] message from the provided
/// contract and oracle information.
pub fn offer_contract<W: Deref, B: Deref, T: Deref, X: ContractSigner, SP: Deref, C: Signing>(
    secp: &Secp256k1<C>,
    contract_input: &ContractInput,
    oracle_announcements: Vec<Vec<OracleAnnouncement>>,
    refund_delay: u32,
    counter_party: &PublicKey,
    wallet: &W,
    blockchain: &B,
    time: &T,
    signer_provider: &SP,
) -> Result<(OfferedContract, OfferDlc), Error>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    T::Target: Time,
    SP::Target: ContractSignerProvider<Signer = X>,
{
    contract_input.validate()?;

    let id = crate::utils::get_new_temporary_id();
    let keys_id = signer_provider.derive_signer_key_id(true, id);
    let signer = signer_provider.derive_contract_signer(keys_id)?;
    let (party_params, funding_inputs_info) = crate::utils::get_party_params(
        secp,
        contract_input.offer_collateral,
        contract_input.fee_rate,
        wallet,
        &signer,
        blockchain,
    )?;

    let offered_contract = OfferedContract::new(
        id,
        contract_input,
        oracle_announcements,
        &party_params,
        &funding_inputs_info,
        counter_party,
        refund_delay,
        time.unix_time_now() as u32,
        keys_id,
    );

    let offer_msg: OfferDlc = (&offered_contract).into();

    Ok((offered_contract, offer_msg))
}

/// Creates an [`AcceptedContract`] and produces
/// the accepting party's cet adaptor signatures.
pub fn accept_contract<W: Deref, X: ContractSigner, SP: Deref, B: Deref>(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    wallet: &W,
    signer_provider: &SP,
    blockchain: &B,
) -> Result<(AcceptedContract, AcceptDlc), Error>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    SP::Target: ContractSignerProvider<Signer = X>,
{
    let total_collateral = offered_contract.total_collateral;

    let signer = signer_provider.derive_contract_signer(offered_contract.keys_id)?;
    let (accept_params, funding_inputs) = crate::utils::get_party_params(
        secp,
        total_collateral - offered_contract.offer_params.collateral,
        offered_contract.fee_rate_per_vb,
        wallet,
        &signer,
        blockchain,
    )?;

    let accepted_contract =
        accept_contract_internal(secp, offered_contract, &accept_params, &funding_inputs)?;

    let accept_msg: AcceptDlc = accepted_contract.get_accept_contract_msg();

    Ok((accepted_contract, accept_msg))
}

pub(crate) fn accept_contract_internal(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    accept_params: &PartyParams,
    funding_inputs: &[FundingInput],
) -> Result<AcceptedContract, crate::Error> {
    let (adaptor_info, mut scripts) = offered_contract.contract_info[0].get_scripts(
        secp,
        offered_contract.total_collateral,
        &offered_contract.offer_params.payout_script_pubkey,
        &accept_params.payout_script_pubkey,
        0,
    )?;
    let mut adaptor_infos = vec![adaptor_info];

    for contract_info in offered_contract.contract_info.iter().skip(1) {
        let (adaptor_info, new_scripts) = contract_info.get_scripts(
            secp,
            offered_contract.total_collateral,
            &offered_contract.offer_params.payout_script_pubkey,
            &accept_params.payout_script_pubkey,
            scripts.len(),
        )?;

        scripts.extend(new_scripts);

        adaptor_infos.push(adaptor_info);
    }

    let taproot_spend_info = dlc::opcat_utils::taproot_spend_info(secp, &scripts)?;

    let address = Address::p2tr_tweaked(taproot_spend_info.output_key(), Network::Regtest);
    let script_pk = address.script_pubkey();

    let fund = dlc::create_fund_transaction_with_fees(
        &offered_contract.offer_params,
        accept_params,
        offered_contract.fee_rate_per_vb,
        0,
        0,
        &script_pk,
        Amount::ZERO,
    )
    .expect("Could not build fund tx");

    let accepted_contract = AcceptedContract {
        offered_contract: offered_contract.clone(),
        adaptor_infos,
        // Drop own adaptor signatures as no point keeping them.
        accept_params: accept_params.clone(),
        funding_inputs: funding_inputs.to_vec(),
        fund_transaction: fund,
        opcat_scripts: scripts.clone(),
    };

    Ok(accepted_contract)
}

/// Verifies the information of the accepting party [`Accept` message](dlc_messages::AcceptDlc),
/// creates a [`SignedContract`], and generates the offering party CET adaptor signatures.
pub fn verify_accepted_and_sign_contract<W: Deref>(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    accept_msg: &AcceptDlc,
    wallet: &W,
) -> Result<(SignedContract, SignDlc), Error>
where
    W::Target: Wallet,
{
    let (tx_input_infos, input_amount) = get_tx_input_infos(&accept_msg.funding_inputs)?;

    let accept_params = PartyParams {
        fund_pubkey: accept_msg.funding_pubkey,
        change_script_pubkey: accept_msg.change_spk.clone(),
        change_serial_id: accept_msg.change_serial_id,
        payout_script_pubkey: accept_msg.payout_spk.clone(),
        payout_serial_id: accept_msg.payout_serial_id,
        inputs: tx_input_infos,
        input_amount,
        collateral: accept_msg.accept_collateral,
    };

    let signed_contract = sign_contract_internal(
        secp,
        offered_contract,
        &accept_params,
        &accept_msg.funding_inputs,
        wallet,
    )?;

    let signed_msg: SignDlc = signed_contract.get_sign_dlc();

    Ok((signed_contract, signed_msg))
}

fn populate_psbt(psbt: &mut Psbt, all_funding_inputs: &[&FundingInput]) -> Result<(), Error> {
    // add witness utxo to fund_psbt for all inputs
    for (input_index, x) in all_funding_inputs.iter().enumerate() {
        let tx = Transaction::consensus_decode(&mut x.prev_tx.as_slice()).map_err(|_| {
            Error::InvalidParameters(
                "Could not decode funding input previous tx parameter".to_string(),
            )
        })?;
        let vout = x.prev_tx_vout;
        let tx_out = tx.output.get(vout as usize).ok_or_else(|| {
            Error::InvalidParameters(format!("Previous tx output not found at index {}", vout))
        })?;

        psbt.inputs[input_index].witness_utxo = Some(tx_out.clone());
        psbt.inputs[input_index].redeem_script = Some(x.redeem_script.clone());
    }

    Ok(())
}

pub(crate) fn sign_contract_internal<W: Deref>(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    accept_params: &PartyParams,
    funding_inputs_info: &[FundingInput],
    wallet: &W,
) -> Result<SignedContract, Error>
where
    W::Target: Wallet,
{
    let mut all_scripts: Vec<ScriptBuf> = Vec::new();

    let mut adaptor_infos = Vec::new();

    for contract_info in offered_contract.contract_info.iter() {
        let (adaptor_info, scripts) = contract_info.get_scripts(
            secp,
            offered_contract.total_collateral,
            &offered_contract.offer_params.payout_script_pubkey,
            &accept_params.payout_script_pubkey,
            all_scripts.len(),
        )?;
        adaptor_infos.push(adaptor_info);
        all_scripts.extend(scripts);
    }

    // get all funding inputs
    let mut all_funding_inputs = offered_contract
        .funding_inputs
        .iter()
        .chain(funding_inputs_info.iter())
        .collect::<Vec<_>>();
    // sort by serial id
    all_funding_inputs.sort_by_key(|x| x.input_serial_id);

    let taproot_spend_info = dlc::opcat_utils::taproot_spend_info(secp, &all_scripts)?;

    let script_pk =
        Address::p2tr_tweaked(taproot_spend_info.output_key(), Network::Regtest).script_pubkey();

    let fund = dlc::create_fund_transaction_with_fees(
        &offered_contract.offer_params,
        accept_params,
        offered_contract.fee_rate_per_vb,
        0,
        0,
        &script_pk,
        Amount::ZERO,
    )
    .expect("Could not build fund tx");

    let mut fund_psbt = Psbt::from_unsigned_tx(fund.clone())
        .map_err(|_| Error::InvalidState("Tried to create PSBT from signed tx".to_string()))?;
    populate_psbt(&mut fund_psbt, &all_funding_inputs)?;

    // Vec<Witness>
    let witnesses: Vec<Witness> = offered_contract
        .funding_inputs
        .iter()
        .map(|x| {
            let input_index = all_funding_inputs
                .iter()
                .position(|y| y == &x)
                .ok_or_else(|| {
                    Error::InvalidState(format!(
                        "Could not find input for serial id {}",
                        x.input_serial_id
                    ))
                })?;

            wallet.sign_psbt_input(&mut fund_psbt, input_index)?;

            let witness = fund_psbt.inputs[input_index]
                .final_script_witness
                .clone()
                .ok_or(Error::InvalidParameters(
                    "No witness from signing psbt input".to_string(),
                ))?;

            Ok(witness)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let funding_signatures: Vec<FundingSignature> = witnesses
        .into_iter()
        .map(|witness| {
            let witness_elements = witness
                .iter()
                .map(|z| WitnessElement {
                    witness: z.to_vec(),
                })
                .collect();
            Ok(FundingSignature { witness_elements })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let accepted_contract = AcceptedContract {
        offered_contract: offered_contract.clone(),
        accept_params: accept_params.clone(),
        funding_inputs: funding_inputs_info.to_vec(),
        adaptor_infos,
        opcat_scripts: all_scripts,
        fund_transaction: fund.clone(),
    };

    let signed_contract = SignedContract {
        accepted_contract,
        funding_signatures: FundingSignatures { funding_signatures },
    };

    Ok(signed_contract)
}

/// Verifies the information from the offer party [`Sign` message](dlc_messages::SignDlc),
/// creates the accepting party's [`SignedContract`] and returns it along with the
/// signed fund transaction.
pub fn verify_signed_contract<W: Deref>(
    accepted_contract: &AcceptedContract,
    sign_msg: &SignDlc,
    wallet: &W,
) -> Result<(SignedContract, Transaction), Error>
where
    W::Target: Wallet,
{
    verify_signed_contract_internal(accepted_contract, &sign_msg.funding_signatures, wallet)
}

pub(crate) fn verify_signed_contract_internal<W: Deref>(
    accepted_contract: &AcceptedContract,
    funding_signatures: &FundingSignatures,
    wallet: &W,
) -> Result<(SignedContract, Transaction), Error>
where
    W::Target: Wallet,
{
    let offered_contract = &accepted_contract.offered_contract;

    let fund_tx = &accepted_contract.fund_transaction;
    let mut fund_psbt = Psbt::from_unsigned_tx(fund_tx.clone())
        .map_err(|_| Error::InvalidState("Tried to create PSBT from signed tx".to_string()))?;

    // get all funding inputs
    let mut all_funding_inputs = offered_contract
        .funding_inputs
        .iter()
        .chain(accepted_contract.funding_inputs.iter())
        .collect::<Vec<_>>();
    // sort by serial id
    all_funding_inputs.sort_by_key(|x| x.input_serial_id);

    populate_psbt(&mut fund_psbt, &all_funding_inputs)?;

    for (funding_input, funding_signatures) in offered_contract
        .funding_inputs
        .iter()
        .zip(funding_signatures.funding_signatures.iter())
    {
        let input_index = all_funding_inputs
            .iter()
            .position(|x| x == &funding_input)
            .ok_or_else(|| {
                Error::InvalidState(format!(
                    "Could not find input for serial id {}",
                    funding_input.input_serial_id
                ))
            })?;

        fund_psbt.inputs[input_index].final_script_witness = Some(Witness::from_slice(
            &funding_signatures
                .witness_elements
                .iter()
                .map(|x| x.witness.clone())
                .collect::<Vec<_>>(),
        ));
    }

    for funding_input in &accepted_contract.funding_inputs {
        let input_index = all_funding_inputs
            .iter()
            .position(|x| x == &funding_input)
            .ok_or_else(|| {
                Error::InvalidState(format!(
                    "Could not find input for serial id {}",
                    funding_input.input_serial_id
                ))
            })?;

        wallet.sign_psbt_input(&mut fund_psbt, input_index)?;
    }

    let signed_contract = SignedContract {
        accepted_contract: accepted_contract.clone(),
        funding_signatures: funding_signatures.clone(),
    };

    let transaction = fund_psbt.extract_tx_unchecked_fee_rate();

    Ok((signed_contract, transaction))
}

/// Signs and return the CET that can be used to close the given contract.
pub fn get_signed_cet(
    secp: &Secp256k1<All>,
    contract: &SignedContract,
    contract_info: &ContractInfo,
    adaptor_info: &AdaptorInfo,
    attestations: &[(usize, OracleAttestation)],
) -> Result<Transaction, Error> {
    let (range_info, sigs) =
        crate::utils::get_range_info_and_oracle_sigs(contract_info, adaptor_info, attestations)?;
    let fund_tx = &contract.accepted_contract.fund_transaction;
    let agg_key = Keypair::from_secret_key(secp, &signatures_to_secret(&sigs)?);

    let taproot_spend_info =
        dlc::opcat_utils::taproot_spend_info(secp, &contract.accepted_contract.opcat_scripts)?;

    let tx = create_dlc_tx(
        bitcoin::OutPoint {
            txid: fund_tx.compute_txid(),
            vout: 0,
        },
        fund_tx.output[0].clone(),
        &contract
            .accepted_contract
            .offered_contract
            .offer_params
            .payout_script_pubkey,
        &contract
            .accepted_contract
            .accept_params
            .payout_script_pubkey,
        &agg_key,
        contract_info.get_payouts(contract.accepted_contract.offered_contract.total_collateral)?
            [range_info.payout_index],
        &taproot_spend_info,
    )?;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use bitcoin::Amount;
    use mocks::dlc_manager::contract::offered_contract::OfferedContract;
    use secp256k1_zkp::PublicKey;

    #[test]
    fn accept_contract_test() {
        let offer_dlc =
            serde_json::from_str(include_str!("../test_inputs/offer_contract.json")).unwrap();
        let dummy_pubkey: PublicKey =
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"
                .parse()
                .unwrap();
        let offered_contract =
            OfferedContract::try_from_offer_dlc(&offer_dlc, dummy_pubkey, [0; 32]).unwrap();
        let blockchain = Rc::new(mocks::mock_blockchain::MockBlockchain::new());
        let fee_rate: u64 = offered_contract.fee_rate_per_vb;
        let utxo_value = offered_contract.total_collateral
            - offered_contract.offer_params.collateral
            + crate::utils::get_half_common_fee(fee_rate).unwrap();
        let wallet = Rc::new(mocks::mock_wallet::MockWallet::new(
            &blockchain,
            &[utxo_value, Amount::from_sat(10000)],
        ));

        mocks::dlc_manager::contract_updater::accept_contract(
            secp256k1_zkp::SECP256K1,
            &offered_contract,
            &wallet,
            &wallet,
            &blockchain,
        )
        .expect("Not to fail");
    }
}
