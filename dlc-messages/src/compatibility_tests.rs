extern crate bitcoin;
extern crate bitcoin_test_utils;
extern crate dlc;
extern crate lightning;
extern crate secp256k1;

use super::{
    AcceptDlc, ContractInfo, ContractOutcome, FundingInput, FundingSignature, FundingSignatures,
    OfferDlc, OracleInfo, SignDlc, WitnessElement,
};
use bitcoin::consensus::encode::Decodable;
use bitcoin::SigHashType;
use bitcoin::{Address, OutPoint, Script, Transaction, Txid, VarInt};
use bitcoin_test_utils::*;
use dlc::{DlcTransactions, OracleInfo as DlcOracleInfo, PartyParams, Payout, TxInputInfo};
use lightning::ln::wire::{write, Encode};
use lightning::util::ser::Writeable;
use secp256k1::{
    ecdsa_adaptor::{AdaptorProof, AdaptorSignature},
    schnorrsig::Signature as SchnorrSignature,
    PublicKey, Secp256k1, SecretKey, Signature, Signing,
};
use std::str::FromStr;

const BITCOIN_CHAINHASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FeeTestParams {
    inputs: FeeTestInputs,
    offer_funding_fee: u64,
    offer_closing_fee: u64,
    accept_funding_fee: u64,
    accept_closing_fee: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FeeTestInputs {
    offer_inputs: Vec<FeeTestOfferInputs>,
    accept_inputs: Vec<FeeTestOfferInputs>,
    #[serde(rename = "offerPayoutSPKLen")]
    local_payout_spk_len: usize,
    #[serde(rename = "offerChangeSPKLen")]
    offer_change_spk_len: usize,
    #[serde(rename = "acceptPayoutSPKLen")]
    accept_payout_spk_len: usize,
    #[serde(rename = "acceptChangeSPKLen")]
    accept_change_spk_len: usize,
    fee_rate: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FeeTestOfferInputs {
    redeem_script_len: usize,
    max_witness_len: usize,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FeeTestScript {
    byte_len: usize,
    script: String,
    description: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TestParams {
    fee_rate: u64,
    contract_info: Vec<TestContractOutcomeInfo>,
    contract_maturity_bound: u32,
    contract_timeout: u32,
    oracle_info: OracleInfo,
    oracle_signature: SchnorrSignature,
    real_outcome: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TestInputs {
    params: TestParams,
    offer_params: TestPartyParams,
    accept_params: TestPartyParams,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    inputs: TestInputs,
    txs: Option<TestDlcTxs>,
    unsigned_txs: Option<TestDlcTxs>,
    signed_txs: Option<TestDlcTxs>,
    offer: Option<String>,
    accept: Option<String>,
    sign: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TestContractOutcomeInfo {
    outcome: String,
    pre_image: String,
    local_payout: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TestFundingInputInfo {
    tx: String,
    idx: u32,
    max_witness_len: u16,
    input_keys: Vec<SecretKey>,
    redeem_script: Option<String>,
    script_witness: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TestPartyParams {
    collateral: u64,
    funding_input_txs: Vec<TestFundingInputInfo>,
    change_address: Address,
    funding_priv_key: SecretKey,
    payout_address: Address,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TestDlcTxs {
    funding_tx: String,
    cets: Vec<String>,
    refund_tx: String,
}

impl From<&TestContractOutcomeInfo> for ContractOutcome {
    fn from(info: &TestContractOutcomeInfo) -> ContractOutcome {
        ContractOutcome {
            outcome: info.pre_image.clone(),
            local_payout: info.local_payout,
        }
    }
}

fn assert_unsigned_txs_equal(expected: &TestDlcTxs, actual: &DlcTransactions) {
    assert_eq!(expected.funding_tx, tx_to_string(&actual.fund));
    assert!(expected
        .cets
        .iter()
        .map(|x| tx_from_string(&x))
        .zip(actual.cets.iter())
        .all(|(a, b)| a.txid() == b.txid()));
    assert_eq!(
        tx_from_string(&expected.refund_tx).txid(),
        actual.refund.txid(),
    );
}

fn assert_signed_txs_equal(expected: &TestDlcTxs, actual: &DlcTransactions) {
    assert_eq!(expected.funding_tx, tx_to_string(&actual.fund));
    for i in 0..expected.cets.len() {
        assert_eq!(expected.cets[i], tx_to_string(&actual.cets[i]));
    }
    assert_eq!(expected.refund_tx, tx_to_string(&actual.refund));
}

fn parse_redeem_script(input: &Option<String>) -> Script {
    match input {
        None => Script::new(),
        Some(s) => {
            let hex = str_to_hex(s);
            Script::from(hex)
        }
    }
}

fn get_funding_params(
    txs: &[TestFundingInputInfo],
) -> (Vec<FundingInput>, Vec<Vec<SecretKey>>, u64) {
    let mut funding_inputs = Vec::<FundingInput>::with_capacity(txs.len());
    let mut sks = Vec::<Vec<SecretKey>>::new();
    let mut total_value = 0;
    for tx_info in txs {
        let mut tx_hex = Vec::<u8>::new();
        tx_hex.resize(tx_info.tx.len() / 2, 0);
        from_hex(&tx_info.tx, &mut tx_hex).unwrap();
        let tx = ::bitcoin::Transaction::consensus_decode(&tx_hex[..]).unwrap();
        let output = &tx.output[tx_info.idx as usize];
        funding_inputs.push(FundingInput {
            prev_tx: str_to_hex(&tx_info.tx),
            prev_tx_vout: tx_info.idx,
            max_witness_len: tx_info.max_witness_len,
            sequence: 0xffffffff,
            redeem_script: parse_redeem_script(&tx_info.redeem_script),
        });
        sks.push(tx_info.input_keys.clone());
        total_value += output.value;
    }

    (funding_inputs, sks, total_value)
}

fn get_party_params<C: Signing>(
    secp: &Secp256k1<C>,
    params: &TestPartyParams,
) -> (PartyParams, Vec<FundingInput>, Vec<Vec<SecretKey>>) {
    let (fund_inputs, sks, total_value) = get_funding_params(&params.funding_input_txs);
    let inputs: Vec<TxInputInfo> = fund_inputs.iter().map(|x| x.into()).collect();
    (
        PartyParams {
            fund_pubkey: PublicKey::from_secret_key(secp, &params.funding_priv_key),
            change_script_pubkey: params.change_address.script_pubkey(),
            final_script_pubkey: params.payout_address.script_pubkey(),
            inputs,
            collateral: params.collateral,
            input_amount: total_value,
        },
        fund_inputs,
        sks,
    )
}

fn get_payout(info: &TestContractOutcomeInfo, total_collateral: u64) -> Payout {
    Payout {
        offer: info.local_payout,
        accept: total_collateral - info.local_payout,
    }
}

fn get_contract_info(contract_outcome_infos: &Vec<TestContractOutcomeInfo>) -> ContractInfo {
    let outcomes = contract_outcome_infos
        .into_iter()
        .map(|x| ContractOutcome::from(x))
        .collect();

    ContractInfo { outcomes }
}

fn parse_script_witness(input: &Vec<u8>) -> Vec<Vec<u8>> {
    let nb_elements = VarInt::consensus_decode(&input[..]).unwrap();
    let mut remaining: Vec<u8> = input.iter().cloned().skip(nb_elements.len()).collect();
    let mut res = Vec::<Vec<u8>>::new();
    for _ in 0..nb_elements.0 {
        let size = VarInt::consensus_decode(&remaining[..]).unwrap();
        remaining.drain(0..size.len() as usize);
        res.push(remaining.drain(0..size.0 as usize).collect());
    }

    res
}

fn get_fund_input_witness<C: Signing>(
    secp: &Secp256k1<C>,
    fund_tx: &Transaction,
    info: &TxInputInfo,
    input: &FundingInput,
    sk: &Vec<SecretKey>,
    witness: &Vec<u8>,
    input_index: usize,
) -> Vec<Vec<u8>> {
    let prev_tx = Transaction::consensus_decode(&input.prev_tx[..]).unwrap();
    let prev_tx_output = &prev_tx.output[info.outpoint.vout as usize];
    let script_pubkey = &prev_tx_output.script_pubkey;
    let witness_stack = parse_script_witness(&witness);
    if script_pubkey.is_v0_p2wpkh() {
        vec![
            dlc::util::get_sig_for_p2wpkh_input(
                &secp,
                &sk[0],
                fund_tx,
                input_index,
                prev_tx_output.value,
                SigHashType::All,
            ),
            PublicKey::from_secret_key(secp, &sk[0])
                .serialize()
                .to_vec(),
        ]
    } else if script_pubkey.is_v0_p2wsh() || info.redeem_script.is_witness_program() {
        let sigs = sk
            .iter()
            .map(|x| {
                dlc::util::get_sig_for_tx_input(
                    &secp,
                    fund_tx,
                    input_index,
                    &Script::from(witness_stack[0].clone()),
                    prev_tx.output[info.outpoint.vout as usize].value,
                    SigHashType::All,
                    &x,
                )
            })
            .collect::<Vec<Vec<u8>>>();
        let mut res = vec![Vec::new()];
        res.extend(sigs);
        res.extend(witness_stack);
        res
    } else {
        panic!("Unsupported redeem script type");
    }
}

fn get_fund_input_witnesses<C: Signing>(
    secp: &Secp256k1<C>,
    fund_tx: &Transaction,
    witnesses: &Vec<Vec<u8>>,
    params: &PartyParams,
    inputs: &Vec<FundingInput>,
    sks: &Vec<Vec<SecretKey>>,
    index_start: usize,
) -> Vec<FundingSignature> {
    params
        .inputs
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let witness_stack = get_fund_input_witness(
                secp,
                &fund_tx,
                &x,
                &inputs[i],
                &sks[i],
                &witnesses[i],
                i + index_start,
            );
            FundingSignature {
                witness_elements: witness_stack
                    .into_iter()
                    .map(|x| WitnessElement { witness: x })
                    .collect(),
            }
        })
        .collect()
}

fn get_funding_signatures<C: Signing>(
    secp: &Secp256k1<C>,
    fund_tx: &Transaction,
    test_party_params: &TestPartyParams,
    party_params: &PartyParams,
    inputs: &Vec<FundingInput>,
    sks: &Vec<Vec<SecretKey>>,
    index_start: usize,
) -> Vec<FundingSignature> {
    let offer_fund_input_witnesses = test_party_params
        .funding_input_txs
        .iter()
        .map(|x| str_to_hex(&x.script_witness))
        .collect();
    get_fund_input_witnesses(
        secp,
        fund_tx,
        &offer_fund_input_witnesses,
        party_params,
        inputs,
        sks,
        index_start,
    )
}

fn get_cets_and_refund_sigs(
    secp: &Secp256k1<secp256k1::All>,
    cets: &Vec<Transaction>,
    refund_tx: &Transaction,
    oracle_infos: &Vec<DlcOracleInfo>,
    fund_sk: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
) -> (Vec<(AdaptorSignature, AdaptorProof)>, Signature) {
    (
        dlc::create_cet_adaptor_sigs_from_oracle_info(
            secp,
            cets,
            oracle_infos,
            fund_sk,
            funding_script_pubkey,
            fund_output_value,
        )
        .unwrap(),
        dlc::util::get_raw_sig_for_tx_input(
            &secp,
            refund_tx,
            0,
            funding_script_pubkey,
            fund_output_value,
            fund_sk,
        ),
    )
}

fn assert_msg_eq<M: Encode + Writeable>(expected_str: &str, actual: M) {
    let mut actual_hex = Vec::new();
    write(&actual, &mut actual_hex).unwrap();
    let expected_hex = str_to_hex(expected_str);
    assert_eq!(expected_hex, actual_hex);
}

fn test_single(case: TestCase, secp: &secp256k1::Secp256k1<secp256k1::All>) {
    let params = &case.inputs.params;
    let (offer_params, offer_inputs, offer_input_sks) =
        get_party_params(&secp, &case.inputs.offer_params);
    let (accept_params, accept_inputs, accept_input_sks) =
        get_party_params(&secp, &case.inputs.accept_params);

    let total_collateral = offer_params.collateral + accept_params.collateral;

    let outcomes: Vec<Vec<u8>> = params
        .contract_info
        .iter()
        .map(|x| str_to_hex(&x.outcome))
        .collect();
    let contract_info = get_contract_info(&params.contract_info);

    let payouts = &params
        .contract_info
        .iter()
        .map(|x| get_payout(x, total_collateral))
        .collect::<Vec<_>>();

    let dlc_txs = dlc::create_dlc_transactions(
        &offer_params,
        &accept_params,
        payouts,
        params.contract_timeout,
        params.fee_rate,
        0,
        params.contract_maturity_bound,
    )
    .unwrap();

    let mut fund_tx = dlc_txs.fund.clone();
    let mut refund_tx = dlc_txs.refund.clone();
    let funding_script_pubkey =
        dlc::make_funding_redeemscript(&offer_params.fund_pubkey, &accept_params.fund_pubkey);
    let offer_funding_witnesses = get_funding_signatures(
        secp,
        &fund_tx,
        &case.inputs.offer_params,
        &offer_params,
        &offer_inputs,
        &offer_input_sks,
        0,
    );
    let accept_funding_witnesses = get_funding_signatures(
        secp,
        &fund_tx,
        &case.inputs.accept_params,
        &accept_params,
        &accept_inputs,
        &accept_input_sks,
        offer_inputs.len(),
    );

    let fund_output_value = fund_tx.output[0].value;
    let offer_fund_sk = case.inputs.offer_params.funding_priv_key;
    let accept_fund_sk = case.inputs.accept_params.funding_priv_key;
    let oracle_pub_key = params.oracle_info.public_key;
    let oracle_nonce = params.oracle_info.nonce;
    let msgs: Vec<_> = outcomes
        .iter()
        .map(|x| vec![secp256k1::Message::from_slice(x).unwrap()])
        .collect();
    let oracle_infos = vec![DlcOracleInfo {
        public_key: oracle_pub_key,
        nonces: vec![oracle_nonce],
        msgs,
    }];

    let (offer_cets_sigs, offer_refund_sig) = get_cets_and_refund_sigs(
        secp,
        &dlc_txs.cets,
        &refund_tx,
        &oracle_infos,
        &offer_fund_sk,
        &funding_script_pubkey,
        fund_output_value,
    );
    let (accept_cets_sigs, accept_refund_sig) = get_cets_and_refund_sigs(
        secp,
        &dlc_txs.cets,
        &refund_tx,
        &oracle_infos,
        &accept_fund_sk,
        &funding_script_pubkey,
        fund_output_value,
    );

    let actual_outcome_index = params
        .contract_info
        .iter()
        .position(|x| x.outcome == case.inputs.params.real_outcome)
        .unwrap();

    let fund_tx_id = fund_tx.txid();
    for i in 0..fund_tx.input.len() {
        fund_tx.input[i].witness = match i {
            i if i < offer_funding_witnesses.len() => offer_funding_witnesses[i]
                .witness_elements
                .iter()
                .map(|x| x.witness.clone())
                .collect(),
            _ => accept_funding_witnesses[i - offer_funding_witnesses.len()]
                .witness_elements
                .iter()
                .map(|x| x.witness.clone())
                .collect(),
        }
    }
    let mut offer_final_cet = dlc_txs.cets[actual_outcome_index].clone();

    dlc::sign_cet(
        secp,
        &mut offer_final_cet,
        &accept_cets_sigs[actual_outcome_index].0,
        &vec![vec![case.inputs.params.oracle_signature]],
        &offer_fund_sk,
        &accept_params.fund_pubkey,
        &funding_script_pubkey,
        fund_tx.output[0].value,
    )
    .expect("Error signing CET");

    let mut accept_final_cet = dlc_txs.cets[actual_outcome_index].clone();

    dlc::sign_cet(
        secp,
        &mut accept_final_cet,
        &offer_cets_sigs[actual_outcome_index].0,
        &vec![vec![case.inputs.params.oracle_signature]],
        &accept_fund_sk,
        &offer_params.fund_pubkey,
        &funding_script_pubkey,
        fund_tx.output[0].value,
    )
    .expect("Error signing CET");

    dlc::util::sign_multi_sig_input(
        &secp,
        &mut refund_tx,
        &offer_refund_sig,
        &PublicKey::from_secret_key(&secp, &offer_fund_sk),
        &accept_fund_sk,
        &funding_script_pubkey,
        fund_tx.output[0].value,
        0,
    );

    let signed_dlc_txs = DlcTransactions {
        fund: fund_tx,
        cets: vec![offer_final_cet, accept_final_cet],
        refund: refund_tx,
    };

    let offer = OfferDlc {
        contract_flags: 0,
        chain_hash: BITCOIN_CHAINHASH,
        oracle_info: OracleInfo {
            public_key: params.oracle_info.public_key,
            nonce: params.oracle_info.nonce,
        },
        funding_pubkey: offer_params.fund_pubkey,
        payout_spk: case.inputs.offer_params.payout_address.script_pubkey(),
        total_collateral: case.inputs.offer_params.collateral,
        change_spk: case.inputs.offer_params.change_address.script_pubkey(),
        contract_info,
        contract_maturity_bound: params.contract_maturity_bound,
        contract_timeout: params.contract_timeout,
        fee_rate_per_vb: params.fee_rate,
        funding_inputs: offer_inputs,
    };

    let temporary_contract_id = offer.get_hash().unwrap();

    let accept = AcceptDlc {
        funding_inputs: accept_inputs,
        change_spk: case.inputs.accept_params.change_address.script_pubkey(),
        payout_spk: case.inputs.accept_params.payout_address.script_pubkey(),
        funding_pubkey: accept_params.fund_pubkey,
        cet_adaptor_signatures: accept_cets_sigs.into(),
        refund_signature: accept_refund_sig,
        temporary_contract_id,
        total_collateral: accept_params.collateral,
    };

    let sign = SignDlc {
        cet_adaptor_signatures: offer_cets_sigs.into(),
        contract_id: super::compute_contract_id(fund_tx_id, 0, temporary_contract_id),
        funding_signatures: FundingSignatures {
            funding_signatures: offer_funding_witnesses,
        },
        refund_signature: offer_refund_sig,
    };

    // Assert

    let unsigned_txs = case.unsigned_txs.unwrap();
    assert_unsigned_txs_equal(&unsigned_txs, &dlc_txs);

    let signed_txs = case.signed_txs.unwrap();
    assert_signed_txs_equal(&signed_txs, &signed_dlc_txs);

    assert_msg_eq(&case.offer.unwrap(), offer);
    assert_msg_eq(&case.accept.unwrap(), accept);
    assert_msg_eq(&case.sign.unwrap(), sign);
}

#[test]
fn test_dlc_fees() {
    let content = include_str!("./test_inputs/dlc_fee_test.json");
    let content_test_scripts = include_str!("./test_inputs/dlc_fee_test_scripts.json");
    let test_cases: Vec<FeeTestParams> = serde_json::from_str(&content).unwrap();
    let test_scripts: Vec<FeeTestScript> = serde_json::from_str(&content_test_scripts).unwrap();

    let get_test_script = |len: usize| -> Script {
        let script_str = test_scripts
            .iter()
            .find(|x| x.byte_len == len)
            .unwrap()
            .script
            .clone();
        let mut script_hex = Vec::new();
        script_hex.resize(script_str.len() / 2, 0);
        from_hex(&script_str, &mut script_hex).unwrap();
        Script::from(script_hex)
    };

    let get_redeem_script = |len: usize| -> Script {
        if len == 0 {
            Script::new()
        } else {
            let mut res = Vec::new();
            res.resize(len, 0);
            Script::from(res)
        }
    };

    let get_inputs = |test_inputs: Vec<FeeTestOfferInputs>| -> Vec<TxInputInfo> {
        test_inputs
            .iter()
            .map(|x| TxInputInfo {
                outpoint: OutPoint {
                    txid: Txid::from_str(
                        "83266d6b22a9babf6ee469b88fd0d3a0c690525f7c903aff22ec8ee44214604f",
                    )
                    .unwrap(),
                    vout: 0,
                },
                max_witness_len: x.max_witness_len,
                redeem_script: get_redeem_script(x.redeem_script_len),
            })
            .collect()
    };

    let get_party_params = |change_spk_len: usize,
                            payout_spk_len: usize,
                            inputs: Vec<FeeTestOfferInputs>|
     -> PartyParams {
        PartyParams {
            fund_pubkey: PublicKey::from_str(
                "03c06fd4dee6502848b937840019effbab0856a227d984785367b079969471a6ed",
            )
            .unwrap(),
            collateral: 100000,
            change_script_pubkey: get_test_script(change_spk_len),
            final_script_pubkey: get_test_script(payout_spk_len),
            inputs: get_inputs(inputs),
            input_amount: 110000,
        }
    };

    for case in test_cases {
        let offer_party_params = get_party_params(
            case.inputs.offer_change_spk_len,
            case.inputs.local_payout_spk_len,
            case.inputs.offer_inputs,
        );
        let accept_party_params = get_party_params(
            case.inputs.accept_change_spk_len,
            case.inputs.accept_payout_spk_len,
            case.inputs.accept_inputs,
        );
        let (_, offer_fund_fee, offer_close_fee) = offer_party_params
            .get_change_output_and_fees(case.inputs.fee_rate)
            .unwrap();
        let (_, accept_fund_fee, accept_close_fee) = accept_party_params
            .get_change_output_and_fees(case.inputs.fee_rate)
            .unwrap();

        assert_eq!(case.offer_funding_fee, offer_fund_fee);
        assert_eq!(case.offer_closing_fee, offer_close_fee);
        assert_eq!(case.accept_funding_fee, accept_fund_fee);
        assert_eq!(case.accept_closing_fee, accept_close_fee);
    }
}

#[test]
fn test_dlc_txs() {
    let secp = Secp256k1::new();
    let content = include_str!("./test_inputs/dlc_tx_test.json");
    let test_cases: Vec<TestCase> = serde_json::from_str(&content).unwrap();

    for test_case in test_cases {
        let params = test_case.inputs.params;
        let (offer_params, _, _) = get_party_params(&secp, &test_case.inputs.offer_params);
        let (accept_params, _, _) = get_party_params(&secp, &test_case.inputs.accept_params);
        let total_collateral = offer_params.collateral + accept_params.collateral;
        let txs = dlc::create_dlc_transactions(
            &offer_params,
            &accept_params,
            &params
                .contract_info
                .iter()
                .map(|x| get_payout(x, total_collateral))
                .collect::<Vec<_>>(),
            params.contract_timeout,
            params.fee_rate,
            0,
            params.contract_maturity_bound,
        )
        .unwrap();
        let test_txs = test_case.txs.unwrap();

        assert_unsigned_txs_equal(&test_txs, &txs);
    }
}

#[test]
fn test_tlv_vectors() {
    let secp = secp256k1::Secp256k1::new();
    let content = include_str!("./test_inputs/dlc_test.json");
    let test_cases: Vec<TestCase> = serde_json::from_str(&content).unwrap();

    for case in test_cases {
        test_single(case, &secp);
    }
}
