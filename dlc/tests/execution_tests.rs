extern crate bitcoin;
extern crate bitcoincore_rpc;
extern crate bitcoincore_rpc_json;
extern crate dlc;
extern crate secp256k1;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc_json::AddressType;

use bitcoin::hashes::*;
use bitcoin::{OutPoint, Script, SigHashType};
use dlc::digit_decomposition::{decompose_value, group_by_ignoring_digits, pad_range_payouts};
use dlc::multi_trie::{MultiTrie, MultiTrieIterator};
use dlc::{DlcTransactions, OracleInfo, PartyParams, Payout, RangeInfo, RangePayout, TxInputInfo};
use secp256k1::{
    ecdsa_adaptor::{AdaptorProof, AdaptorSignature},
    rand::{seq::SliceRandom, thread_rng, Rng, RngCore},
    schnorrsig::{KeyPair, PublicKey as SchnorrPublicKey, Signature as SchnorrSignature},
    Message, PublicKey, Secp256k1, SecretKey, Signing,
};
use std::convert::TryInto;

const LOCALPARTY: &str = "alice";
const REMOTEPARTY: &str = "bob";
const SINK: &str = "sink";

const RPCBASE: &str = "http://localhost:18443";

const BTC_TO_SAT: u64 = 100000000;
const PARTY_COLLATERAL: u64 = 1 * BTC_TO_SAT;

const FUND_LOCK_TIME: u32 = 1000;
const CET_LOCK_TIME: u32 = FUND_LOCK_TIME + 1000;
const REFUND_LOCK_TIME: u32 = CET_LOCK_TIME + 1000;

struct OraclePrivInfo {
    info: OracleInfo,
    priv_keypair: KeyPair,
    priv_nonces: Vec<[u8; 32]>,
}

struct PartyTestParams {
    params: PartyParams,
    fund_priv_key: SecretKey,
    input_priv_key: SecretKey,
    rpc: Client,
}

struct TestParams<C: Signing> {
    secp: Secp256k1<C>,
    offer_adaptor_pair: (AdaptorSignature, AdaptorProof),
    offer_params: PartyTestParams,
    accept_params: PartyTestParams,
    dlc_txs: DlcTransactions,
    oracle_signatures: Vec<Vec<SchnorrSignature>>,
    funding_script_pubkey: Script,
    fund_output_value: u64,
    cet_index: usize,
    sink_rpc: Client,
}

fn outcomes() -> Vec<Payout> {
    vec![
        Payout {
            offer: 2 * BTC_TO_SAT,
            accept: 0,
        },
        Payout {
            offer: 0,
            accept: 2 * BTC_TO_SAT,
        },
    ]
}

fn get_new_wallet_rpc(default_rpc: &Client, wallet_name: &str, auth: Auth) -> Client {
    default_rpc
        .create_wallet(wallet_name, Some(false), None, None, None)
        .unwrap();
    let rpc_url = format!("{}{}{}", RPCBASE, "/wallet/", wallet_name);
    Client::new(rpc_url, auth).unwrap()
}

fn get_base_test_msgs(
    nb_oracles: usize,
    nb_outcomes: usize,
    nb_digits: usize,
) -> Vec<Vec<Vec<Message>>> {
    (0..nb_outcomes)
        .map(|x| {
            (0..nb_oracles)
                .map(|y| {
                    (0..nb_digits)
                        .map(|z| {
                            Message::from_hashed_data::<secp256k1::bitcoin_hashes::sha256::Hash>(&[
                                ((y + x + z) as u8).try_into().unwrap(),
                            ])
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn get_oracle_sigs<C: Signing>(
    secp: &Secp256k1<C>,
    oracle_infos: &Vec<OraclePrivInfo>,
    messages: &Vec<Vec<Vec<Message>>>,
    outcome_index: usize,
) -> Vec<Vec<SchnorrSignature>> {
    let mut oracle_sigs: Vec<Vec<SchnorrSignature>> = Vec::with_capacity(oracle_infos.len());
    oracle_sigs.resize(oracle_infos.len(), Vec::new());
    for (i, info) in oracle_infos.iter().enumerate() {
        for j in 0..messages[outcome_index][i].len() {
            let sig = secp.schnorrsig_sign_with_nonce(
                &messages[outcome_index][i][j],
                &info.priv_keypair,
                &info.priv_nonces[j],
            );
            oracle_sigs[i].push(sig);
        }
    }
    oracle_sigs
}

fn get_oracle_infos<C: Signing, R: Rng + ?Sized>(
    secp: &Secp256k1<C>,
    rng: &mut R,
    nb_oracles: usize,
    nb_digits: usize,
) -> Vec<OraclePrivInfo> {
    let mut oracle_infos: Vec<OraclePrivInfo> = Vec::with_capacity(nb_oracles);

    for _ in 0..nb_oracles {
        let (oracle_kp, oracle_pubkey) = secp.generate_schnorrsig_keypair(rng);
        let mut nonces: Vec<SchnorrPublicKey> = Vec::with_capacity(nb_digits);
        let mut sk_nonces: Vec<[u8; 32]> = Vec::with_capacity(nb_digits);
        for _ in 0..nb_digits {
            let mut sk_nonce = [0u8; 32];
            rng.fill_bytes(&mut sk_nonce);
            let oracle_r_kp =
                secp256k1::schnorrsig::KeyPair::from_seckey_slice(&secp, &sk_nonce).unwrap();
            let nonce = SchnorrPublicKey::from_keypair(&secp, &oracle_r_kp);
            nonces.push(nonce);
            sk_nonces.push(sk_nonce);
        }
        oracle_infos.push(OraclePrivInfo {
            info: OracleInfo {
                public_key: oracle_pubkey,
                nonces,
            },
            priv_keypair: oracle_kp,
            priv_nonces: sk_nonces,
        });
    }
    oracle_infos
}

fn init() -> (Client, Client, Client) {
    let auth = Auth::UserPass(
        "testuser".to_string(),
        "lq6zequb-gYTdF2_ZEUtr8ywTXzLYtknzWU4nV8uVoo=".to_string(),
    );
    let rpc = Client::new(RPCBASE.to_string(), auth.clone()).unwrap();

    let offer_rpc = get_new_wallet_rpc(&rpc, LOCALPARTY, auth.clone());
    let accept_rpc = get_new_wallet_rpc(&rpc, REMOTEPARTY, auth.clone());
    let sink_rpc = get_new_wallet_rpc(&rpc, SINK, auth.clone());

    let offer_address = offer_rpc
        .get_new_address(None, Some(AddressType::Bech32))
        .unwrap();
    let accept_address = accept_rpc
        .get_new_address(None, Some(AddressType::Bech32))
        .unwrap();
    let sink_address = sink_rpc
        .get_new_address(None, Some(AddressType::Bech32))
        .unwrap();

    sink_rpc.generate_to_address(1, &offer_address).unwrap();
    sink_rpc.generate_to_address(1, &accept_address).unwrap();
    sink_rpc.generate_to_address(100, &sink_address).unwrap();

    (offer_rpc, accept_rpc, sink_rpc)
}

fn generate_dlc_parameters<'a, C: secp256k1::Signing>(
    rpc: Client,
    secp: &secp256k1::Secp256k1<C>,
    collateral: u64,
) -> PartyTestParams {
    let mut rng = thread_rng();
    let change_address = rpc
        .get_new_address(None, Some(AddressType::Bech32))
        .unwrap();
    let payout_address = rpc
        .get_new_address(None, Some(AddressType::Bech32))
        .unwrap();
    let fund_address = rpc
        .get_new_address(None, Some(AddressType::Bech32))
        .unwrap();
    let fund_priv_key = rpc.dump_private_key(&fund_address).unwrap().key;
    let mut utxos = rpc
        .list_unspent(None, None, None, Some(false), None)
        .unwrap();
    let utxo = utxos.pop().unwrap();
    let input_priv_key = {
        let address = utxo.address.clone().unwrap();
        let privkey = rpc.dump_private_key(&address).unwrap();
        privkey.key
    };

    PartyTestParams {
        params: PartyParams {
            fund_pubkey: PublicKey::from_secret_key(secp, &fund_priv_key),
            change_script_pubkey: change_address.script_pubkey(),
            change_serial_id: rng.next_u64(),
            payout_script_pubkey: payout_address.script_pubkey(),
            payout_serial_id: rng.next_u64(),
            inputs: vec![TxInputInfo {
                outpoint: OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                max_witness_len: dlc::P2WPKH_WITNESS_SIZE,
                redeem_script: Script::new(),
                serial_id: rng.next_u64(),
            }],
            input_amount: utxo.amount.as_sat(),
            collateral,
        },
        fund_priv_key,
        input_priv_key,
        rpc,
    }
}

#[derive(PartialEq)]
enum TestCase {
    Close,
    Refund,
    Decomposition,
}

fn get_adaptor_point_from_paths<C: Signing>(
    secp: &Secp256k1<C>,
    oracle_infos: &Vec<OracleInfo>,
    paths: &Vec<Vec<usize>>,
) -> Result<PublicKey, dlc::Error> {
    let paths_msg: Vec<Vec<Message>> = paths
        .iter()
        .map(|x| {
            x.iter()
                .map(|y| Message::from_hashed_data::<sha256::Hash>(y.to_string().as_bytes()))
                .collect()
        })
        .collect();
    dlc::get_adaptor_point_from_oracle_info(&secp, &oracle_infos, &paths_msg)
}

#[test]
#[ignore]
fn integration_tests_close() {
    let mut test_params = integration_tests_basic_setup();
    integration_tests_common(&mut test_params, TestCase::Close);
}

#[test]
#[ignore]
fn integration_tests_refund() {
    let mut test_params = integration_tests_basic_setup();
    integration_tests_common(&mut test_params, TestCase::Refund);
}

#[test]
#[ignore]
fn integration_tests_decomposed_single_oracle() {
    integration_tests_decomposed_common(1, 1, 1000, 11, 4, 5, 2);
}

#[test]
#[ignore]
fn integration_tests_decomposed_multi_oracle() {
    integration_tests_decomposed_common(3, 2, 100, 11, 4, 5, 2);
}

fn integration_tests_decomposed_common(
    nb_oracles: usize,
    nb_required: usize,
    nb_payouts: u64,
    nb_digits: usize,
    min_support_exp: usize,
    max_error_exp: usize,
    base: usize,
) {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = &mut thread_rng();
    let payouts: Vec<Payout> = (0..nb_payouts)
        .map(|i| Payout {
            offer: (2 * nb_payouts - 2 * i) * (BTC_TO_SAT / nb_payouts),
            accept: (2 * i) * (BTC_TO_SAT / nb_payouts),
        })
        .collect();
    let mut outcomes = Vec::<RangePayout>::new();
    for i in 0..(nb_payouts as usize) {
        outcomes.push(RangePayout {
            start: (nb_payouts as usize) + i,
            count: 1,
            payout: payouts[i].clone(),
        })
    }

    let outcomes = pad_range_payouts(outcomes, base, nb_digits);

    let (offer_rpc, accept_rpc, sink_rpc) = init();

    let offer_params = generate_dlc_parameters(offer_rpc, &secp, PARTY_COLLATERAL);
    let accept_params = generate_dlc_parameters(accept_rpc, &secp, PARTY_COLLATERAL);

    let dlc_txs = dlc::create_dlc_transactions(
        &offer_params.params,
        &accept_params.params,
        &payouts,
        REFUND_LOCK_TIME,
        2,
        FUND_LOCK_TIME,
        CET_LOCK_TIME,
        rng.next_u64(),
    )
    .expect("Error creating dlc transactions.");

    let oracle_priv_infos = get_oracle_infos(&secp, rng, nb_oracles, nb_digits);
    let oracle_infos: Vec<OracleInfo> = oracle_priv_infos.iter().map(|x| x.info.clone()).collect();

    let funding_script_pubkey = dlc::make_funding_redeemscript(
        &offer_params.params.fund_pubkey,
        &accept_params.params.fund_pubkey,
    );

    let fund_output_value = dlc::util::get_output_for_script_pubkey(
        &dlc_txs.fund,
        &funding_script_pubkey.to_v0_p2wsh(),
    )
    .expect("Could not find fund output")
    .1
    .value;

    let mut multi_trie = MultiTrie::new(
        nb_oracles,
        nb_required,
        base,
        min_support_exp,
        max_error_exp,
        nb_digits,
        true,
    );
    let mut adaptor_pairs_offer = Vec::new();
    let mut adaptor_pairs_accept = Vec::new();
    let mut cet_index = 0;

    for outcome in outcomes {
        if outcome.payout != payouts[cet_index] {
            cet_index += 1;
            assert_eq!(outcome.payout, payouts[cet_index]);
        }

        let cet = &dlc_txs.cets[cet_index];

        let groups = group_by_ignoring_digits(
            outcome.start,
            outcome.start + outcome.count - 1,
            base,
            nb_digits,
        )
        .unwrap();
        for group in groups {
            let mut get_value = |paths: &Vec<Vec<usize>>,
                                 oracle_indexes: &Vec<usize>|
             -> Result<RangeInfo, dlc::Error> {
                let adaptor_point = get_adaptor_point_from_paths(
                    &secp,
                    &oracle_infos
                        .iter()
                        .enumerate()
                        .filter_map(|(i, x)| {
                            if oracle_indexes.contains(&i) {
                                Some(x.clone())
                            } else {
                                None
                            }
                        })
                        .collect(),
                    paths,
                )
                .unwrap();
                let adaptor_pair_offer = dlc::create_cet_adaptor_sig_from_point(
                    &secp,
                    cet,
                    &adaptor_point,
                    &offer_params.fund_priv_key,
                    &funding_script_pubkey,
                    fund_output_value,
                )
                .unwrap();
                let adaptor_pair_accept = dlc::create_cet_adaptor_sig_from_point(
                    &secp,
                    cet,
                    &adaptor_point,
                    &accept_params.fund_priv_key,
                    &funding_script_pubkey,
                    fund_output_value,
                )
                .unwrap();
                adaptor_pairs_offer.push(adaptor_pair_offer);
                adaptor_pairs_accept.push(adaptor_pair_accept);
                Ok(RangeInfo {
                    cet_index,
                    adaptor_index: adaptor_pairs_offer.len() - 1,
                })
            };
            multi_trie
                .insert(&group, &mut get_value)
                .expect("Error inserting into trie");
        }
    }

    let m_trie_iter = MultiTrieIterator::new(&multi_trie);

    for res in m_trie_iter {
        let mut cur_oracle_infos: Vec<OracleInfo> = Vec::with_capacity(nb_required);
        let mut paths = Vec::new();

        for (oracle_index, path) in res.path {
            cur_oracle_infos.push(oracle_infos[oracle_index].clone());
            paths.push(path);
        }

        let adaptor_point = get_adaptor_point_from_paths(&secp, &cur_oracle_infos, &paths).unwrap();

        let adaptor_pair_offer = adaptor_pairs_offer[res.value.adaptor_index];
        let adaptor_pair_accept = adaptor_pairs_accept[res.value.adaptor_index];
        let cet = &dlc_txs.cets[res.value.cet_index];
        assert!(dlc::verify_cet_adaptor_sig_from_point(
            &secp,
            &adaptor_pair_offer.0,
            &adaptor_pair_offer.1,
            cet,
            &adaptor_point,
            &offer_params.params.fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
        )
        .is_ok());
        assert!(dlc::verify_cet_adaptor_sig_from_point(
            &secp,
            &adaptor_pair_accept.0,
            &adaptor_pair_accept.1,
            cet,
            &adaptor_point,
            &accept_params.params.fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
        )
        .is_ok());
    }

    let max_value = base.pow(nb_digits as u32);
    let outcome = (rng.next_u32() % (max_value as u32)) as usize;
    let nb_active_oracles = if nb_required == nb_oracles {
        nb_required
    } else {
        (rng.next_u32() % ((nb_oracles - nb_required) as u32) + (nb_required as u32)) as usize
    };
    let mut oracle_indexes: Vec<usize> = (0..nb_oracles).collect();
    oracle_indexes.shuffle(&mut rng);
    oracle_indexes = oracle_indexes.into_iter().take(nb_active_oracles).collect();
    oracle_indexes.sort();

    let decomposed_outcome = decompose_value(outcome, base, nb_digits);
    let mut oracle_signatures: Vec<(usize, Vec<SchnorrSignature>)> = vec![(
        oracle_indexes[0],
        decomposed_outcome
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let msg = Message::from_hashed_data::<sha256::Hash>(x.to_string().as_bytes());
                secp.schnorrsig_sign_with_nonce(
                    &msg,
                    &oracle_priv_infos[oracle_indexes[0]].priv_keypair,
                    &oracle_priv_infos[oracle_indexes[0]].priv_nonces[i],
                )
            })
            .collect(),
    )];
    let mut paths = vec![(oracle_indexes[0], decomposed_outcome)];

    for index in oracle_indexes.iter().skip(1) {
        let mut delta = ((rng.next_u32() as usize) % base.pow(min_support_exp as u32)) as i32;
        delta = if rng.next_u32() % 2 == 1 {
            -delta
        } else {
            delta
        };

        let cur_outcome: usize = {
            let tmp_outcome = (outcome as i32) + delta;
            if tmp_outcome < 0 {
                0
            } else if tmp_outcome > (max_value as i32) {
                max_value as usize
            } else {
                tmp_outcome as usize
            }
        };

        let decomposed_value = decompose_value(cur_outcome, base, nb_digits);
        oracle_signatures.push((
            *index,
            decomposed_value
                .iter()
                .enumerate()
                .map(|(i, x)| {
                    let msg = Message::from_hashed_data::<sha256::Hash>(x.to_string().as_bytes());
                    secp.schnorrsig_sign_with_nonce(
                        &msg,
                        &oracle_priv_infos[*index].priv_keypair,
                        &oracle_priv_infos[*index].priv_nonces[i],
                    )
                })
                .collect(),
        ));
        paths.push((*index, decomposed_value));
    }

    let outcome_info = multi_trie.look_up(&paths).unwrap();
    let outcome_range_info = outcome_info.value;
    let outcome_path = outcome_info.path;

    let final_oracle_signatures = oracle_signatures
        .into_iter()
        .filter_map(|(index, mut sigs)| {
            if let Some((_, path)) = outcome_path.iter().find(|(i, _)| *i == index) {
                sigs.drain(path.len()..);
                return Some(sigs);
            }
            None
        })
        .collect();

    let mut test_params = TestParams {
        secp,
        offer_adaptor_pair: adaptor_pairs_offer[outcome_range_info.adaptor_index],
        offer_params,
        accept_params,
        dlc_txs,
        oracle_signatures: final_oracle_signatures,
        funding_script_pubkey,
        fund_output_value,
        cet_index: outcome_range_info.cet_index,
        sink_rpc,
    };

    integration_tests_common(&mut test_params, TestCase::Decomposition);
}

fn integration_tests_basic_setup() -> TestParams<secp256k1::All> {
    let nb_oracles = 3;
    let nb_digits = 20;
    let nb_outcomes = 2;
    let outcome_index = 0;
    let messages = get_base_test_msgs(nb_oracles, nb_outcomes, nb_digits);
    let outcomes = outcomes();
    let secp = secp256k1::Secp256k1::new();
    let rng = &mut thread_rng();
    let oracle_priv_infos = get_oracle_infos(&secp, rng, nb_oracles, nb_digits);
    let oracle_signatures = get_oracle_sigs(&secp, &oracle_priv_infos, &messages, outcome_index);
    let oracle_infos = oracle_priv_infos.into_iter().map(|x| x.info).collect();
    let (offer_rpc, accept_rpc, sink_rpc) = init();

    let offer_params = generate_dlc_parameters(offer_rpc, &secp, PARTY_COLLATERAL);
    let accept_params = generate_dlc_parameters(accept_rpc, &secp, PARTY_COLLATERAL);

    let dlc_txs = dlc::create_dlc_transactions(
        &offer_params.params,
        &accept_params.params,
        &outcomes,
        REFUND_LOCK_TIME,
        2,
        FUND_LOCK_TIME,
        CET_LOCK_TIME,
        rng.next_u64(),
    )
    .expect("Error creating dlc transactions.");

    let funding_script_pubkey = dlc::make_funding_redeemscript(
        &offer_params.params.fund_pubkey,
        &accept_params.params.fund_pubkey,
    );
    let fund_output_value = dlc::util::get_output_for_script_pubkey(
        &dlc_txs.fund,
        &funding_script_pubkey.to_v0_p2wsh(),
    )
    .expect("Could not find fund output")
    .1
    .value;
    let (offer_adaptor_pair, _) = {
        let offer_cets_sigs = dlc::create_cet_adaptor_sigs_from_oracle_info(
            &secp,
            &dlc_txs.cets,
            &oracle_infos,
            &offer_params.fund_priv_key,
            &funding_script_pubkey,
            fund_output_value,
            &messages,
        )
        .unwrap();
        let accept_cets_sigs = dlc::create_cet_adaptor_sigs_from_oracle_info(
            &secp,
            &dlc_txs.cets,
            &oracle_infos,
            &accept_params.fund_priv_key,
            &funding_script_pubkey,
            fund_output_value,
            &messages,
        )
        .unwrap();

        assert!(offer_cets_sigs.iter().enumerate().all(|(i, z)| {
            dlc::verify_cet_adaptor_sig_from_oracle_info(
                &secp,
                &z.0,
                &z.1,
                &dlc_txs.cets[i],
                &oracle_infos,
                &offer_params.params.fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
                &messages[i],
            )
            .is_ok()
        }));

        assert!(accept_cets_sigs.iter().enumerate().all(|(i, z)| {
            dlc::verify_cet_adaptor_sig_from_oracle_info(
                &secp,
                &z.0,
                &z.1,
                &dlc_txs.cets[i],
                &oracle_infos,
                &accept_params.params.fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
                &messages[i],
            )
            .is_ok()
        }));
        (
            offer_cets_sigs[outcome_index],
            accept_cets_sigs[outcome_index],
        )
    };

    TestParams {
        secp,
        offer_adaptor_pair,
        offer_params,
        accept_params,
        oracle_signatures,
        dlc_txs,
        funding_script_pubkey,
        fund_output_value,
        cet_index: outcome_index,
        sink_rpc,
    }
}

fn integration_tests_common<C: Signing>(test_params: &mut TestParams<C>, test_case: TestCase) {
    let mut dlc_txs = test_params.dlc_txs.clone();
    let generate_blocks = |nb_blocks: u64| {
        let address = test_params.sink_rpc.get_new_address(None, None).unwrap();
        test_params
            .sink_rpc
            .generate_to_address(nb_blocks, &address)
            .unwrap();
    };
    assert!(dlc::sign_cet(
        &test_params.secp,
        &mut dlc_txs.cets[test_params.cet_index],
        &test_params.offer_adaptor_pair.0,
        &test_params.oracle_signatures,
        &test_params.accept_params.fund_priv_key,
        &test_params.offer_params.params.fund_pubkey,
        &test_params.funding_script_pubkey,
        test_params.fund_output_value,
    )
    .is_ok());

    let mut input_serial_ids: Vec<u64> = test_params
        .offer_params
        .params
        .inputs
        .iter()
        .map(|x| x.serial_id)
        .chain(
            test_params
                .accept_params
                .params
                .inputs
                .iter()
                .map(|x| x.serial_id),
        )
        .collect();

    input_serial_ids.sort();

    dlc::util::sign_p2wpkh_input(
        &test_params.secp,
        &test_params.offer_params.input_priv_key,
        &mut dlc_txs.fund,
        input_serial_ids
            .iter()
            .position(|&x| x == test_params.offer_params.params.inputs[0].serial_id)
            .unwrap(),
        SigHashType::All,
        test_params.offer_params.params.input_amount,
    );

    dlc::util::sign_p2wpkh_input(
        &test_params.secp,
        &test_params.accept_params.input_priv_key,
        &mut dlc_txs.fund,
        input_serial_ids
            .iter()
            .position(|&x| x == test_params.accept_params.params.inputs[0].serial_id)
            .unwrap(),
        SigHashType::All,
        test_params.accept_params.params.input_amount,
    );

    let go_to_height = |height: u64| {
        let block_count = test_params.offer_params.rpc.get_block_count().unwrap();

        generate_blocks(height - block_count);
    };

    // Should not be able to broadcast before fund lock time
    assert!(test_params
        .offer_params
        .rpc
        .send_raw_transaction(&dlc_txs.fund)
        .is_err());

    go_to_height(FUND_LOCK_TIME as u64);

    test_params
        .offer_params
        .rpc
        .send_raw_transaction(&dlc_txs.fund)
        .expect("Could not send fund transaction.");

    generate_blocks(1);

    if test_case == TestCase::Refund {
        let offer_refund_sig = dlc::util::get_raw_sig_for_tx_input(
            &test_params.secp,
            &dlc_txs.refund,
            0,
            &test_params.funding_script_pubkey,
            test_params.fund_output_value,
            &test_params.offer_params.fund_priv_key,
        );

        dlc::util::sign_multi_sig_input(
            &test_params.secp,
            &mut dlc_txs.refund,
            &offer_refund_sig,
            &PublicKey::from_secret_key(&test_params.secp, &test_params.offer_params.fund_priv_key),
            &test_params.accept_params.fund_priv_key,
            &test_params.funding_script_pubkey,
            test_params.fund_output_value,
            0,
        );

        // Should not be able to broadcast before refund lock time
        assert!(test_params
            .offer_params
            .rpc
            .send_raw_transaction(&dlc_txs.refund)
            .is_err());

        go_to_height(REFUND_LOCK_TIME as u64);

        test_params
            .offer_params
            .rpc
            .send_raw_transaction(&dlc_txs.refund)
            .expect("Could not send refund transaction.");
    } else {
        // Should not be able to broadcast before cet lock time
        assert!(test_params
            .offer_params
            .rpc
            .send_raw_transaction(&dlc_txs.cets[test_params.cet_index])
            .is_err());

        go_to_height(CET_LOCK_TIME as u64);

        test_params
            .offer_params
            .rpc
            .send_raw_transaction(&dlc_txs.cets[test_params.cet_index])
            .expect("Could not send CET.");
    }
}
