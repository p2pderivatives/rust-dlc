extern crate bitcoin;
extern crate bitcoincore_rpc;
extern crate bitcoincore_rpc_json;
extern crate dlc;
extern crate secp256k1;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc_json::AddressType;

use bitcoin::{OutPoint, Script, SigHashType};
use dlc::{OracleInfo, PartyParams, Payout, TxInputInfo};
use secp256k1::{
    rand::{thread_rng, Rng},
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

fn get_oracle_infos<C: Signing, R: Rng + ?Sized>(
    secp: &Secp256k1<C>,
    rng: &mut R,
) -> (Vec<OracleInfo>, Vec<Vec<SchnorrSignature>>) {
    const NB_ORACLES: usize = 3;
    const NB_OUTCOMES: usize = 2;
    const NB_DIGITS: usize = 20;
    let mut oracle_infos: Vec<OracleInfo> = Vec::with_capacity(NB_ORACLES);
    let mut oracle_sks: Vec<KeyPair> = Vec::with_capacity(NB_ORACLES);
    let mut oracle_sk_nonce: Vec<Vec<[u8; 32]>> = Vec::with_capacity(NB_ORACLES);
    let mut oracle_sigs: Vec<Vec<SchnorrSignature>> = Vec::with_capacity(NB_ORACLES);
    let mut messages: Vec<Vec<Vec<_>>> =
        (0..NB_ORACLES)
            .map(|x| {
                (0..NB_OUTCOMES)
                    .map(|y| {
                        (0..NB_DIGITS).map(|z|
                Message::from_hashed_data::<secp256k1::bitcoin_hashes::sha256::Hash>(&[
                    ((y + x + z) as u8).try_into().unwrap()
                ])).collect()
                    })
                    .collect()
            })
            .collect();

    for i in 0..NB_ORACLES {
        let (oracle_kp, oracle_pubkey) = secp.generate_schnorrsig_keypair(rng);
        let mut nonces: Vec<SchnorrPublicKey> = Vec::with_capacity(NB_DIGITS);
        let mut sk_nonces: Vec<[u8; 32]> = Vec::with_capacity(NB_DIGITS);
        oracle_sigs.push(Vec::with_capacity(NB_DIGITS));
        for j in 0..NB_DIGITS {
            let mut sk_nonce = [0u8; 32];
            rng.fill_bytes(&mut sk_nonce);
            let oracle_r_kp =
                secp256k1::schnorrsig::KeyPair::from_seckey_slice(&secp, &sk_nonce).unwrap();
            let nonce = SchnorrPublicKey::from_keypair(&secp, &oracle_r_kp);
            let sig = secp.schnorrsig_sign_with_nonce(&messages[0][0][j], &oracle_kp, &sk_nonce);
            oracle_sigs[i].push(sig);
            nonces.push(nonce);
            sk_nonces.push(sk_nonce);
        }
        oracle_infos.push(OracleInfo {
            public_key: oracle_pubkey,
            nonces,
            msgs: messages.remove(0),
        });
        oracle_sk_nonce.push(sk_nonces);
        oracle_sks.push(oracle_kp);
    }
    (oracle_infos, oracle_sigs)
}

fn init() -> (Client, Client, Box<dyn Fn(u64) -> ()>) {
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

    (
        offer_rpc,
        accept_rpc,
        Box::new(move |nb_blocks| {
            sink_rpc
                .generate_to_address(nb_blocks, &sink_address)
                .unwrap();
        }),
    )
}

fn generate_dlc_parameters<'a, C: secp256k1::Signing>(
    rpc: &Client,
    secp: &secp256k1::Secp256k1<C>,
    collateral: u64,
) -> (PartyParams, SecretKey, SecretKey) {
    let change_address = rpc
        .get_new_address(None, Some(AddressType::Bech32))
        .unwrap();
    let final_address = rpc
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
    let input_sk = {
        let address = utxo.address.clone().unwrap();
        let privkey = rpc.dump_private_key(&address).unwrap();
        privkey.key
    };
    (
        PartyParams {
            fund_pubkey: PublicKey::from_secret_key(secp, &fund_priv_key),
            change_script_pubkey: change_address.script_pubkey(),
            final_script_pubkey: final_address.script_pubkey(),
            inputs: vec![TxInputInfo {
                outpoint: OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                max_witness_len: dlc::P2WPKH_WITNESS_SIZE,
                redeem_script: Script::new(),
            }],
            input_amount: utxo.amount.as_sat(),
            collateral,
        },
        fund_priv_key,
        input_sk,
    )
}

#[derive(PartialEq)]
enum TestCase {
    Close,
    Refund,
}

#[test]
#[ignore]
fn integration_tests_close() {
    integration_tests_common(TestCase::Close);
}

#[test]
#[ignore]
fn integration_tests_refund() {
    integration_tests_common(TestCase::Refund);
}

fn integration_tests_common(test_case: TestCase) {
    let secp = secp256k1::Secp256k1::new();
    let rng = &mut thread_rng();
    let (oracle_infos, oracle_signatures) = get_oracle_infos(&secp, rng);
    let (offer_rpc, accept_rpc, generate_blocks) = init();

    let (offer_params, offer_fund_sk, offer_input_sk) =
        generate_dlc_parameters(&offer_rpc, &secp, PARTY_COLLATERAL);
    let (accept_params, accept_fund_sk, accept_input_sk) =
        generate_dlc_parameters(&accept_rpc, &secp, PARTY_COLLATERAL);

    let mut dlc_txs = dlc::create_dlc_transactions(
        &offer_params,
        &accept_params,
        &outcomes(),
        REFUND_LOCK_TIME,
        2,
        FUND_LOCK_TIME,
        CET_LOCK_TIME,
    )
    .expect("Error creating dlc transactions.");

    let funding_script_pubkey =
        dlc::make_funding_redeemscript(&offer_params.fund_pubkey, &accept_params.fund_pubkey);
    let fund_output_value = dlc_txs.fund.output[0].value;
    let remote_sig = {
        let local_cets_sigs = dlc::create_cet_adaptor_sigs_from_oracle_info(
            &secp,
            &dlc_txs.cets,
            &oracle_infos,
            &offer_fund_sk,
            &funding_script_pubkey,
            fund_output_value,
        )
        .unwrap();
        let remote_cets_sigs = dlc::create_cet_adaptor_sigs_from_oracle_info(
            &secp,
            &dlc_txs.cets,
            &oracle_infos,
            &accept_fund_sk,
            &funding_script_pubkey,
            fund_output_value,
        )
        .unwrap();

        assert!(local_cets_sigs.iter().enumerate().all(|(i, z)| {
            dlc::verify_cet_adaptor_sig_from_oracle_info(
                &secp,
                &z.0,
                &z.1,
                &dlc_txs.cets[i],
                &oracle_infos,
                &offer_params.fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
                i,
            )
            .is_ok()
        }));

        assert!(remote_cets_sigs.iter().enumerate().all(|(i, z)| {
            dlc::verify_cet_adaptor_sig_from_oracle_info(
                &secp,
                &z.0,
                &z.1,
                &dlc_txs.cets[i],
                &oracle_infos,
                &accept_params.fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
                i,
            )
            .is_ok()
        }));
        remote_cets_sigs[0]
    };

    assert!(dlc::sign_cet(
        &secp,
        &mut dlc_txs.cets[0],
        &remote_sig.0,
        &oracle_signatures,
        &offer_fund_sk,
        &PublicKey::from_secret_key(&secp, &accept_fund_sk),
        &funding_script_pubkey,
        fund_output_value,
    )
    .is_ok());

    dlc::util::sign_p2wpkh_input(
        &secp,
        &offer_input_sk,
        &mut dlc_txs.fund,
        0,
        SigHashType::All,
        offer_params.input_amount,
    );

    dlc::util::sign_p2wpkh_input(
        &secp,
        &accept_input_sk,
        &mut dlc_txs.fund,
        1,
        SigHashType::All,
        accept_params.input_amount,
    );

    let go_to_height = |height: u64| {
        let block_count = offer_rpc.get_block_count().unwrap();

        generate_blocks(height - block_count);
    };

    // Should not be able to broadcast before fund lock time
    assert!(offer_rpc.send_raw_transaction(&dlc_txs.fund).is_err());

    go_to_height(FUND_LOCK_TIME as u64);

    assert!(offer_rpc.send_raw_transaction(&dlc_txs.fund).is_ok());

    generate_blocks(1);

    if test_case == TestCase::Close {
        // Should not be able to broadcast before cet lock time
        assert!(offer_rpc.send_raw_transaction(&dlc_txs.cets[0]).is_err());

        go_to_height(CET_LOCK_TIME as u64);

        assert!(offer_rpc.send_raw_transaction(&dlc_txs.cets[0]).is_ok());
    } else {
        let offer_refund_sig = dlc::util::get_raw_sig_for_tx_input(
            &secp,
            &dlc_txs.refund,
            0,
            &funding_script_pubkey,
            dlc_txs.fund.output[0].value,
            &offer_fund_sk,
        );

        dlc::util::sign_multi_sig_input(
            &secp,
            &mut dlc_txs.refund,
            &offer_refund_sig,
            &PublicKey::from_secret_key(&secp, &offer_fund_sk),
            &accept_fund_sk,
            &funding_script_pubkey,
            dlc_txs.fund.output[0].value,
            0,
        );

        // Should not be able to broadcast before refund lock time
        assert!(offer_rpc.send_raw_transaction(&dlc_txs.refund).is_err());

        go_to_height(REFUND_LOCK_TIME as u64);

        assert!(offer_rpc.send_raw_transaction(&dlc_txs.refund).is_ok());
    }
}
