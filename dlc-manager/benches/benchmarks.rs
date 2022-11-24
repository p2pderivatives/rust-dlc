use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use bitcoin::Script;
use bitcoin::WPubkeyHash;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dlc::create_dlc_transactions;
use dlc::DlcTransactions;
use dlc::PartyParams;
use dlc::Payout;
use dlc::TxInputInfo;
use dlc_manager::contract::contract_info::ContractInfo;
use dlc_manager::contract::numerical_descriptor::DifferenceParams;
use dlc_manager::contract::numerical_descriptor::NumericalDescriptor;
use dlc_manager::contract::ContractDescriptor;
use dlc_manager::payout_curve::PayoutFunction;
use dlc_manager::payout_curve::PayoutFunctionPiece;
use dlc_manager::payout_curve::PayoutPoint;
use dlc_manager::payout_curve::PolynomialPayoutCurvePiece;
use dlc_manager::payout_curve::RoundingInterval;
use dlc_manager::payout_curve::RoundingIntervals;
use dlc_messages::oracle_msgs::DigitDecompositionEventDescriptor;
use dlc_messages::oracle_msgs::EventDescriptor;
use dlc_messages::oracle_msgs::OracleAnnouncement;
use dlc_messages::oracle_msgs::OracleEvent;
use secp256k1_zkp::{
    global::SECP256K1, rand::thread_rng, schnorr::Signature, KeyPair, SecretKey, XOnlyPublicKey,
};
use std::str::FromStr;

/// The base in which the outcome values are decomposed.
const BASE: u32 = 2;
/// The point after which payout is constant.
const FLOOR: u64 = 0;
const CAP: u64 = 1023;
/// The rounding modulus to use (1 means no rounding is done).
const ROUNDING_MOD: u64 = 1;
/// The number of digits used to represent outcome values.
const NB_DIGITS: usize = 10;
/// The minimum difference between oracle supported for the contract (as a power of 2).
const MIN_SUPPORT_EXP: usize = 7;
/// The maximum difference between oracle supported for the contract (as a power of 2).
const MAX_ERROR_EXP: usize = 8;
/// Whether to allow difference in oracle's attestation values.
const USE_DIFF_PARAMS: bool = false;
/// The number of oracles used for the contract.
const NB_ORACLES: usize = 3;
/// The number of oracles required to be in agreement to close the contract.
const THRESHOLD: usize = 2;
/// The ID of the event.
const EVENT_ID: &str = "Test";
/// The total collateral value locked in the contract.
const TOTAL_COLLATERAL: u64 = 200000000;

fn max_value() -> u32 {
    BASE.pow(NB_DIGITS as u32) - 1
}

fn create_contract_descriptor() -> ContractDescriptor {
    let difference_params = if USE_DIFF_PARAMS {
        Some(DifferenceParams {
            max_error_exp: MAX_ERROR_EXP,
            min_support_exp: MIN_SUPPORT_EXP,
            maximize_coverage: false,
        })
    } else {
        None
    };
    ContractDescriptor::Numerical(NumericalDescriptor {
        payout_function: PayoutFunction::new(vec![
            PayoutFunctionPiece::PolynomialPayoutCurvePiece(
                PolynomialPayoutCurvePiece::new(vec![
                    PayoutPoint {
                        event_outcome: 0,
                        outcome_payout: 0,
                        extra_precision: 0,
                    },
                    PayoutPoint {
                        event_outcome: CAP,
                        outcome_payout: TOTAL_COLLATERAL,
                        extra_precision: 0,
                    },
                ])
                .unwrap(),
            ),
        ])
        .unwrap(),
        rounding_intervals: RoundingIntervals {
            intervals: vec![RoundingInterval {
                begin_interval: 0,
                rounding_mod: ROUNDING_MOD,
            }],
        },
        oracle_numeric_infos: dlc_trie::OracleNumericInfo {
            base: BASE as usize,
            nb_digits: std::iter::repeat(NB_DIGITS)
                .take(NB_ORACLES)
                .collect::<Vec<_>>(),
        },
        difference_params,
    })
}

fn get_schnorr_pubkey() -> XOnlyPublicKey {
    XOnlyPublicKey::from_keypair(&KeyPair::new(SECP256K1, &mut thread_rng())).0
}

fn get_pubkey() -> secp256k1_zkp::PublicKey {
    secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &SecretKey::new(&mut thread_rng()))
}

fn get_p2wpkh_script_pubkey() -> Script {
    Script::new_v0_p2wpkh(&WPubkeyHash::hash(&get_pubkey().serialize()))
}

fn create_oracle_announcements() -> Vec<OracleAnnouncement> {
    (0..NB_ORACLES).map(|_| {
            OracleAnnouncement {
            announcement_signature: Signature::from_str("859833d34b9cbd7c0a898693a289af434c74ad1d65e15c67d1b1d3bf74d9ee85cbd5258da5e91815da9989185c8bc9b026ce6f6598c1b2fb127c1bb1a6bef74a").unwrap(),
            oracle_public_key: get_schnorr_pubkey(),
            oracle_event: OracleEvent{
                event_descriptor: EventDescriptor::DigitDecompositionEvent(DigitDecompositionEventDescriptor {
                base: BASE as u16,
                is_signed: false,
                unit: "sats/sec".to_owned(),
                precision: 0,
                nb_digits: NB_DIGITS as u16,
            }),
                oracle_nonces: (0..NB_DIGITS).map(|_| get_schnorr_pubkey()).collect(),
                event_maturity_epoch: 1234567,
                event_id: EVENT_ID.to_string(),
        }}}).collect()
}

fn create_contract_info() -> ContractInfo {
    let contract_descriptor = create_contract_descriptor();
    let oracle_announcements = create_oracle_announcements();
    ContractInfo {
        contract_descriptor,
        oracle_announcements,
        threshold: THRESHOLD,
    }
}

fn create_txinputinfo_vec() -> Vec<TxInputInfo> {
    let tx_input_info = TxInputInfo {
        outpoint: OutPoint::default(),
        redeem_script: Script::new(),
        max_witness_len: 108,
        serial_id: 2,
    };
    vec![tx_input_info]
}

fn create_transactions(payouts: &[Payout]) -> DlcTransactions {
    let offer_params = PartyParams {
        fund_pubkey: secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &offer_seckey()),
        change_script_pubkey: get_p2wpkh_script_pubkey(),
        change_serial_id: 4,
        payout_script_pubkey: get_p2wpkh_script_pubkey(),
        payout_serial_id: 1,
        inputs: create_txinputinfo_vec(),
        input_amount: 300000000,
        collateral: 100000000,
    };

    let accept_params = PartyParams {
        fund_pubkey: secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &accept_seckey()),
        change_script_pubkey: get_p2wpkh_script_pubkey(),
        change_serial_id: 4,
        payout_script_pubkey: get_p2wpkh_script_pubkey(),
        payout_serial_id: 1,
        inputs: create_txinputinfo_vec(),
        input_amount: 300000000,
        collateral: 100000000,
    };
    create_dlc_transactions(&offer_params, &accept_params, payouts, 1000, 2, 0, 1000, 3).unwrap()
}

fn accept_seckey() -> SecretKey {
    "c0296e3059b34c9707f05dc54ec008de90c0ce52841ff54b98e51487de031e6d"
        .parse()
        .unwrap()
}

fn offer_seckey() -> SecretKey {
    "c3b1634c6a13019f372722db0ec0435df11fb2dd6b0b5c647503ef6b5e4656ec"
        .parse()
        .unwrap()
}

/// Benchmark to measure the adaptor signature creation time.
pub fn sign_bench(c: &mut Criterion) {
    let contract_info = create_contract_info();
    let dlc_transactions = create_transactions(&contract_info.get_payouts(200000000).unwrap());
    let fund_output_value = dlc_transactions.get_fund_output().value;

    let seckey = accept_seckey();
    c.bench_function("sign", |b| {
        b.iter(|| {
            black_box(
                contract_info
                    .get_adaptor_info(
                        SECP256K1,
                        TOTAL_COLLATERAL,
                        &seckey,
                        &dlc_transactions.funding_script_pubkey,
                        fund_output_value,
                        &dlc_transactions.cets,
                        0,
                    )
                    .unwrap(),
            )
        });
    });
}

/// Benchmark to measure the adaptor signature verification time.
pub fn verify_bench(c: &mut Criterion) {
    let contract_info = create_contract_info();
    let dlc_transactions = create_transactions(&contract_info.get_payouts(200000000).unwrap());
    let fund_output_value = dlc_transactions.get_fund_output().value;

    let seckey = accept_seckey();
    let pubkey = secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &seckey);
    let adaptor_info = contract_info
        .get_adaptor_info(
            SECP256K1,
            TOTAL_COLLATERAL,
            &seckey,
            &dlc_transactions.funding_script_pubkey,
            fund_output_value,
            &dlc_transactions.cets,
            0,
        )
        .unwrap();
    let adaptor_signatures = &adaptor_info.1;
    c.bench_function("verify", |b| {
        b.iter(|| {
            black_box(
                contract_info
                    .verify_adaptor_info(
                        SECP256K1,
                        &pubkey,
                        &dlc_transactions.funding_script_pubkey,
                        fund_output_value,
                        &dlc_transactions.cets,
                        adaptor_signatures,
                        0,
                        &adaptor_info.0,
                    )
                    .unwrap(),
            );
        });
    });
}

criterion_group! {
    name = sign_verify_bench;
    config = Criterion::default();
    targets = sign_bench, verify_bench
}
criterion_main!(sign_verify_bench);
