extern crate bitcoin_rpc_provider;
extern crate bitcoin_test_utils;
extern crate bitcoincore_rpc;
extern crate bitcoincore_rpc_json;
extern crate dlc_manager;

use bitcoin_rpc_provider::BitcoinCoreProvider;
use bitcoin_test_utils::rpc_helpers::init_clients;
use bitcoincore_rpc::RpcApi;
use dlc::{EnumerationPayout, Payout};
use dlc_manager::contract::{
    contract_input::{ContractInput, ContractInputInfo, OracleInput},
    enum_descriptor::EnumDescriptor,
    numerical_descriptor::{DifferenceParams, NumericalDescriptor},
    Contract, ContractDescriptor,
};
use dlc_manager::manager::Manager;
use dlc_manager::payout_curve::{
    PayoutFunction, PayoutFunctionPiece, PayoutPoint, PolynomialPayoutCurvePiece, RoundingInterval,
    RoundingIntervals,
};
use dlc_manager::{Oracle, Storage};
use dlc_messages::oracle_msgs::{
    DigitDecompositionEventDescriptor, EnumEventDescriptor, EventDescriptor,
};
use dlc_messages::{AcceptDlc, OfferDlc, SignDlc};
use dlc_messages::{CetAdaptorSignatures, Message};
use dlc_trie::{digit_decomposition::decompose_value, OracleNumericInfo};
use lightning::ln::wire::Type;
use lightning::util::ser::Writeable;
use mocks::mock_oracle_provider::MockOracle;
use secp256k1_zkp::rand::{seq::SliceRandom, thread_rng, RngCore};
use secp256k1_zkp::{EcdsaAdaptorSignature, Signature};
use serde_json::{from_str, to_writer_pretty};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::channel,
    Arc, Mutex,
};
use std::thread;

#[derive(serde::Serialize, serde::Deserialize)]
struct TestVectorPart<T> {
    message: T,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "dlc_messages::serde_utils::serialize_hex",
            deserialize_with = "dlc_messages::serde_utils::deserialize_hex_string"
        )
    )]
    serialized: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TestVector {
    offer_message: TestVectorPart<OfferDlc>,
    accept_message: TestVectorPart<AcceptDlc>,
    sign_message: TestVectorPart<SignDlc>,
}

fn write_message<T: Writeable + serde::Serialize + Type>(msg_name: &str, s: T) {
    if std::env::var("GENERATE_TEST_VECTOR").is_ok() {
        let mut buf = Vec::new();
        s.type_id().write(&mut buf).unwrap();
        s.write(&mut buf).unwrap();
        let t = TestVectorPart {
            message: s,
            serialized: buf,
        };
        to_writer_pretty(
            &std::fs::File::create(format!("{}.json", msg_name)).unwrap(),
            &t,
        )
        .unwrap();
    }
}

fn create_test_vector() {
    if std::env::var("GENERATE_TEST_VECTOR").is_ok() {
        let test_vector = TestVector {
            offer_message: from_str(&std::fs::read_to_string("offer_message.json").unwrap())
                .unwrap(),
            accept_message: from_str(&std::fs::read_to_string("accept_message.json").unwrap())
                .unwrap(),
            sign_message: from_str(&std::fs::read_to_string("sign_message.json").unwrap()).unwrap(),
        };
        let file_name = std::env::var("TEST_VECTOR_OUTPUT_NAME")
            .unwrap_or_else(|_| "test_vector.json".to_string());
        to_writer_pretty(std::fs::File::create(file_name).unwrap(), &test_vector).unwrap();
    }
}

macro_rules! assert_contract_state {
    ($d:expr, $id:expr, $p:ident) => {
        let res = $d
            .lock()
            .unwrap()
            .get_store()
            .get_contract(&$id)
            .expect("Could not retrieve contract");
        if let Some(Contract::$p(_)) = res {
        } else {
            panic!("Unexpected contract state {:?}", res);
        }
    };
}

macro_rules! periodic_check {
    ($d:expr, $id:expr, $p:ident) => {
        $d.lock()
            .unwrap()
            .periodic_check()
            .expect("Periodic check error");

        assert_contract_state!($d, $id, $p);
    };
}

macro_rules! receive_loop {
    ($receive:expr, $manager:expr, $send:expr, $expect_err:expr, $sync_send:expr, $rcv_callback: expr) => {
        thread::spawn(move || loop {
            match $receive.recv() {
                Ok(Some(msg)) => match $manager.lock().unwrap().on_dlc_message(
                    &msg,
                    "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
                        .parse()
                        .unwrap(),
                ) {
                    Ok(opt) => {
                        if $expect_err.load(Ordering::Relaxed) != false {
                            panic!("Expected error not raised");
                        }
                        match opt {
                            Some(msg) => {
                                let msg = $rcv_callback(msg);
                                match &msg {
                                    Message::Sign(s) => {
                                        write_message("sign_message", s.clone());
                                    }
                                    _ => {}
                                }
                                (&$send).send(Some(msg)).expect("Error sending");
                            }
                            None => {}
                        }
                    }
                    Err(e) => {
                        if $expect_err.load(Ordering::Relaxed) != true {
                            panic!("Unexpected error {}", e);
                        }
                    }
                },
                Ok(None) | Err(_) => return,
            };
            $sync_send.send(()).expect("Error syncing");
        })
    };
}

const NB_DIGITS: u32 = 10;
const MIN_SUPPORT_EXP: usize = 1;
const MAX_ERROR_EXP: usize = 2;
const BASE: u32 = 2;
const EVENT_MATURITY: u32 = 1623133104;
const EVENT_ID: &str = "Test";
const COLLATERAL: u64 = 100000000;
const MID_POINT: u64 = 5;
const ROUNDING_MOD: u64 = 1;

#[derive(Eq, PartialEq, Clone)]
enum TestPath {
    Close,
    Refund,
    BadAcceptCetSignature,
    BadAcceptRefundSignature,
    BadSignCetSignature,
    BadSignRefundSignature,
}

fn enum_outcomes() -> Vec<String> {
    vec![
        "a".to_owned(),
        "b".to_owned(),
        "c".to_owned(),
        "d".to_owned(),
    ]
}

fn max_value() -> u32 {
    BASE.pow(NB_DIGITS as u32) - 1
}

fn max_value_from_digits(nb_digits: usize) -> u32 {
    BASE.pow(nb_digits as u32) - 1
}

fn select_active_oracles(nb_oracles: usize, threshold: usize) -> Vec<usize> {
    let nb_active_oracles = if threshold == nb_oracles {
        threshold
    } else {
        (thread_rng().next_u32() % ((nb_oracles - threshold) as u32) + (threshold as u32)) as usize
    };
    let mut oracle_indexes: Vec<usize> = (0..nb_oracles).collect();
    oracle_indexes.shuffle(&mut thread_rng());
    oracle_indexes = oracle_indexes.into_iter().take(nb_active_oracles).collect();
    oracle_indexes.sort_unstable();
    oracle_indexes
}

#[derive(Debug)]
struct TestParams {
    oracles: Vec<MockOracle>,
    contract_input: ContractInput,
}

fn get_difference_params() -> DifferenceParams {
    DifferenceParams {
        max_error_exp: MAX_ERROR_EXP,
        min_support_exp: MIN_SUPPORT_EXP,
        maximize_coverage: false,
    }
}

fn get_enum_contract_descriptor() -> ContractDescriptor {
    let outcome_payouts: Vec<_> = enum_outcomes()
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let payout = if i % 2 == 0 {
                Payout {
                    offer: 2 * COLLATERAL,
                    accept: 0,
                }
            } else {
                Payout {
                    offer: 0,
                    accept: 2 * COLLATERAL,
                }
            };
            EnumerationPayout {
                outcome: x.to_owned(),
                payout,
            }
        })
        .collect();
    ContractDescriptor::Enum(EnumDescriptor { outcome_payouts })
}

fn get_enum_oracle() -> MockOracle {
    let mut oracle = MockOracle::new();
    let event = EnumEventDescriptor {
        outcomes: enum_outcomes(),
    };

    oracle.add_event(EVENT_ID, &EventDescriptor::EnumEvent(event), EVENT_MATURITY);

    oracle
}

fn get_enum_oracles(nb_oracles: usize, threshold: usize) -> Vec<MockOracle> {
    let mut oracles: Vec<_> = (0..nb_oracles).map(|_| get_enum_oracle()).collect();

    let active_oracles = select_active_oracles(nb_oracles, threshold);
    let outcomes = enum_outcomes();
    let outcome = outcomes[(thread_rng().next_u32() as usize) % outcomes.len()].clone();
    for index in active_oracles {
        oracles
            .get_mut(index)
            .unwrap()
            .add_attestation(EVENT_ID, &[outcome.clone()]);
    }

    oracles
}

fn get_enum_test_params(
    nb_oracles: usize,
    threshold: usize,
    oracles: Option<Vec<MockOracle>>,
) -> TestParams {
    let oracles = oracles.unwrap_or_else(|| get_enum_oracles(nb_oracles, threshold));
    let contract_descriptor = get_enum_contract_descriptor();
    let contract_info = ContractInputInfo {
        contract_descriptor,
        oracles: OracleInput {
            public_keys: oracles.iter().map(|x| x.get_public_key()).collect(),
            event_id: EVENT_ID.to_owned(),
            threshold: threshold as u16,
        },
    };

    let contract_input = ContractInput {
        offer_collateral: COLLATERAL,
        accept_collateral: COLLATERAL,
        maturity_time: EVENT_MATURITY,
        fee_rate: 2,
        contract_infos: vec![contract_info],
    };

    TestParams {
        oracles,
        contract_input,
    }
}

fn get_numerical_contract_descriptor(
    oracle_numeric_infos: OracleNumericInfo,
    difference_params: Option<DifferenceParams>,
) -> ContractDescriptor {
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
                        event_outcome: MID_POINT,
                        outcome_payout: 200000000,
                        extra_precision: 0,
                    },
                ])
                .unwrap(),
            ),
            PayoutFunctionPiece::PolynomialPayoutCurvePiece(
                PolynomialPayoutCurvePiece::new(vec![
                    PayoutPoint {
                        event_outcome: MID_POINT,
                        outcome_payout: 200000000,
                        extra_precision: 0,
                    },
                    PayoutPoint {
                        event_outcome: max_value_from_digits(
                            oracle_numeric_infos.get_min_nb_digits(),
                        ) as u64,
                        outcome_payout: 200000000,
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
        oracle_numeric_infos,
        difference_params,
    })
}

fn get_digit_decomposition_oracle(nb_digits: u16) -> MockOracle {
    let mut oracle = MockOracle::new();
    let event = DigitDecompositionEventDescriptor {
        base: BASE as u64,
        is_signed: false,
        unit: "sats/sec".to_owned(),
        precision: 0,
        nb_digits,
    };

    oracle.add_event(
        EVENT_ID,
        &EventDescriptor::DigitDecompositionEvent(event),
        EVENT_MATURITY,
    );
    oracle
}

fn get_digit_decomposition_oracles(
    oracle_numeric_infos: &OracleNumericInfo,
    threshold: usize,
    with_diff: bool,
    use_max_value: bool,
) -> Vec<MockOracle> {
    let mut oracles: Vec<_> = oracle_numeric_infos
        .nb_digits
        .iter()
        .map(|x| get_digit_decomposition_oracle(*x as u16))
        .collect();
    let outcome_value = if use_max_value {
        max_value_from_digits(oracle_numeric_infos.get_min_nb_digits()) as usize
    } else {
        (thread_rng().next_u32() % max_value()) as usize
    };
    let oracle_indexes = select_active_oracles(oracle_numeric_infos.nb_digits.len(), threshold);

    for (i, index) in oracle_indexes.iter().enumerate() {
        let cur_outcome: usize = if !use_max_value && (i == 0 || !with_diff) {
            outcome_value
        } else {
            if !use_max_value {
                let mut delta = (thread_rng().next_u32() % BASE.pow(MIN_SUPPORT_EXP as u32)) as i32;
                delta = if thread_rng().next_u32() % 2 == 1 {
                    -delta
                } else {
                    delta
                };

                let tmp_outcome = (outcome_value as i32) + delta;
                if tmp_outcome < 0 {
                    0
                } else if tmp_outcome
                    > (max_value_from_digits(oracle_numeric_infos.nb_digits[*index]) as i32)
                {
                    max_value() as usize
                } else {
                    tmp_outcome as usize
                }
            } else {
                let max_value =
                    max_value_from_digits(oracle_numeric_infos.nb_digits[*index]) as usize;
                if max_value == outcome_value {
                    outcome_value
                } else {
                    outcome_value
                        + 1
                        + (thread_rng().next_u32() as usize % (max_value - outcome_value))
                }
            }
        };

        let outcomes: Vec<_> = decompose_value(
            cur_outcome,
            BASE as usize,
            oracle_numeric_infos.nb_digits[*index],
        )
        .iter()
        .map(|x| x.to_string())
        .collect();

        oracles
            .get_mut(*index)
            .unwrap()
            .add_attestation(EVENT_ID, &outcomes);
    }

    oracles
}

fn get_numerical_test_params(
    oracle_numeric_infos: &OracleNumericInfo,
    threshold: usize,
    with_diff: bool,
    contract_descriptor: ContractDescriptor,
    use_max_value: bool,
) -> TestParams {
    let oracles =
        get_digit_decomposition_oracles(oracle_numeric_infos, threshold, with_diff, use_max_value);
    let contract_info = ContractInputInfo {
        oracles: OracleInput {
            public_keys: oracles.iter().map(|x| x.get_public_key()).collect(),
            event_id: EVENT_ID.to_owned(),
            threshold: threshold as u16,
        },
        contract_descriptor,
    };

    let contract_input = ContractInput {
        offer_collateral: 100000000,
        accept_collateral: 100000000,
        maturity_time: EVENT_MATURITY,
        fee_rate: 2,
        contract_infos: vec![contract_info],
    };

    TestParams {
        oracles,
        contract_input,
    }
}

fn numerical_common(
    nb_oracles: usize,
    threshold: usize,
    difference_params: Option<DifferenceParams>,
) {
    let oracle_numeric_infos = get_same_num_digits_oracle_numeric_infos(nb_oracles);
    let with_diff = difference_params.is_some();
    let contract_descriptor =
        get_numerical_contract_descriptor(oracle_numeric_infos.clone(), difference_params);
    manager_execution_test(
        get_numerical_test_params(
            &oracle_numeric_infos,
            threshold,
            with_diff,
            contract_descriptor,
            false,
        ),
        TestPath::Close,
    );
}

fn numerical_common_diff_nb_digits(
    nb_oracles: usize,
    threshold: usize,
    difference_params: Option<DifferenceParams>,
    use_max_value: bool,
) {
    let with_diff = difference_params.is_some();
    let oracle_numeric_infos = get_variable_oracle_numeric_infos(
        &(0..nb_oracles)
            .map(|_| (NB_DIGITS + (thread_rng().next_u32() % 6)) as usize)
            .collect::<Vec<_>>(),
    );
    let contract_descriptor =
        get_numerical_contract_descriptor(oracle_numeric_infos.clone(), difference_params);

    manager_execution_test(
        get_numerical_test_params(
            &oracle_numeric_infos,
            threshold,
            with_diff,
            contract_descriptor,
            use_max_value,
        ),
        TestPath::Close,
    );
}

fn get_enum_and_numerical_test_params(
    nb_oracles: usize,
    threshold: usize,
    with_diff: bool,
    difference_params: Option<DifferenceParams>,
) -> TestParams {
    let oracle_numeric_infos = get_same_num_digits_oracle_numeric_infos(nb_oracles);
    let enum_oracles = get_enum_oracles(nb_oracles, threshold);
    let enum_contract_descriptor = get_enum_contract_descriptor();
    let enum_contract_info = ContractInputInfo {
        oracles: OracleInput {
            public_keys: enum_oracles.iter().map(|x| x.get_public_key()).collect(),
            event_id: EVENT_ID.to_owned(),
            threshold: threshold as u16,
        },
        contract_descriptor: enum_contract_descriptor,
    };
    let numerical_oracles =
        get_digit_decomposition_oracles(&oracle_numeric_infos, threshold, with_diff, false);
    let numerical_contract_descriptor = get_numerical_contract_descriptor(
        get_same_num_digits_oracle_numeric_infos(nb_oracles),
        difference_params,
    );
    let numerical_contract_info = ContractInputInfo {
        oracles: OracleInput {
            public_keys: numerical_oracles
                .iter()
                .map(|x| x.get_public_key())
                .collect(),
            event_id: EVENT_ID.to_owned(),
            threshold: threshold as u16,
        },
        contract_descriptor: numerical_contract_descriptor,
    };

    let contract_infos = if thread_rng().next_u32() % 2 == 0 {
        vec![enum_contract_info, numerical_contract_info]
    } else {
        vec![numerical_contract_info, enum_contract_info]
    };

    let contract_input = ContractInput {
        offer_collateral: 100000000,
        accept_collateral: 100000000,
        maturity_time: EVENT_MATURITY,
        fee_rate: 2,
        contract_infos,
    };

    TestParams {
        oracles: enum_oracles
            .into_iter()
            .chain(numerical_oracles.into_iter())
            .collect(),
        contract_input,
    }
}

fn get_same_num_digits_oracle_numeric_infos(nb_oracles: usize) -> OracleNumericInfo {
    OracleNumericInfo {
        nb_digits: std::iter::repeat(NB_DIGITS as usize)
            .take(nb_oracles)
            .collect(),
        base: BASE as usize,
    }
}

fn get_variable_oracle_numeric_infos(nb_digits: &[usize]) -> OracleNumericInfo {
    OracleNumericInfo {
        base: BASE as usize,
        nb_digits: nb_digits.to_vec(),
    }
}

#[test]
#[ignore]
fn single_oracle_numerical_test() {
    numerical_common(1, 1, None);
}

#[test]
#[ignore]
fn three_of_three_oracle_numerical_test() {
    numerical_common(3, 3, None);
}

#[test]
#[ignore]
fn two_of_five_oracle_numerical_test() {
    numerical_common(5, 2, None);
}

#[test]
#[ignore]
fn three_of_three_oracle_numerical_with_diff_test() {
    numerical_common(3, 3, Some(get_difference_params()));
}

#[test]
#[ignore]
fn two_of_five_oracle_numerical_with_diff_test() {
    numerical_common(5, 2, Some(get_difference_params()));
}

#[test]
#[ignore]
fn three_of_five_oracle_numerical_with_diff_test() {
    numerical_common(5, 3, Some(get_difference_params()));
}

#[test]
#[ignore]
fn enum_single_oracle_test() {
    manager_execution_test(get_enum_test_params(1, 1, None), TestPath::Close);
}

#[test]
#[ignore]
fn enum_3_of_3_test() {
    manager_execution_test(get_enum_test_params(3, 3, None), TestPath::Close);
}

#[test]
#[ignore]
fn enum_3_of_5_test() {
    manager_execution_test(get_enum_test_params(5, 3, None), TestPath::Close);
}

#[test]
#[ignore]
fn enum_and_numerical_with_diff_3_of_5_test() {
    manager_execution_test(
        get_enum_and_numerical_test_params(5, 3, true, Some(get_difference_params())),
        TestPath::Close,
    );
}

#[test]
#[ignore]
fn enum_and_numerical_with_diff_5_of_5_test() {
    manager_execution_test(
        get_enum_and_numerical_test_params(5, 5, true, Some(get_difference_params())),
        TestPath::Close,
    );
}

#[test]
#[ignore]
fn enum_and_numerical_3_of_5_test() {
    manager_execution_test(
        get_enum_and_numerical_test_params(5, 3, false, None),
        TestPath::Close,
    );
}

#[test]
#[ignore]
fn enum_and_numerical_5_of_5_test() {
    manager_execution_test(
        get_enum_and_numerical_test_params(5, 5, false, None),
        TestPath::Close,
    );
}

#[test]
#[ignore]
fn enum_single_oracle_refund_test() {
    manager_execution_test(
        get_enum_test_params(1, 1, Some(get_enum_oracles(1, 0))),
        TestPath::Refund,
    );
}

#[test]
#[ignore]
fn enum_single_oracle_bad_accept_cet_sig_test() {
    manager_execution_test(
        get_enum_test_params(1, 1, Some(get_enum_oracles(1, 0))),
        TestPath::BadAcceptCetSignature,
    );
}

#[test]
#[ignore]
fn enum_single_oracle_bad_accept_refund_sig_test() {
    manager_execution_test(
        get_enum_test_params(1, 1, Some(get_enum_oracles(1, 0))),
        TestPath::BadAcceptRefundSignature,
    );
}

#[test]
#[ignore]
fn enum_single_oracle_bad_sign_cet_sig_test() {
    manager_execution_test(
        get_enum_test_params(1, 1, Some(get_enum_oracles(1, 0))),
        TestPath::BadSignCetSignature,
    );
}

#[test]
#[ignore]
fn enum_single_oracle_bad_sign_refund_sig_test() {
    manager_execution_test(
        get_enum_test_params(1, 1, Some(get_enum_oracles(1, 0))),
        TestPath::BadSignRefundSignature,
    );
}

#[test]
#[ignore]
fn two_of_two_oracle_numerical_diff_nb_digits_test() {
    numerical_common_diff_nb_digits(2, 2, None, false);
}

#[test]
#[ignore]
fn two_of_five_oracle_numerical_diff_nb_digits_test() {
    numerical_common_diff_nb_digits(5, 2, None, false);
}

#[test]
#[ignore]
fn two_of_two_oracle_numerical_with_diff_diff_nb_digits_test() {
    numerical_common_diff_nb_digits(2, 2, Some(get_difference_params()), false);
}

#[test]
#[ignore]
fn three_of_three_oracle_numerical_with_diff_diff_nb_digits_test() {
    numerical_common_diff_nb_digits(3, 3, Some(get_difference_params()), false);
}

#[test]
#[ignore]
fn two_of_five_oracle_numerical_with_diff_diff_nb_digits_test() {
    numerical_common_diff_nb_digits(5, 2, Some(get_difference_params()), false);
}

#[test]
#[ignore]
fn two_of_two_oracle_numerical_with_diff_diff_nb_digits_max_value_test() {
    numerical_common_diff_nb_digits(2, 2, Some(get_difference_params()), true);
}

#[test]
#[ignore]
fn two_of_three_oracle_numerical_with_diff_diff_nb_digits_max_value_test() {
    numerical_common_diff_nb_digits(3, 2, Some(get_difference_params()), true);
}

#[test]
#[ignore]
fn two_of_five_oracle_numerical_with_diff_diff_nb_digits_max_value_test() {
    numerical_common_diff_nb_digits(5, 2, Some(get_difference_params()), true);
}

#[test]
#[ignore]
fn two_of_two_oracle_numerical_diff_nb_digits_max_value_test() {
    numerical_common_diff_nb_digits(2, 2, None, true);
}

#[test]
#[ignore]
fn two_of_three_oracle_numerical_diff_nb_digits_max_value_test() {
    numerical_common_diff_nb_digits(3, 2, None, true);
}

#[test]
#[ignore]
fn two_of_five_oracle_numerical_diff_nb_digits_max_value_test() {
    numerical_common_diff_nb_digits(5, 2, None, true);
}

fn alter_adaptor_sig(input: &mut CetAdaptorSignatures) {
    let sig_index = thread_rng().next_u32() as usize % input.ecdsa_adaptor_signatures.len();

    let mut copy = input.ecdsa_adaptor_signatures[sig_index]
        .signature
        .as_ref()
        .to_vec();
    let i = thread_rng().next_u32() as usize % secp256k1_zkp::ffi::ECDSA_ADAPTOR_SIGNATURE_LENGTH;
    copy[i] = copy[i].checked_add(1).unwrap_or(0);
    input.ecdsa_adaptor_signatures[sig_index].signature =
        EcdsaAdaptorSignature::from_slice(&copy).unwrap();
}

fn alter_refund_sig(refund_signature: &Signature) -> Signature {
    let mut copy = refund_signature.serialize_compact();
    let i = thread_rng().next_u32() as usize % secp256k1_zkp::constants::COMPACT_SIGNATURE_SIZE;
    copy[i] = copy[i].checked_add(1).unwrap_or(0);
    Signature::from_compact(&copy).unwrap()
}

fn manager_execution_test(test_params: TestParams, path: TestPath) {
    env_logger::init();
    let (alice_send, bob_receive) = channel::<Option<Message>>();
    let (bob_send, alice_receive) = channel::<Option<Message>>();
    let (sync_send, sync_receive) = channel::<()>();
    let alice_sync_send = sync_send.clone();
    let bob_sync_send = sync_send;
    let (alice_rpc, bob_rpc, sink_rpc) = init_clients();

    let alice_bitcoin_core = Arc::new(BitcoinCoreProvider { client: alice_rpc });
    let bob_bitcoin_core = Arc::new(BitcoinCoreProvider { client: bob_rpc });

    let mut alice_oracles = HashMap::with_capacity(1);
    let mut bob_oracles = HashMap::with_capacity(1);

    for oracle in test_params.oracles {
        let oracle = Arc::new(oracle);
        alice_oracles.insert(oracle.get_public_key(), Arc::clone(&oracle));
        bob_oracles.insert(oracle.get_public_key(), Arc::clone(&oracle));
    }

    let alice_store = mocks::memory_storage_provider::MemoryStorage::new();
    let bob_store = mocks::memory_storage_provider::MemoryStorage::new();
    let mock_time = Arc::new(mocks::mock_time::MockTime {});
    mocks::mock_time::set_time((test_params.contract_input.maturity_time as u64) - 1);

    let alice_manager = Arc::new(Mutex::new(Manager::new(
        Arc::clone(&alice_bitcoin_core),
        Arc::clone(&alice_bitcoin_core),
        Box::new(alice_store),
        alice_oracles,
        Arc::clone(&mock_time),
    )));

    let alice_manager_loop = Arc::clone(&alice_manager);
    let alice_manager_send = Arc::clone(&alice_manager);

    let bob_manager = Arc::new(Mutex::new(Manager::new(
        Arc::clone(&bob_bitcoin_core),
        Arc::clone(&bob_bitcoin_core),
        Box::new(bob_store),
        bob_oracles,
        Arc::clone(&mock_time),
    )));

    let bob_manager_loop = Arc::clone(&bob_manager);
    let bob_manager_send = Arc::clone(&bob_manager);
    let alice_send_loop = alice_send.clone();
    let bob_send_loop = bob_send.clone();

    let alice_expect_error = Arc::new(AtomicBool::new(false));
    let bob_expect_error = Arc::new(AtomicBool::new(false));

    let alice_expect_error_loop = alice_expect_error.clone();
    let bob_expect_error_loop = bob_expect_error.clone();

    let path_copy = path.clone();
    let alter_sign = move |msg| match msg {
        Message::Sign(mut sign_dlc) => {
            match path_copy {
                TestPath::BadSignCetSignature => {
                    alter_adaptor_sig(&mut sign_dlc.cet_adaptor_signatures)
                }
                TestPath::BadSignRefundSignature => {
                    sign_dlc.refund_signature = alter_refund_sig(&sign_dlc.refund_signature);
                }
                _ => {}
            }
            Message::Sign(sign_dlc)
        }
        _ => msg,
    };

    let alice_handle = receive_loop!(
        alice_receive,
        alice_manager_loop,
        alice_send_loop,
        alice_expect_error_loop,
        alice_sync_send,
        |msg| msg
    );

    let bob_handle = receive_loop!(
        bob_receive,
        bob_manager_loop,
        bob_send_loop,
        bob_expect_error_loop,
        bob_sync_send,
        alter_sign
    );

    let offer_msg = bob_manager_send
        .lock()
        .unwrap()
        .send_offer(
            &test_params.contract_input,
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
                .parse()
                .unwrap(),
        )
        .expect("Send offer error");

    write_message("offer_message", offer_msg.clone());
    let temporary_contract_id = offer_msg.temporary_contract_id;
    bob_send.send(Some(Message::Offer(offer_msg))).unwrap();

    assert_contract_state!(bob_manager_send, temporary_contract_id, Offered);

    sync_receive.recv().expect("Error synchronizing");

    assert_contract_state!(alice_manager_send, temporary_contract_id, Offered);

    let (contract_id, _, mut accept_msg) = alice_manager_send
        .lock()
        .unwrap()
        .accept_contract_offer(&temporary_contract_id)
        .expect("Error accepting contract offer");

    write_message("accept_message", accept_msg.clone());

    assert_contract_state!(alice_manager_send, contract_id, Accepted);

    match path {
        TestPath::BadAcceptCetSignature | TestPath::BadAcceptRefundSignature => {
            match path {
                TestPath::BadAcceptCetSignature => {
                    alter_adaptor_sig(&mut accept_msg.cet_adaptor_signatures)
                }
                TestPath::BadAcceptRefundSignature => {
                    accept_msg.refund_signature = alter_refund_sig(&accept_msg.refund_signature);
                }
                _ => {}
            };
            bob_expect_error.store(true, Ordering::Relaxed);
            alice_send.send(Some(Message::Accept(accept_msg))).unwrap();
            sync_receive.recv().expect("Error synchronizing");
            assert_contract_state!(bob_manager_send, temporary_contract_id, FailedAccept);
        }
        TestPath::BadSignCetSignature | TestPath::BadSignRefundSignature => {
            alice_expect_error.store(true, Ordering::Relaxed);
            alice_send.send(Some(Message::Accept(accept_msg))).unwrap();
            // Bob receives accept message
            sync_receive.recv().expect("Error synchronizing");
            // Alice receives sign message
            sync_receive.recv().expect("Error synchronizing");
            assert_contract_state!(alice_manager_send, contract_id, FailedSign);
        }
        _ => {
            alice_send.send(Some(Message::Accept(accept_msg))).unwrap();
            sync_receive.recv().expect("Error synchronizing");

            assert_contract_state!(bob_manager_send, contract_id, Signed);

            // Should not change state and should not error
            periodic_check!(bob_manager_send, contract_id, Signed);

            sync_receive.recv().expect("Error synchronizing");

            assert_contract_state!(alice_manager_send, contract_id, Signed);

            let sink_address = sink_rpc.get_new_address(None, None).expect("RPC Error");
            sink_rpc
                .generate_to_address(6, &sink_address)
                .expect("RPC Error");

            periodic_check!(alice_manager_send, contract_id, Confirmed);
            periodic_check!(bob_manager_send, contract_id, Confirmed);

            mocks::mock_time::set_time((test_params.contract_input.maturity_time as u64) + 1);

            // Select the first one to close or refund randomly
            let (first, second) = if thread_rng().next_u32() % 2 == 0 {
                (alice_manager_send, bob_manager_send)
            } else {
                (bob_manager_send, alice_manager_send)
            };

            match path {
                TestPath::Close => {
                    periodic_check!(first, contract_id, Closed);

                    // Randomly check with or without having the CET mined
                    if thread_rng().next_u32() % 2 == 0 {
                        sink_rpc
                            .generate_to_address(1, &sink_address)
                            .expect("RPC Error");
                    }

                    periodic_check!(second, contract_id, Closed);
                }
                TestPath::Refund => {
                    periodic_check!(first, contract_id, Confirmed);

                    periodic_check!(second, contract_id, Confirmed);

                    mocks::mock_time::set_time(
                        ((test_params.contract_input.maturity_time
                            + dlc_manager::manager::REFUND_DELAY) as u64)
                            + 1,
                    );
                    sink_rpc
                        .generate_to_address(10, &sink_address)
                        .expect("RPC Error");

                    periodic_check!(first, contract_id, Refunded);

                    // Randomly check with or without having the Refund mined.
                    if thread_rng().next_u32() % 2 == 0 {
                        sink_rpc
                            .generate_to_address(1, &sink_address)
                            .expect("RPC Error");
                    }

                    periodic_check!(second, contract_id, Refunded);
                }
                _ => unreachable!(),
            }
        }
    }

    alice_send.send(None).unwrap();
    bob_send.send(None).unwrap();

    alice_handle.join().unwrap();
    bob_handle.join().unwrap();

    create_test_vector();
}
