#![allow(dead_code)]

extern crate bitcoin_rpc_provider;
extern crate bitcoin_test_utils;
extern crate bitcoincore_rpc;
extern crate bitcoincore_rpc_json;
extern crate dlc_manager;

use std::ops::Deref;

use dlc::{EnumerationPayout, Payout};
use dlc_manager::payout_curve::{
    PayoutFunction, PayoutFunctionPiece, PayoutPoint, PolynomialPayoutCurvePiece, RoundingInterval,
    RoundingIntervals,
};
use dlc_manager::{
    contract::{
        contract_input::{ContractInput, ContractInputInfo, OracleInput},
        enum_descriptor::EnumDescriptor,
        numerical_descriptor::{DifferenceParams, NumericalDescriptor},
        ContractDescriptor,
    },
    payout_curve::HyperbolaPayoutCurvePiece,
};
use dlc_manager::{Blockchain, Oracle};
use dlc_messages::oracle_msgs::{
    DigitDecompositionEventDescriptor, EnumEventDescriptor, EventDescriptor,
};
use dlc_trie::{digit_decomposition::decompose_value, OracleNumericInfo};
use mocks::mock_oracle_provider::MockOracle;
use secp256k1_zkp::rand::{seq::SliceRandom, thread_rng, RngCore};
use simple_wallet::{WalletBlockchainProvider, WalletStorage};

pub const NB_DIGITS: u32 = 10;
pub const MIN_SUPPORT_EXP: usize = 1;
pub const MAX_ERROR_EXP: usize = 2;
pub const BASE: u32 = 2;
pub const EVENT_MATURITY: u32 = 1623133104;
pub const EVENT_ID: &str = "Test";
pub const OFFER_COLLATERAL: u64 = 90000000;
pub const ACCEPT_COLLATERAL: u64 = 11000000;
pub const TOTAL_COLLATERAL: u64 = OFFER_COLLATERAL + ACCEPT_COLLATERAL;
pub const MID_POINT: u64 = 5;
pub const ROUNDING_MOD: u64 = 1;

#[macro_export]
macro_rules! receive_loop {
    ($receive:expr, $manager:expr, $send:expr, $expect_err:expr, $sync_send:expr, $rcv_callback: expr, $msg_callback: expr) => {
        thread::spawn(move || loop {
            let m;
            match $receive.recv() {
                Ok(Some(msg)) => {
                    m = format!("{:?}", msg).split_at(6).0.to_string();
                    let res = $manager.lock().unwrap().on_dlc_message(
                        &msg,
                        "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
                            .parse()
                            .unwrap(),
                    );
                    $sync_send.send(()).expect("Error syncing");
                    match res {
                        Ok(opt) => {
                            if $expect_err.load(Ordering::Relaxed) != false {
                                panic!("Expected error not raised");
                            }
                            match opt {
                                Some(msg) => {
                                    let msg_opt = $rcv_callback(msg);
                                    if let Some(msg) = msg_opt {
                                        $msg_callback(&msg);
                                        (&$send).send(Some(msg)).expect("Error sending");
                                    }
                                }
                                None => {}
                            }
                        }
                        Err(e) => {
                            if $expect_err.load(Ordering::Relaxed) != true {
                                panic!("Unexpected error {}", e);
                            }
                        }
                    }
                }
                Ok(None) | Err(_) => return,
            };
        })
    };
}

#[macro_export]
macro_rules! write_contract {
    ($contract: ident, $state: ident) => {
        match $contract {
            Contract::$state(s) => {
                let mut buf = Vec::new();
                s.write(&mut buf)
                    .expect("to be able to serialize the contract.");
                std::fs::write(format!("{}", stringify!($state)), buf)
                    .expect("to be able to save the contract to file.");
            }
            _ => {}
        }
    };
}

#[macro_export]
macro_rules! assert_contract_state {
    ($d:expr, $id:expr, $p:ident) => {
        assert_contract_state_unlocked!($d.lock().unwrap(), $id, $p);
    };
}

#[macro_export]
macro_rules! assert_contract_state_unlocked {
    ($d:expr, $id:expr, $p:ident) => {
        let res = $d
            .get_store()
            .get_contract(&$id)
            .expect("Could not retrieve contract");
        if let Some(c) = res {
            if let Contract::$p(_) = c {
            } else {
                panic!("Unexpected contract state {:?}", c);
            }
            if std::env::var("GENERATE_SERIALIZED_CONTRACT").is_ok() {
                write_contract!(c, $p);
            }
        } else {
            panic!("Contract {:02x?} does not exist in store", $id);
        }
    };
}

#[macro_export]
macro_rules! assert_channel_contract_state {
    ($d: expr, $id: expr, $p: ident) => {{
        let channel = $d
            .get_store()
            .get_channel(&$id)
            .expect("Could not retrieve contract")
            .expect(&format!("No such channel: {:?}", $id));
        let contract_id = channel.get_contract_id().expect("No contract id");

        assert_contract_state_unlocked!($d, contract_id, $p);
        contract_id
    }};
}

#[macro_export]
macro_rules! write_channel {
    ($channel: ident, $state: ident) => {
        let suffix = if let Channel::Signed(s) = &$channel {
            format!("{}", s.state)
        } else {
            "".to_string()
        };
        match $channel {
            Channel::$state(s) => {
                let mut buf = Vec::new();
                s.write(&mut buf)
                    .expect("to be able to serialize the channel.");
                std::fs::write(format!("{}Channel{}", stringify!($state), suffix), buf)
                    .expect("to be able to save the channel to file.");
            }
            _ => {}
        }
    };
}

#[macro_export]
macro_rules! write_sub_channel {
    ($channel: ident, $state: ident) => {
        use lightning::util::ser::Writeable;

        let mut buf = Vec::new();
        $channel
            .write(&mut buf)
            .expect("to be able to serialize the sub channel");
        std::fs::write(format!("{}SubChannel", stringify!($state)), buf)
            .expect("to be able to save the sub channel to file");
    };
}

#[macro_export]
macro_rules! assert_channel_state {
    ($d:expr, $id:expr, $p:ident $(, $s: ident)?) => {{
        assert_channel_state_unlocked!($d.lock().unwrap(), $id, $p $(, $s)?)
    }};
}

#[allow(unused_macros)]
macro_rules! assert_channel_state_unlocked {
    ($d:expr, $id:expr, $p:ident $(, $s: ident)?) => {{
        let res = $d
            .get_store()
            .get_channel(&$id)
            .expect("Could not retrieve contract");
        if let Some(Channel::$p(c)) = res {
            $(if let dlc_manager::channel::signed_channel::SignedChannelState::$s { .. } = c.state {
            } else {
                panic!("Unexpected signed channel state {:?}", c.state);
            })?
            if std::env::var("GENERATE_SERIALIZED_CHANNEL").is_ok() {
                let channel = Channel::$p(c);
                write_channel!(channel, $p);
            }
        } else {
            let state = match res {
                Some(Channel::Offered(_)) => "offered",
                Some(Channel::Accepted(_)) => "accepted",
                Some(Channel::Signed(_)) => "signed",
                Some(Channel::FailedAccept(_)) => "failed accept",
                Some(Channel::FailedSign(_)) => "failed sign",
                None => "none",
            };
            panic!("Unexpected channel state {}", state);
        }
    }};
}

#[macro_export]
macro_rules! assert_sub_channel_state {
    ($d:expr, $id:expr $(, $s_tuple: ident)? $(;$s_simple: ident)?) => {{
        let res = $d
            .get_dlc_manager()
            .get_store()
            .get_sub_channel(*$id)
            .expect("Could not retrieve contract");
        if let Some(sub_channel) = res {
            $(if let SubChannelState::$s_tuple(_)  = sub_channel.state {
            } else {
                panic!("Unexpected sub channel state {:?}", sub_channel.state);
            }
            if std::env::var("GENERATE_SERIALIZED_SUB_CHANNEL").is_ok() {
                write_sub_channel!(sub_channel, $s_tuple);
            })?
            $(if let SubChannelState::$s_simple  = sub_channel.state {
            } else {
                panic!("Unexpected sub channel state {:?}", sub_channel.state);
            }
            if std::env::var("GENERATE_SERIALIZED_SUB_CHANNEL").is_ok() {
                write_sub_channel!(sub_channel, $s_simple);
            })?

            let dlc_channel_id = sub_channel.get_dlc_channel_id(0);

            if let Some(dlc_channel_id) = dlc_channel_id {
                match sub_channel.state {
                    SubChannelState::Offered(_) => {
                        assert_channel_state_unlocked!($d.get_dlc_manager(), dlc_channel_id, Offered);
                        assert_channel_contract_state!($d.get_dlc_manager(), dlc_channel_id, Offered);
                    }
                    SubChannelState::Accepted(_) => {
                        assert_channel_state_unlocked!($d.get_dlc_manager(), dlc_channel_id, Accepted);
                        assert_channel_contract_state!($d.get_dlc_manager(), dlc_channel_id, Accepted);
                    }
                    _ => {}
                }
            }

        } else {
            panic!("Sub channel not found");
        }
    }};
}

pub fn enum_outcomes() -> Vec<String> {
    vec![
        "a".to_owned(),
        "b".to_owned(),
        "c".to_owned(),
        "d".to_owned(),
    ]
}

pub fn max_value() -> u32 {
    BASE.pow(NB_DIGITS) - 1
}

pub fn max_value_from_digits(nb_digits: usize) -> u32 {
    BASE.pow(nb_digits as u32) - 1
}

pub fn select_active_oracles(nb_oracles: usize, threshold: usize) -> Vec<usize> {
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
pub struct TestParams {
    pub oracles: Vec<MockOracle>,
    pub contract_input: ContractInput,
}

pub fn get_difference_params() -> DifferenceParams {
    DifferenceParams {
        max_error_exp: MAX_ERROR_EXP,
        min_support_exp: MIN_SUPPORT_EXP,
        maximize_coverage: false,
    }
}

pub fn get_enum_contract_descriptor(total_collateral: u64) -> ContractDescriptor {
    let outcome_payouts: Vec<_> = enum_outcomes()
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let payout = if i % 2 == 0 {
                Payout {
                    offer: total_collateral,
                    accept: 0,
                }
            } else {
                Payout {
                    offer: 0,
                    accept: total_collateral,
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

pub fn get_enum_oracle() -> MockOracle {
    let mut oracle = MockOracle::new();
    let event = EnumEventDescriptor {
        outcomes: enum_outcomes(),
    };

    oracle.add_event(EVENT_ID, &EventDescriptor::EnumEvent(event), EVENT_MATURITY);

    oracle
}

pub fn get_enum_oracles(nb_oracles: usize, threshold: usize) -> Vec<MockOracle> {
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

pub fn get_enum_test_params(
    nb_oracles: usize,
    threshold: usize,
    oracles: Option<Vec<MockOracle>>,
) -> TestParams {
    get_enum_test_params_custom_collateral(
        nb_oracles,
        threshold,
        oracles,
        OFFER_COLLATERAL,
        ACCEPT_COLLATERAL,
    )
}

pub fn get_enum_test_params_custom_collateral(
    nb_oracles: usize,
    threshold: usize,
    oracles: Option<Vec<MockOracle>>,
    offer_collateral: u64,
    accept_collateral: u64,
) -> TestParams {
    let oracles = oracles.unwrap_or_else(|| get_enum_oracles(nb_oracles, threshold));
    let contract_descriptor = get_enum_contract_descriptor(offer_collateral + accept_collateral);
    let contract_info = ContractInputInfo {
        contract_descriptor,
        oracles: OracleInput {
            public_keys: oracles.iter().map(|x| x.get_public_key()).collect(),
            event_id: EVENT_ID.to_owned(),
            threshold: threshold as u16,
        },
    };

    let contract_input = ContractInput {
        offer_collateral,
        accept_collateral,
        fee_rate: 1,
        contract_infos: vec![contract_info],
    };

    TestParams {
        oracles,
        contract_input,
    }
}

pub fn get_polynomial_payout_curve_pieces(min_nb_digits: usize) -> Vec<PayoutFunctionPiece> {
    vec![
        PayoutFunctionPiece::PolynomialPayoutCurvePiece(
            PolynomialPayoutCurvePiece::new(vec![
                PayoutPoint {
                    event_outcome: 0,
                    outcome_payout: 0,
                    extra_precision: 0,
                },
                PayoutPoint {
                    event_outcome: 3,
                    outcome_payout: OFFER_COLLATERAL,
                    extra_precision: 0,
                },
                PayoutPoint {
                    event_outcome: MID_POINT,
                    outcome_payout: TOTAL_COLLATERAL,
                    extra_precision: 0,
                },
            ])
            .unwrap(),
        ),
        PayoutFunctionPiece::PolynomialPayoutCurvePiece(
            PolynomialPayoutCurvePiece::new(vec![
                PayoutPoint {
                    event_outcome: MID_POINT,
                    outcome_payout: TOTAL_COLLATERAL,
                    extra_precision: 0,
                },
                PayoutPoint {
                    event_outcome: max_value_from_digits(min_nb_digits) as u64,
                    outcome_payout: TOTAL_COLLATERAL,
                    extra_precision: 0,
                },
            ])
            .unwrap(),
        ),
    ]
}

pub fn get_hyperbola_payout_curve_pieces(min_nb_digits: usize) -> Vec<PayoutFunctionPiece> {
    vec![PayoutFunctionPiece::HyperbolaPayoutCurvePiece(
        HyperbolaPayoutCurvePiece::new(
            PayoutPoint {
                event_outcome: 0,
                outcome_payout: 0,
                extra_precision: 0,
            },
            PayoutPoint {
                event_outcome: max_value_from_digits(min_nb_digits) as u64,
                outcome_payout: 0,
                extra_precision: 0,
            },
            true,
            50.0,
            50.0,
            5.0,
            -1.0,
            0.0,
            1.0,
        )
        .unwrap(),
    )]
}

pub fn get_numerical_contract_descriptor(
    oracle_numeric_infos: OracleNumericInfo,
    function_pieces: Vec<PayoutFunctionPiece>,
    difference_params: Option<DifferenceParams>,
) -> ContractDescriptor {
    ContractDescriptor::Numerical(NumericalDescriptor {
        payout_function: PayoutFunction::new(function_pieces).unwrap(),
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

pub fn get_digit_decomposition_oracle(nb_digits: u16) -> MockOracle {
    let mut oracle = MockOracle::new();
    let event = DigitDecompositionEventDescriptor {
        base: BASE as u16,
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

pub fn get_digit_decomposition_oracles(
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
        } else if !use_max_value {
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
            let max_value = max_value_from_digits(oracle_numeric_infos.nb_digits[*index]) as usize;
            if max_value == outcome_value {
                outcome_value
            } else {
                outcome_value + 1 + (thread_rng().next_u32() as usize % (max_value - outcome_value))
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

pub fn get_numerical_test_params(
    oracle_numeric_infos: &OracleNumericInfo,
    threshold: usize,
    with_diff: bool,
    contract_descriptor: ContractDescriptor,
    use_max_value: bool,
) -> TestParams {
    get_numerical_test_params_custom_collateral(
        oracle_numeric_infos,
        threshold,
        with_diff,
        contract_descriptor,
        use_max_value,
        OFFER_COLLATERAL,
        ACCEPT_COLLATERAL,
    )
}

pub fn get_numerical_test_params_custom_collateral(
    oracle_numeric_infos: &OracleNumericInfo,
    threshold: usize,
    with_diff: bool,
    contract_descriptor: ContractDescriptor,
    use_max_value: bool,
    offer_collateral: u64,
    accept_collateral: u64,
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
        offer_collateral,
        accept_collateral,
        fee_rate: 1,
        contract_infos: vec![contract_info],
    };

    TestParams {
        oracles,
        contract_input,
    }
}

pub fn get_enum_and_numerical_test_params(
    nb_oracles: usize,
    threshold: usize,
    with_diff: bool,
    difference_params: Option<DifferenceParams>,
) -> TestParams {
    let oracle_numeric_infos = get_same_num_digits_oracle_numeric_infos(nb_oracles);
    let enum_oracles = get_enum_oracles(nb_oracles, threshold);
    let enum_contract_descriptor =
        get_enum_contract_descriptor(OFFER_COLLATERAL + ACCEPT_COLLATERAL);
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
        get_polynomial_payout_curve_pieces(oracle_numeric_infos.get_min_nb_digits()),
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
        offer_collateral: OFFER_COLLATERAL,
        accept_collateral: ACCEPT_COLLATERAL,
        fee_rate: 1,
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

pub fn get_same_num_digits_oracle_numeric_infos(nb_oracles: usize) -> OracleNumericInfo {
    OracleNumericInfo {
        nb_digits: std::iter::repeat(NB_DIGITS as usize)
            .take(nb_oracles)
            .collect(),
        base: BASE as usize,
    }
}

pub fn get_variable_oracle_numeric_infos(nb_digits: &[usize]) -> OracleNumericInfo {
    OracleNumericInfo {
        base: BASE as usize,
        nb_digits: nb_digits.to_vec(),
    }
}

pub fn refresh_wallet<B: Deref, W: Deref>(
    wallet: &simple_wallet::SimpleWallet<B, W>,
    expected_funds: u64,
) where
    B::Target: Blockchain + WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    let mut retry = 0;
    while wallet.get_balance() != expected_funds {
        if retry > 30 {
            panic!("Wallet refresh taking too long.")
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        wallet.refresh().unwrap();
        retry += 1;
    }
}
