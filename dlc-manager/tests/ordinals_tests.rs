use std::collections::HashMap;
use std::sync::Arc;
use std::{env::current_dir, path::PathBuf, process::Command};

use bitcoin::{OutPoint, Transaction};
use bitcoin_rpc_provider::BitcoinCoreProvider;
use bitcoin_test_utils::rpc_helpers::{init_clients, ACCEPT_PARTY, OFFER_PARTY, SINK};
use bitcoincore_rpc::{Client, RpcApi};
use dlc::ord::SatPoint;
use dlc::{EnumerationPayout, Payout};
use dlc_manager::contract::contract_input::{ContractInput, ContractInputInfo, OracleInput};
use dlc_manager::contract::enum_descriptor::EnumDescriptor;
use dlc_manager::contract::ord_descriptor::{
    OrdDescriptor, OrdEnumDescriptor, OrdNumericalDescriptor, OrdOutcomeDescriptor,
};
use dlc_manager::contract::ContractDescriptor;
use dlc_manager::manager::Manager;
use dlc_manager::Oracle;
use dlc_messages::Message;
use dlc_trie::digit_decomposition::decompose_value;
use mocks::memory_storage_provider::MemoryStorage;
use mocks::mock_oracle_provider::MockOracle;
use mocks::mock_time::MockTime;
use secp256k1_zkp::rand::distributions::Uniform;
use secp256k1_zkp::rand::{thread_rng, Rng, RngCore};
use test_utils::{
    enum_outcomes, get_digit_decomposition_oracle, get_enum_oracles,
    get_numerical_contract_descriptor, get_polynomial_payout_curve_pieces,
    get_same_num_digits_oracle_numeric_infos, TestParams, ACCEPT_COLLATERAL, EVENT_ID, NB_DIGITS,
    OFFER_COLLATERAL, TOTAL_COLLATERAL,
};

use crate::test_utils::{max_value, BASE, EVENT_MATURITY};

type TestManager = Manager<
    Arc<BitcoinCoreProvider>,
    Arc<BitcoinCoreProvider>,
    Arc<MemoryStorage>,
    Arc<MockOracle>,
    Arc<MockTime>,
    Arc<BitcoinCoreProvider>,
>;

#[derive(Debug, serde::Deserialize, PartialEq, Eq)]
struct InscriptionsOutput {
    inscription: String,
    location: String,
    explorer: String,
    postage: u64,
}

#[macro_use]
#[allow(dead_code)]
mod test_utils;

const DEFAULT_POSTAGE: u64 = 10000;

fn ord_binary_path() -> PathBuf {
    let mut dir = current_dir().unwrap();
    dir.push("tests");
    dir.push("ord");
    dir
}

fn ord_command_base() -> Command {
    let ord_bin_path = ord_binary_path();
    let mut command = Command::new(&ord_bin_path);
    command.arg("-r");
    command.arg("--bitcoin-rpc-user");
    command.arg("testuser");
    command.arg("--bitcoin-rpc-pass");
    command.arg("lq6zequb-gYTdF2_ZEUtr8ywTXzLYtknzWU4nV8uVoo=");
    command.arg("--data-dir");
    command.arg("./tests/orddata");
    command
}

fn ord_command_wallet(name: &str) -> Command {
    let mut command = ord_command_base();
    command.arg("--wallet");
    command.arg(name);
    command.arg("wallet");
    command
}

fn create_ordinal_wallet(name: &str) {
    let mut command = ord_command_wallet(name);
    command.arg("create");
    let mut handle = command.spawn().expect("not to fail");
    handle.wait().unwrap();
}

fn inscribe_logo(wallet_name: &str) {
    let mut command = ord_command_wallet(wallet_name);
    command.arg("inscribe");
    command.arg("--fee-rate");
    command.arg("1");
    command.arg("./tests/logo-bw.svg");
    let mut handle = command.spawn().expect("not to fail");
    handle.wait().unwrap();
}

fn get_inscriptions(wallet_name: &str) -> Vec<InscriptionsOutput> {
    let mut command = ord_command_wallet(wallet_name);
    command.arg("inscriptions");
    let res = command.output().expect("not to fail");
    serde_json::from_str(&String::from_utf8(res.stdout).unwrap()).unwrap()
}

fn generate_blocks(sink_rpc: &Client, nb_blocks: u64) {
    let prev_blockchain_height = sink_rpc.get_block_count().unwrap();

    let sink_address = sink_rpc
        .call("getnewaddress", &["".into(), "bech32m".into()])
        .expect("RPC Error");
    sink_rpc
        .generate_to_address(nb_blocks, &sink_address)
        .expect("RPC Error");

    // Make sure all blocks have been generated
    let mut cur_blockchain_height = prev_blockchain_height;
    while cur_blockchain_height < prev_blockchain_height + nb_blocks {
        std::thread::sleep(std::time::Duration::from_millis(200));
        cur_blockchain_height = sink_rpc.get_block_count().unwrap();
    }
}

fn get_enum_ord_outcome_descriptor(win_both: bool) -> OrdOutcomeDescriptor {
    let outcome_payouts: Vec<_> = enum_outcomes()
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let payout = if i % 2 == 0 {
                Payout {
                    offer: TOTAL_COLLATERAL,
                    accept: 0,
                }
            } else {
                Payout {
                    offer: 0,
                    accept: TOTAL_COLLATERAL,
                }
            };
            EnumerationPayout {
                outcome: x.to_owned(),
                payout,
            }
        })
        .collect();
    OrdOutcomeDescriptor::Enum(OrdEnumDescriptor {
        to_offer_payouts: outcome_payouts
            .iter()
            .enumerate()
            .map(|(i, _)| i % 2 == (!win_both as usize))
            .collect(),
        descriptor: EnumDescriptor { outcome_payouts },
    })
}

fn get_numerical_ord_outcome_descriptor() -> OrdOutcomeDescriptor {
    let oracle_numeric_infos = get_same_num_digits_oracle_numeric_infos(1);
    if let ContractDescriptor::Numerical(numerical) = get_numerical_contract_descriptor(
        oracle_numeric_infos.clone(),
        get_polynomial_payout_curve_pieces(NB_DIGITS as usize),
        None,
    ) {
        let mut rng = thread_rng();
        let distribution = Uniform::new(0, 2_u64.pow(NB_DIGITS) - 1);
        let nb_ranges = rng.gen_range(0..30);

        let mut bounds: Vec<_> = (0..nb_ranges * 2)
            .map(|_| rng.sample(distribution))
            .collect();

        bounds.sort();
        bounds.dedup();
        if bounds.len() % 2 == 1 {
            bounds.remove(0);
        }
        let mut to_offer_ranges = Vec::new();

        for i in (0..bounds.len()).step_by(2) {
            to_offer_ranges.push((bounds[i], bounds[i + 1]));
        }

        OrdOutcomeDescriptor::Numerical(OrdNumericalDescriptor {
            descriptor: numerical,
            to_offer_ranges,
        })
    } else {
        panic!()
    }
}

fn get_ord_contract_descriptor(
    ordinal_sat_point: SatPoint,
    ordinal_tx: &Transaction,
    outcome_descriptor: &OrdOutcomeDescriptor,
) -> ContractDescriptor {
    let ord_descriptor = OrdDescriptor {
        ordinal_sat_point,
        ordinal_tx: ordinal_tx.clone(),
        refund_offer: true,
        outcome_descriptor: outcome_descriptor.clone(),
    };

    ContractDescriptor::Ord(ord_descriptor)
}

fn get_ord_test_params(
    nb_oracles: usize,
    threshold: usize,
    ordinal_sat_point: SatPoint,
    ordinal_tx: &Transaction,
    outcome_descriptor: &OrdOutcomeDescriptor,
) -> TestParams {
    let oracles = match outcome_descriptor {
        OrdOutcomeDescriptor::Enum(_) => get_enum_oracles(nb_oracles, threshold),
        OrdOutcomeDescriptor::Numerical(_) => {
            let mut oracle = get_digit_decomposition_oracle(NB_DIGITS as u16);
            let outcome_value = (thread_rng().next_u32() % max_value()) as usize;
            let outcomes: Vec<_> =
                decompose_value(outcome_value, BASE as usize, NB_DIGITS as usize)
                    .iter()
                    .map(|x| x.to_string())
                    .collect();

            oracle.add_attestation(EVENT_ID, &outcomes);

            vec![oracle]
        }
    };
    let contract_descriptor =
        get_ord_contract_descriptor(ordinal_sat_point, ordinal_tx, outcome_descriptor);
    let contract_info = ContractInputInfo {
        contract_descriptor,
        oracles: OracleInput {
            public_keys: oracles.iter().map(|x| x.get_public_key()).collect(),
            event_id: EVENT_ID.to_owned(),
            threshold: threshold as u16,
        },
    };

    let contract_input = ContractInput {
        offer_collateral: OFFER_COLLATERAL,
        accept_collateral: ACCEPT_COLLATERAL,
        fee_rate: 2,
        contract_infos: vec![contract_info],
    };

    TestParams {
        oracles,
        contract_input,
    }
}

#[test]
#[ignore]
fn ordinal_enum_test() {
    let outcome_descriptor = get_enum_ord_outcome_descriptor(false);
    let (mut alice_manager, mut bob_manager, sink_rpc, inscription, test_params) =
        init(&outcome_descriptor);

    execute_contract(
        &mut alice_manager,
        &mut bob_manager,
        &sink_rpc,
        &test_params,
    );

    mocks::mock_time::set_time((EVENT_MATURITY as u64) + 1);

    alice_manager.periodic_check().unwrap();

    generate_blocks(&sink_rpc, 1);

    let outcomes = enum_outcomes();
    let outcome_pos = outcomes
        .iter()
        .position(|x| {
            test_params.oracles[0]
                .get_attestation(EVENT_ID)
                .unwrap()
                .outcomes[0]
                == *x
        })
        .unwrap();

    let winner = if outcome_pos % 2 == 1 {
        OFFER_PARTY
    } else {
        ACCEPT_PARTY
    };

    let win_inscriptions = get_inscriptions(winner);

    let inscription = win_inscriptions
        .iter()
        .find(|x| x.inscription == inscription.inscription)
        .expect("To find the inscription");
    let outpoint = location_string_to_outpoint(&inscription.location);
    let tx = sink_rpc.get_raw_transaction(&outpoint.txid, None).unwrap();
    assert_eq!(DEFAULT_POSTAGE, tx.output[0].value);
    assert_eq!(TOTAL_COLLATERAL, tx.output[1].value);
}

#[test]
#[ignore]
fn ordinal_enum_win_both_test() {
    let outcome_descriptor = get_enum_ord_outcome_descriptor(true);
    let (mut alice_manager, mut bob_manager, sink_rpc, inscription, test_params) =
        init(&outcome_descriptor);

    execute_contract(
        &mut alice_manager,
        &mut bob_manager,
        &sink_rpc,
        &test_params,
    );

    mocks::mock_time::set_time((EVENT_MATURITY as u64) + 1);

    alice_manager.periodic_check().unwrap();

    generate_blocks(&sink_rpc, 1);

    let outcomes = enum_outcomes();
    let outcome_pos = outcomes
        .iter()
        .position(|x| {
            test_params.oracles[0]
                .get_attestation(EVENT_ID)
                .unwrap()
                .outcomes[0]
                == *x
        })
        .unwrap();

    let winner = if outcome_pos % 2 == 0 {
        OFFER_PARTY
    } else {
        ACCEPT_PARTY
    };

    let win_inscriptions = get_inscriptions(winner);

    let inscription = win_inscriptions
        .iter()
        .find(|x| x.inscription == inscription.inscription)
        .expect("To find the inscription");
    let outpoint = location_string_to_outpoint(&inscription.location);
    let tx = sink_rpc.get_raw_transaction(&outpoint.txid, None).unwrap();
    assert_eq!(DEFAULT_POSTAGE + TOTAL_COLLATERAL, tx.output[0].value);
    assert_eq!(1, tx.output.len());
}

#[test]
#[ignore]
fn ordinal_numerical_test() {
    let outcome_descriptor = get_numerical_ord_outcome_descriptor();
    let (mut alice_manager, mut bob_manager, sink_rpc, inscription, test_params) =
        init(&outcome_descriptor);

    execute_contract(
        &mut alice_manager,
        &mut bob_manager,
        &sink_rpc,
        &test_params,
    );

    mocks::mock_time::set_time((EVENT_MATURITY as u64) + 1);

    alice_manager.periodic_check().unwrap();

    generate_blocks(&sink_rpc, 1);

    let outcome = u64::from_str_radix(
        &test_params.oracles[0]
            .get_attestation(EVENT_ID)
            .unwrap()
            .outcomes
            .join(""),
        2,
    )
    .unwrap();

    let winner = if let OrdOutcomeDescriptor::Numerical(n) = &outcome_descriptor {
        if n.to_offer_ranges
            .iter()
            .any(|(x, y)| outcome >= *x && outcome <= *y)
        {
            OFFER_PARTY
        } else {
            ACCEPT_PARTY
        }
    } else {
        unreachable!();
    };

    let win_inscriptions = get_inscriptions(winner);

    let _ = win_inscriptions
        .iter()
        .find(|x| x.inscription == inscription.inscription)
        .expect("To find the inscription");
    // let outpoint = location_string_to_outpoint(&inscription.location);
    // let tx = sink_rpc.get_raw_transaction(&outpoint.txid, None).unwrap();
    // assert_eq!(DEFAULT_POSTAGE + TOTAL_COLLATERAL, tx.output[0].value);
    // assert_eq!(1, tx.output.len());
}

fn init(
    outcome_descriptor: &OrdOutcomeDescriptor,
) -> (
    TestManager,
    TestManager,
    Client,
    InscriptionsOutput,
    TestParams,
) {
    create_ordinal_wallet(OFFER_PARTY);
    create_ordinal_wallet(ACCEPT_PARTY);
    create_ordinal_wallet(SINK);
    let (alice_rpc, bob_rpc, sink_rpc) = init_clients();
    inscribe_logo(OFFER_PARTY);
    generate_blocks(&sink_rpc, 1);
    let mut inscriptions = get_inscriptions(OFFER_PARTY);
    let mut inscriptions_outpoints = inscriptions
        .iter()
        .map(|x| location_string_to_outpoint(&x.location))
        .collect::<Vec<_>>();
    inscriptions_outpoints.sort();
    inscriptions_outpoints.dedup();

    let inscription = inscriptions.remove(0);

    let sat_point_data = inscription.location.split(":").collect::<Vec<_>>();
    let sat_point = SatPoint {
        outpoint: OutPoint {
            txid: sat_point_data[0].parse().unwrap(),
            vout: sat_point_data[1].parse().unwrap(),
        },
        offset: sat_point_data[2].parse().unwrap(),
    };

    let ordinal_tx = sink_rpc
        .get_raw_transaction(&sat_point.outpoint.txid, None)
        .unwrap();

    let alice_store = Arc::new(mocks::memory_storage_provider::MemoryStorage::new());
    let bob_store = Arc::new(mocks::memory_storage_provider::MemoryStorage::new());
    let mock_time = Arc::new(mocks::mock_time::MockTime {});
    mocks::mock_time::set_time((EVENT_MATURITY as u64) - 1);

    let mut alice_oracles = HashMap::with_capacity(1);
    let mut bob_oracles = HashMap::with_capacity(1);

    let test_params = get_ord_test_params(1, 1, sat_point, &ordinal_tx, outcome_descriptor);

    for oracle in &test_params.oracles {
        let oracle = Arc::new(oracle.clone());
        alice_oracles.insert(oracle.get_public_key(), Arc::clone(&oracle));
        bob_oracles.insert(oracle.get_public_key(), Arc::clone(&oracle));
    }

    let alice_core_client = Arc::new(BitcoinCoreProvider::new_from_rpc_client(alice_rpc).unwrap());
    let bob_core_client = Arc::new(BitcoinCoreProvider::new_from_rpc_client(bob_rpc).unwrap());

    let alice_manager = Manager::new(
        Arc::clone(&alice_core_client),
        Arc::clone(&alice_core_client),
        alice_store,
        alice_oracles,
        Arc::clone(&mock_time),
        Arc::clone(&alice_core_client),
    )
    .unwrap();

    let bob_manager = Manager::new(
        Arc::clone(&bob_core_client),
        Arc::clone(&bob_core_client),
        bob_store,
        bob_oracles,
        Arc::clone(&mock_time),
        Arc::clone(&bob_core_client),
    )
    .unwrap();

    (
        alice_manager,
        bob_manager,
        sink_rpc,
        inscription,
        test_params,
    )
}

fn execute_contract(
    alice_manager: &mut TestManager,
    bob_manager: &mut TestManager,
    sink_rpc: &Client,
    test_params: &TestParams,
) {
    let dummy_pubkey = "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
        .parse()
        .unwrap();

    let offer = alice_manager
        .send_offer(&test_params.contract_input, dummy_pubkey)
        .unwrap();
    let temporary_contract_id = offer.temporary_contract_id;

    bob_manager
        .on_dlc_message(&Message::Offer(offer), dummy_pubkey)
        .unwrap();

    let (_contract_id, _, accept_msg) = bob_manager
        .accept_contract_offer(&temporary_contract_id)
        .expect("Error accepting contract offer");

    let sign = alice_manager
        .on_dlc_message(&Message::Accept(accept_msg), dummy_pubkey)
        .unwrap()
        .unwrap();

    bob_manager.on_dlc_message(&sign, dummy_pubkey).unwrap();

    generate_blocks(&sink_rpc, 10);
}

fn location_string_to_outpoint(location: &str) -> OutPoint {
    let split_location: Vec<_> = location.split(":").collect();
    OutPoint {
        txid: split_location[0].parse().unwrap(),
        vout: split_location[1].parse().unwrap(),
    }
}
