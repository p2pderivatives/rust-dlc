extern crate bitcoin_rpc_provider;
extern crate bitcoin_test_utils;
extern crate bitcoincore_rpc;
extern crate bitcoincore_rpc_json;
extern crate dlc_manager;

#[macro_use]
#[allow(dead_code)]
mod test_utils;

use bitcoin::Amount;
use dlc_manager::payout_curve::PayoutFunctionPiece;
use electrs_blockchain_provider::ElectrsBlockchainProvider;
use simple_wallet::SimpleWallet;
use test_utils::*;

use bitcoin_test_utils::rpc_helpers::init_clients;
use bitcoincore_rpc::RpcApi;
use dlc_manager::contract::{numerical_descriptor::DifferenceParams, Contract};
use dlc_manager::manager::Manager;
use dlc_manager::{Blockchain, Oracle, Storage, Wallet};
use dlc_messages::{AcceptDlc, OfferDlc, SignDlc};
use dlc_messages::{CetAdaptorSignatures, Message};
use lightning::ln::wire::Type;
use lightning::util::ser::Writeable;
use secp256k1_zkp::rand::{thread_rng, RngCore};
use secp256k1_zkp::{ecdsa::Signature, EcdsaAdaptorSignature};
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

macro_rules! periodic_check {
    ($d:expr, $id:expr, $p:ident) => {
        $d.lock()
            .unwrap()
            .periodic_check()
            .expect("Periodic check error");

        assert_contract_state!($d, $id, $p);
    };
}

fn numerical_common<F>(
    nb_oracles: usize,
    threshold: usize,
    payout_function_pieces_cb: F,
    difference_params: Option<DifferenceParams>,
) where
    F: Fn(usize) -> Vec<PayoutFunctionPiece>,
{
    let oracle_numeric_infos = get_same_num_digits_oracle_numeric_infos(nb_oracles);
    let with_diff = difference_params.is_some();
    let contract_descriptor = get_numerical_contract_descriptor(
        oracle_numeric_infos.clone(),
        payout_function_pieces_cb(*oracle_numeric_infos.nb_digits.iter().min().unwrap()),
        difference_params,
    );
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

fn numerical_polynomial_common(
    nb_oracles: usize,
    threshold: usize,
    difference_params: Option<DifferenceParams>,
) {
    numerical_common(
        nb_oracles,
        threshold,
        get_polynomial_payout_curve_pieces,
        difference_params,
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
    let contract_descriptor = get_numerical_contract_descriptor(
        oracle_numeric_infos.clone(),
        get_polynomial_payout_curve_pieces(oracle_numeric_infos.get_min_nb_digits()),
        difference_params,
    );

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

#[derive(Eq, PartialEq, Clone)]
enum TestPath {
    Close,
    Refund,
    BadAcceptCetSignature,
    BadAcceptRefundSignature,
    BadSignCetSignature,
    BadSignRefundSignature,
}

#[test]
#[ignore]
fn single_oracle_numerical_test() {
    numerical_polynomial_common(1, 1, None);
}

#[test]
#[ignore]
fn single_oracle_numerical_hyperbola_test() {
    numerical_common(1, 1, get_hyperbola_payout_curve_pieces, None);
}

#[test]
#[ignore]
fn three_of_three_oracle_numerical_test() {
    numerical_polynomial_common(3, 3, None);
}

#[test]
#[ignore]
fn two_of_five_oracle_numerical_test() {
    numerical_polynomial_common(5, 2, None);
}

#[test]
#[ignore]
fn three_of_three_oracle_numerical_with_diff_test() {
    numerical_polynomial_common(3, 3, Some(get_difference_params()));
}

#[test]
#[ignore]
fn two_of_five_oracle_numerical_with_diff_test() {
    numerical_polynomial_common(5, 2, Some(get_difference_params()));
}

#[test]
#[ignore]
fn three_of_five_oracle_numerical_with_diff_test() {
    numerical_polynomial_common(5, 3, Some(get_difference_params()));
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
    let (_, _, sink_rpc) = init_clients();

    let mut alice_oracles = HashMap::with_capacity(1);
    let mut bob_oracles = HashMap::with_capacity(1);

    for oracle in test_params.oracles {
        let oracle = Arc::new(oracle);
        alice_oracles.insert(oracle.get_public_key(), Arc::clone(&oracle));
        bob_oracles.insert(oracle.get_public_key(), Arc::clone(&oracle));
    }

    let alice_store = Arc::new(mocks::memory_storage_provider::MemoryStorage::new());
    let bob_store = Arc::new(mocks::memory_storage_provider::MemoryStorage::new());
    let mock_time = Arc::new(mocks::mock_time::MockTime {});
    mocks::mock_time::set_time((EVENT_MATURITY as u64) - 1);

    let electrs = Arc::new(ElectrsBlockchainProvider::new(
        "http://localhost:3004/".to_string(),
        bitcoin::Network::Regtest,
    ));

    let alice_wallet = Arc::new(SimpleWallet::new(
        electrs.clone(),
        alice_store.clone(),
        bitcoin::Network::Regtest,
    ));

    let bob_wallet = Arc::new(SimpleWallet::new(
        electrs.clone(),
        bob_store.clone(),
        bitcoin::Network::Regtest,
    ));

    let alice_fund_address = alice_wallet.get_new_address().unwrap();
    let bob_fund_address = bob_wallet.get_new_address().unwrap();

    sink_rpc
        .send_to_address(
            &alice_fund_address,
            Amount::from_btc(2.0).unwrap(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    sink_rpc
        .send_to_address(
            &bob_fund_address,
            Amount::from_btc(2.0).unwrap(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    let generate_blocks = |nb_blocks: u64| {
        let prev_blockchain_height = electrs.get_blockchain_height().unwrap();

        let sink_address = sink_rpc.get_new_address(None, None).expect("RPC Error");
        sink_rpc
            .generate_to_address(nb_blocks, &sink_address)
            .expect("RPC Error");

        // Wait for electrs to have processed the new blocks
        let mut cur_blockchain_height = prev_blockchain_height;
        while cur_blockchain_height < prev_blockchain_height + nb_blocks {
            std::thread::sleep(std::time::Duration::from_millis(200));
            cur_blockchain_height = electrs.get_blockchain_height().unwrap();
        }
    };

    generate_blocks(6);

    refresh_wallet(&alice_wallet, 200000000);
    refresh_wallet(&bob_wallet, 200000000);

    let alice_manager = Arc::new(Mutex::new(
        Manager::new(
            Arc::clone(&alice_wallet),
            Arc::clone(&electrs),
            alice_store,
            alice_oracles,
            Arc::clone(&mock_time),
            Arc::clone(&electrs),
        )
        .unwrap(),
    ));

    let alice_manager_loop = Arc::clone(&alice_manager);
    let alice_manager_send = Arc::clone(&alice_manager);

    let bob_manager = Arc::new(Mutex::new(
        Manager::new(
            Arc::clone(&bob_wallet),
            Arc::clone(&electrs),
            bob_store,
            bob_oracles,
            Arc::clone(&mock_time),
            Arc::clone(&electrs),
        )
        .unwrap(),
    ));

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
            Some(Message::Sign(sign_dlc))
        }
        _ => Some(msg),
    };

    let msg_callback = |msg: &Message| {
        if let Message::Sign(s) = msg {
            write_message("sign_message", s.clone());
        }
    };

    let alice_handle = receive_loop!(
        alice_receive,
        alice_manager_loop,
        alice_send_loop,
        alice_expect_error_loop,
        alice_sync_send,
        Some,
        msg_callback
    );

    let bob_handle = receive_loop!(
        bob_receive,
        bob_manager_loop,
        bob_send_loop,
        bob_expect_error_loop,
        bob_sync_send,
        alter_sign,
        msg_callback
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

            generate_blocks(6);

            periodic_check!(alice_manager_send, contract_id, Confirmed);
            periodic_check!(bob_manager_send, contract_id, Confirmed);

            mocks::mock_time::set_time((EVENT_MATURITY as u64) + 1);

            // Select the first one to close or refund randomly
            let (first, second) = if thread_rng().next_u32() % 2 == 0 {
                (alice_manager_send, bob_manager_send)
            } else {
                (bob_manager_send, alice_manager_send)
            };

            match path {
                TestPath::Close => {
                    periodic_check!(first, contract_id, PreClosed);

                    // Randomly check with or without having the CET mined
                    let case = thread_rng().next_u64() % 3;
                    if case == 2 {
                        // cet becomes fully confirmed to blockchain
                        generate_blocks(6);
                        periodic_check!(first, contract_id, Closed);
                        periodic_check!(second, contract_id, Closed);
                    } else if case == 1 {
                        // cet is not yet fully confirmed to blockchain
                        generate_blocks(1);
                        periodic_check!(first, contract_id, PreClosed);
                        periodic_check!(second, contract_id, PreClosed);
                    } else {
                        periodic_check!(first, contract_id, PreClosed);
                        periodic_check!(second, contract_id, PreClosed);
                    }
                }
                TestPath::Refund => {
                    periodic_check!(first, contract_id, Confirmed);

                    periodic_check!(second, contract_id, Confirmed);

                    mocks::mock_time::set_time(
                        ((EVENT_MATURITY + dlc_manager::manager::REFUND_DELAY) as u64) + 1,
                    );

                    generate_blocks(10);

                    periodic_check!(first, contract_id, Refunded);

                    // Randomly check with or without having the Refund mined.
                    if thread_rng().next_u32() % 2 == 0 {
                        generate_blocks(1);
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
