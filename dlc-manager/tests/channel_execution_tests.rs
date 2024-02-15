#[macro_use]
mod test_utils;

use bitcoin::Amount;
use bitcoin_test_utils::rpc_helpers::init_clients;
use bitcoincore_rpc::RpcApi;
use dlc_manager::contract::contract_input::ContractInput;
use dlc_manager::manager::Manager;
use dlc_manager::{channel::Channel, contract::Contract, Blockchain, Oracle, Storage, Wallet};
use dlc_manager::{ContractId, DlcChannelId};
use dlc_messages::{ChannelMessage, Message};
use electrs_blockchain_provider::ElectrsBlockchainProvider;
use lightning::util::ser::Writeable;
use mocks::memory_storage_provider::MemoryStorage;
use mocks::mock_oracle_provider::MockOracle;
use mocks::mock_time::MockTime;
use secp256k1_zkp::rand::{thread_rng, RngCore};
use secp256k1_zkp::EcdsaAdaptorSignature;
use simple_wallet::SimpleWallet;
use test_utils::{get_enum_test_params, TestParams};

use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, sync_channel},
        Arc, Mutex,
    },
};

use crate::test_utils::{refresh_wallet, EVENT_MATURITY};

type DlcParty = Arc<
    Mutex<
        Manager<
            Arc<SimpleWallet<Arc<ElectrsBlockchainProvider>, Arc<MemoryStorage>>>,
            Arc<ElectrsBlockchainProvider>,
            Arc<MemoryStorage>,
            Arc<MockOracle>,
            Arc<MockTime>,
            Arc<ElectrsBlockchainProvider>,
        >,
    >,
>;

fn get_established_channel_contract_id(
    dlc_party: &DlcParty,
    channel_id: &DlcChannelId,
) -> ContractId {
    let channel = dlc_party
        .lock()
        .unwrap()
        .get_store()
        .get_channel(channel_id)
        .unwrap()
        .unwrap();
    if let Channel::Signed(s) = channel {
        return s.get_contract_id().expect("to have a contract id");
    }

    panic!("Invalid channel state {:?}.", channel);
}

fn alter_adaptor_sig(input: &EcdsaAdaptorSignature) -> EcdsaAdaptorSignature {
    let mut copy = input.as_ref().to_vec();
    let i = thread_rng().next_u32() as usize % secp256k1_zkp::ffi::ECDSA_ADAPTOR_SIGNATURE_LENGTH;
    copy[i] = copy[i].checked_add(1).unwrap_or(0);
    EcdsaAdaptorSignature::from_slice(&copy).expect("to be able to create an adaptor signature")
}

/// We wrap updating the state of the chain monitor and calling the
/// `Manager::periodic_check` because the latter will only be aware of
/// newly confirmed transactions if the former processes new blocks.
fn periodic_check(dlc_party: DlcParty) {
    let dlc_manager = dlc_party.lock().unwrap();

    dlc_manager.periodic_chain_monitor().unwrap();
    dlc_manager.periodic_check().unwrap();
}

#[derive(Eq, PartialEq, Clone)]
enum TestPath {
    Close,
    BadAcceptBufferAdaptorSignature,
    BadSignBufferAdaptorSignature,
    SettleClose,
    BufferCheat,
    RenewedClose,
    SettleCheat,
    CollaborativeClose{
        accept_own_offer: bool
    },
    SettleRenewSettle,
    SettleOfferTimeout,
    SettleAcceptTimeout,
    SettleConfirmTimeout,
    SettleReject,
    SettleRace,
    RenewOfferTimeout,
    RenewAcceptTimeout,
    RenewConfirmTimeout,
    RenewFinalizeTimeout,
    RenewReject,
    RenewRace,
    RenewEstablishedClose,
    CancelOffer,
}

#[test]
#[ignore]
fn channel_established_close_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::Close);
}

#[test]
#[ignore]
fn channel_bad_accept_buffer_adaptor_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::BadAcceptBufferAdaptorSignature,
    );
}

#[test]
#[ignore]
fn channel_bad_sign_buffer_adaptor_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::BadSignBufferAdaptorSignature,
    );
}

#[test]
#[ignore]
fn channel_settled_close_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::SettleClose);
}

#[test]
#[ignore]
fn channel_punish_buffer_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::BufferCheat);
}

#[test]
#[ignore]
fn channel_renew_close_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::RenewedClose);
}

#[test]
#[ignore]
fn channel_renew_established_close_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::RenewEstablishedClose,
    );
}

#[test]
#[ignore]
fn channel_settle_cheat_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::SettleCheat);
}

#[test]
#[ignore]
fn channel_collaborative_close_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::CollaborativeClose{ accept_own_offer: false},
    );
}

#[test]
#[ignore]
fn channel_collaborative_close_own_offer_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::CollaborativeClose{ accept_own_offer: true},
    );
}

#[test]
#[ignore]
fn channel_settle_renew_settle_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::SettleRenewSettle,
    );
}

#[test]
#[ignore]
fn channel_settle_offer_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::SettleOfferTimeout,
    );
}

#[test]
#[ignore]
fn channel_settle_accept_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::SettleAcceptTimeout,
    );
}

#[test]
#[ignore]
fn channel_settle_confirm_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::SettleConfirmTimeout,
    );
}

#[test]
#[ignore]
fn channel_settle_reject_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::SettleReject);
}

#[test]
#[ignore]
fn channel_settle_race_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::SettleRace);
}

#[test]
#[ignore]
fn channel_renew_offer_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::RenewOfferTimeout,
    );
}

#[test]
#[ignore]
fn channel_renew_accept_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::RenewAcceptTimeout,
    );
}

#[test]
#[ignore]
fn channel_renew_confirm_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::RenewConfirmTimeout,
    );
}

#[test]
#[ignore]
fn channel_renew_finalize_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::RenewFinalizeTimeout,
    );
}

#[test]
#[ignore]
fn channel_renew_reject_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::RenewReject);
}

#[test]
#[ignore]
fn channel_renew_race_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::RenewRace);
}

#[test]
#[ignore]
fn channel_offer_reject_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::CancelOffer);
}

fn channel_execution_test(test_params: TestParams, path: TestPath) {
    env_logger::init();
    let (alice_send, bob_receive) = channel::<Option<Message>>();
    let (bob_send, alice_receive) = channel::<Option<Message>>();
    let (alice_sync_send, alice_sync_receive) = sync_channel::<()>(0);
    let (bob_sync_send, bob_sync_receive) = sync_channel::<()>(0);
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
            Arc::clone(&bob_store),
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
    let msg_filter = move |msg| {
        if let TestPath::SettleAcceptTimeout = path_copy {
            if let Message::Channel(ChannelMessage::SettleConfirm(_)) = msg {
                return None;
            }
        }
        if let TestPath::SettleConfirmTimeout = path_copy {
            if let Message::Channel(ChannelMessage::SettleFinalize(_)) = msg {
                return None;
            }
        }
        if let TestPath::RenewAcceptTimeout = path_copy {
            if let Message::Channel(ChannelMessage::RenewConfirm(_)) = msg {
                return None;
            }
        }
        if let TestPath::RenewConfirmTimeout = path_copy {
            if let Message::Channel(ChannelMessage::RenewFinalize(_)) = msg {
                return None;
            }
        }
        if let TestPath::RenewFinalizeTimeout = path_copy {
            if let Message::Channel(ChannelMessage::RenewRevoke(_)) = msg {
                return None;
            }
        }
        Some(msg)
    };

    let msg_filter_copy = msg_filter.clone();
    let path_copy = path.clone();
    let alter_sign = move |msg| match msg {
        Message::Channel(ChannelMessage::Sign(mut sign_channel)) => {
            if path_copy == TestPath::BadSignBufferAdaptorSignature {
                sign_channel.buffer_adaptor_signature =
                    alter_adaptor_sig(&sign_channel.buffer_adaptor_signature);
            }
            Some(Message::Channel(ChannelMessage::Sign(sign_channel)))
        }
        _ => msg_filter_copy(msg),
    };

    let alice_handle = receive_loop!(
        alice_receive,
        alice_manager_loop,
        alice_send_loop,
        alice_expect_error_loop,
        alice_sync_send,
        msg_filter,
        |msg| msg
    );

    let bob_handle = receive_loop!(
        bob_receive,
        bob_manager_loop,
        bob_send_loop,
        bob_expect_error_loop,
        bob_sync_send,
        alter_sign,
        |msg| msg
    );

    let offer_msg = bob_manager_send
        .lock()
        .unwrap()
        .offer_channel(
            &test_params.contract_input,
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
                .parse()
                .unwrap(),
            None
        )
        .expect("Send offer error");

    let temporary_channel_id = offer_msg.temporary_channel_id;
    bob_send
        .send(Some(Message::Channel(ChannelMessage::Offer(offer_msg))))
        .unwrap();

    assert_channel_state!(bob_manager_send, temporary_channel_id, Offered);

    alice_sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(alice_manager_send, temporary_channel_id, Offered);

    if let TestPath::CancelOffer = path {
        let (reject_msg, _) = alice_manager_send.lock().unwrap().reject_channel(&temporary_channel_id).expect("Error rejecting contract offer");
        assert_channel_state!(alice_manager_send, temporary_channel_id, Cancelled);
        alice_send
            .send(Some(Message::Channel(ChannelMessage::Reject(reject_msg))))
            .unwrap();

        bob_sync_receive.recv().expect("Error synchronizing");
        assert_channel_state!(bob_manager_send, temporary_channel_id, Cancelled);
        return;
    }

    let (mut accept_msg, channel_id, contract_id, _) = alice_manager_send
        .lock()
        .unwrap()
        .accept_channel(&temporary_channel_id)
        .expect("Error accepting contract offer");
    assert_channel_state!(alice_manager_send, channel_id, Accepted);

    match path {
        TestPath::BadAcceptBufferAdaptorSignature => {
            accept_msg.buffer_adaptor_signature =
                alter_adaptor_sig(&accept_msg.buffer_adaptor_signature);
            bob_expect_error.store(true, Ordering::Relaxed);
            alice_send
                .send(Some(Message::Channel(ChannelMessage::Accept(accept_msg))))
                .unwrap();
            bob_sync_receive.recv().expect("Error synchronizing");
            assert_channel_state!(bob_manager_send, temporary_channel_id, FailedAccept);
        }
        TestPath::BadSignBufferAdaptorSignature => {
            alice_expect_error.store(true, Ordering::Relaxed);
            alice_send
                .send(Some(Message::Channel(ChannelMessage::Accept(accept_msg))))
                .unwrap();
            // Bob receives accept message
            bob_sync_receive.recv().expect("Error synchronizing");
            // Alice receives sign message
            alice_sync_receive.recv().expect("Error synchronizing");
            assert_channel_state!(alice_manager_send, channel_id, FailedSign);
        }
        _ => {
            alice_send
                .send(Some(Message::Channel(ChannelMessage::Accept(accept_msg))))
                .unwrap();
            bob_sync_receive.recv().expect("Error synchronizing");

            assert_channel_state!(bob_manager_send, channel_id, Signed, Established);

            alice_sync_receive.recv().expect("Error synchronizing");

            assert_channel_state!(alice_manager_send, channel_id, Signed, Established);

            generate_blocks(6);

            mocks::mock_time::set_time((EVENT_MATURITY as u64) + 1);

            periodic_check(alice_manager_send.clone());

            periodic_check(bob_manager_send.clone());

            assert_contract_state!(alice_manager_send, contract_id, Confirmed);
            assert_contract_state!(bob_manager_send, contract_id, Confirmed);

            // Select the first one to close or refund randomly
            let (first, first_send, first_receive, second, second_send, second_receive) =
                if thread_rng().next_u32() % 2 == 0 {
                    (
                        alice_manager_send,
                        &alice_send,
                        &alice_sync_receive,
                        bob_manager_send,
                        &bob_send,
                        &bob_sync_receive,
                    )
                } else {
                    (
                        bob_manager_send,
                        &bob_send,
                        &bob_sync_receive,
                        alice_manager_send,
                        &alice_send,
                        &alice_sync_receive,
                    )
                };

            match path {
                TestPath::Close => {
                    close_established_channel(first, second, channel_id, &generate_blocks);
                }
                TestPath::CollaborativeClose { accept_own_offer } => {
                    collaborative_close(
                        first,
                        first_send,
                        second,
                        channel_id,
                        second_receive,
                        &generate_blocks,
                        accept_own_offer
                    );
                }
                TestPath::SettleOfferTimeout
                | TestPath::SettleAcceptTimeout
                | TestPath::SettleConfirmTimeout => {
                    settle_timeout(
                        first,
                        first_send,
                        first_receive,
                        second,
                        second_send,
                        second_receive,
                        channel_id,
                        path,
                    );
                }
                TestPath::SettleReject => {
                    settle_reject(
                        first,
                        first_send,
                        first_receive,
                        second,
                        second_send,
                        second_receive,
                        channel_id,
                    );
                }
                TestPath::SettleRace => {
                    settle_race(
                        first,
                        first_send,
                        first_receive,
                        second,
                        second_send,
                        second_receive,
                        channel_id,
                    );
                }
                _ => {
                    // Shuffle positions
                    let (first, first_send, first_receive, second, second_send, second_receive) =
                        if thread_rng().next_u32() % 2 == 0 {
                            (
                                first,
                                first_send,
                                first_receive,
                                second,
                                second_send,
                                second_receive,
                            )
                        } else {
                            (
                                second,
                                second_send,
                                second_receive,
                                first,
                                first_send,
                                first_receive,
                            )
                        };

                    first.lock().unwrap().get_store().save();

                    if let TestPath::RenewEstablishedClose = path {
                    } else {
                        settle_channel(
                            first.clone(),
                            first_send,
                            first_receive,
                            second.clone(),
                            second_send,
                            second_receive,
                            channel_id,
                        );
                    }

                    match path {
                        TestPath::SettleClose => {
                            let closer = if thread_rng().next_u32() % 2 == 0 {
                                first
                            } else {
                                second
                            };

                            closer
                                .lock()
                                .unwrap()
                                .force_close_channel(&channel_id, None)
                                .expect("to be able to unilaterally close the channel.");
                        }
                        TestPath::BufferCheat => {
                            cheat_punish(first, second, channel_id, &generate_blocks, true);
                        }
                        TestPath::RenewOfferTimeout
                        | TestPath::RenewAcceptTimeout
                        | TestPath::RenewConfirmTimeout
                        | TestPath::RenewFinalizeTimeout => {
                            renew_timeout(
                                first,
                                first_send,
                                first_receive,
                                second,
                                second_send,
                                second_receive,
                                channel_id,
                                &test_params.contract_input,
                                path,
                                &generate_blocks,
                            );
                        }
                        TestPath::RenewReject => {
                            renew_reject(
                                first,
                                first_send,
                                first_receive,
                                second,
                                second_send,
                                second_receive,
                                channel_id,
                                &test_params.contract_input,
                            );
                        }
                        TestPath::RenewRace => {
                            renew_race(
                                first,
                                first_send,
                                first_receive,
                                second,
                                second_send,
                                second_receive,
                                channel_id,
                                &test_params.contract_input,
                            );
                        }
                        TestPath::RenewedClose
                        | TestPath::SettleCheat
                        | TestPath::RenewEstablishedClose => {
                            first.lock().unwrap().get_store().save();

                            let check_prev_contract_close =
                                if let TestPath::RenewEstablishedClose = path {
                                    true
                                } else {
                                    false
                                };

                            renew_channel(
                                first.clone(),
                                first_send,
                                first_receive,
                                second.clone(),
                                second_send,
                                second_receive,
                                channel_id,
                                &test_params.contract_input,
                                check_prev_contract_close,
                            );

                            if let TestPath::RenewedClose = path {
                                close_established_channel(
                                    first,
                                    second,
                                    channel_id,
                                    &generate_blocks,
                                );
                            } else if let TestPath::SettleCheat = path {
                                cheat_punish(first, second, channel_id, &generate_blocks, false);
                            }
                        }
                        TestPath::SettleRenewSettle => {
                            renew_channel(
                                first.clone(),
                                first_send,
                                first_receive,
                                second.clone(),
                                second_send,
                                second_receive,
                                channel_id,
                                &test_params.contract_input,
                                false,
                            );

                            settle_channel(
                                first,
                                first_send,
                                first_receive,
                                second,
                                second_send,
                                second_receive,
                                channel_id,
                            );
                        }
                        _ => (),
                    }
                }
            }
        }
    }

    alice_send.send(None).unwrap();
    bob_send.send(None).unwrap();

    alice_handle.join().unwrap();
    bob_handle.join().unwrap();
}

fn close_established_channel<F>(
    first: DlcParty,
    second: DlcParty,
    channel_id: DlcChannelId,
    generate_blocks: &F,
) where
    F: Fn(u64),
{
    first
        .lock()
        .unwrap()
        .force_close_channel(&channel_id, None)
        .expect("to be able to unilaterally close.");
    assert_channel_state!(first, channel_id, Signed, Closing);

    let contract_id = get_established_channel_contract_id(&first, &channel_id);

    periodic_check(first.clone());

    let wait = dlc_manager::manager::CET_NSEQUENCE;

    generate_blocks(10);

    periodic_check(second.clone());

    assert_channel_state!(second, channel_id, Signed, Closing);

    periodic_check(first.clone());

    // Should not have changed state before the CET is spendable.
    assert_channel_state!(first, channel_id, Signed, Closing);

    generate_blocks(wait as u64 - 9);

    periodic_check(first.clone());

    assert_channel_state!(first, channel_id, Closed);

    assert_contract_state!(first, contract_id, PreClosed);

    generate_blocks(1);

    periodic_check(second.clone());

    assert_channel_state!(second, channel_id, CounterClosed);
    assert_contract_state!(second, contract_id, PreClosed);

    generate_blocks(5);

    periodic_check(first.clone());
    periodic_check(second.clone());

    assert_contract_state!(first, contract_id, Closed);
    assert_contract_state!(second, contract_id, Closed);
}

fn cheat_punish<F: Fn(u64)>(
    first: DlcParty,
    second: DlcParty,
    channel_id: DlcChannelId,
    generate_blocks: &F,
    established: bool,
) {
    first.lock().unwrap().get_store().rollback();

    if established {
        first
            .lock()
            .unwrap()
            .force_close_channel(&channel_id, None)
            .expect("the cheater to be able to close on established");
    } else {
        first
            .lock()
            .unwrap()
            .force_close_channel(&channel_id, None)
            .expect("the cheater to be able to close on settled");
    }

    generate_blocks(2);

    periodic_check(second.clone());

    assert_channel_state!(second, channel_id, ClosedPunished);
}

fn settle_channel(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    first_receive: &Receiver<()>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    second_receive: &Receiver<()>,
    channel_id: DlcChannelId,
) {
    let (settle_offer, _) = first
        .lock()
        .unwrap()
        .settle_offer(&channel_id, test_utils::ACCEPT_COLLATERAL, None)
        .expect("to be able to offer a settlement of the contract.");

    first_send
        .send(Some(Message::Channel(ChannelMessage::SettleOffer(
            settle_offer,
        ))))
        .unwrap();

    second_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, SettledOffered);

    assert_channel_state!(second, channel_id, Signed, SettledReceived);

    let (settle_accept, _) = second
        .lock()
        .unwrap()
        .accept_settle_offer(&channel_id)
        .expect("to be able to accept a settlement offer");

    second_send
        .send(Some(Message::Channel(ChannelMessage::SettleAccept(
            settle_accept,
        ))))
        .unwrap();

    // Process Accept
    first_receive.recv().expect("Error synchronizing");
    // Process Confirm
    second_receive.recv().expect("Error synchronizing");
    // Process Finalize
    first_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, Settled);

    assert_channel_state!(second, channel_id, Signed, Settled);
}

fn settle_reject(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    first_receive: &Receiver<()>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    second_receive: &Receiver<()>,
    channel_id: DlcChannelId,
) {
    let (settle_offer, _) = first
        .lock()
        .unwrap()
        .settle_offer(&channel_id, test_utils::ACCEPT_COLLATERAL, None)
        .expect("to be able to reject a settlement of the contract.");

    first_send
        .send(Some(Message::Channel(ChannelMessage::SettleOffer(
            settle_offer,
        ))))
        .unwrap();

    second_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, SettledOffered);

    assert_channel_state!(second, channel_id, Signed, SettledReceived);

    let (settle_reject, _) = second
        .lock()
        .unwrap()
        .reject_settle_offer(&channel_id)
        .expect("to be able to reject a settlement offer");

    second_send
        .send(Some(Message::Channel(ChannelMessage::Reject(
            settle_reject,
        ))))
        .unwrap();

    first_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, Established);

    assert_channel_state!(second, channel_id, Signed, Established);
}

fn settle_race(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    first_receive: &Receiver<()>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    second_receive: &Receiver<()>,
    channel_id: DlcChannelId,
) {
    let (settle_offer, _) = first
        .lock()
        .unwrap()
        .settle_offer(&channel_id, test_utils::ACCEPT_COLLATERAL, None)
        .expect("to be able to offer a settlement of the contract.");

    let (settle_offer_2, _) = second
        .lock()
        .unwrap()
        .settle_offer(&channel_id, test_utils::ACCEPT_COLLATERAL, None)
        .expect("to be able to offer a settlement of the contract.");

    first_send
        .send(Some(Message::Channel(ChannelMessage::SettleOffer(
            settle_offer,
        ))))
        .unwrap();

    second_send
        .send(Some(Message::Channel(ChannelMessage::SettleOffer(
            settle_offer_2,
        ))))
        .unwrap();

    // Process 2 offers + 2 rejects
    first_receive
        .recv_timeout(Duration::from_secs(2))
        .expect("Error synchronizing 1");
    second_receive
        .recv_timeout(Duration::from_secs(2))
        .expect("Error synchronizing 2");
    first_receive
        .recv_timeout(Duration::from_secs(2))
        .expect("Error synchronizing 3");
    second_receive
        .recv_timeout(Duration::from_secs(2))
        .expect("Error synchronizing 4");

    assert_channel_state!(first, channel_id, Signed, Established);

    assert_channel_state!(second, channel_id, Signed, Established);
}

fn renew_channel(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    first_receive: &Receiver<()>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    second_receive: &Receiver<()>,
    channel_id: DlcChannelId,
    contract_input: &ContractInput,
    check_prev_contract_close: bool,
) {
    let prev_contract_id = if check_prev_contract_close {
        Some(get_established_channel_contract_id(&first, &channel_id))
    } else {
        None
    };

    let (renew_offer, _) = first
        .lock()
        .unwrap()
        .renew_offer(&channel_id, test_utils::ACCEPT_COLLATERAL, contract_input, None)
        .expect("to be able to renew channel contract");

    first_send
        .send(Some(Message::Channel(ChannelMessage::RenewOffer(
            renew_offer,
        ))))
        .expect("to be able to send the renew offer");

    // Process Renew Offer
    second_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, RenewOffered);
    assert_channel_state!(second, channel_id, Signed, RenewOffered);

    let (accept_renew, _) = second
        .lock()
        .unwrap()
        .accept_renew_offer(&channel_id)
        .expect("to be able to accept the renewal");

    second_send
        .send(Some(Message::Channel(ChannelMessage::RenewAccept(
            accept_renew,
        ))))
        .expect("to be able to send the accept renew");

    // Process Renew Accept
    first_receive.recv().expect("Error synchronizing");
    assert_channel_state!(first, channel_id, Signed, RenewConfirmed);
    // Process Renew Confirm
    second_receive.recv().expect("Error synchronizing");
    // Process Renew Finalize
    first_receive.recv().expect("Error synchronizing");
    // Process Renew Revoke
    second_receive.recv().expect("Error synchronizing");

    if let Some(prev_contract_id) = prev_contract_id {
        assert_contract_state!(first, prev_contract_id, Closed);
        assert_contract_state!(second, prev_contract_id, Closed);
    }

    let new_contract_id = get_established_channel_contract_id(&first, &channel_id);

    assert_channel_state!(first, channel_id, Signed, Established);
    assert_contract_state!(first, new_contract_id, Confirmed);
    assert_channel_state!(second, channel_id, Signed, Established);
    assert_contract_state!(second, new_contract_id, Confirmed);
}

fn renew_reject(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    first_receive: &Receiver<()>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    second_receive: &Receiver<()>,
    channel_id: DlcChannelId,
    contract_input: &ContractInput,
) {
    let (renew_offer, _) = first
        .lock()
        .unwrap()
        .renew_offer(&channel_id, test_utils::ACCEPT_COLLATERAL, contract_input, None)
        .expect("to be able to renew channel contract");

    first_send
        .send(Some(Message::Channel(ChannelMessage::RenewOffer(
            renew_offer,
        ))))
        .expect("to be able to send the renew offer");

    // Process Renew Offer
    second_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, RenewOffered);
    assert_channel_state!(second, channel_id, Signed, RenewOffered);

    let (renew_reject, _) = second
        .lock()
        .unwrap()
        .reject_renew_offer(&channel_id)
        .expect("to be able to reject the renewal");

    second_send
        .send(Some(Message::Channel(ChannelMessage::Reject(renew_reject))))
        .expect("to be able to send the renew reject");

    // Process Renew Reject
    first_receive.recv().expect("Error synchronizing");
    assert_channel_state!(first, channel_id, Signed, Settled);
    assert_channel_state!(second, channel_id, Signed, Settled);
}

fn renew_race(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    first_receive: &Receiver<()>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    second_receive: &Receiver<()>,
    channel_id: DlcChannelId,
    contract_input: &ContractInput,
) {
    let (renew_offer, _) = first
        .lock()
        .unwrap()
        .renew_offer(&channel_id, test_utils::OFFER_COLLATERAL, contract_input, None)
        .expect("to be able to renew channel contract");

    let mut contract_input_2 = contract_input.clone();
    contract_input_2.accept_collateral = contract_input.offer_collateral;
    contract_input_2.offer_collateral = contract_input.accept_collateral;

    let (renew_offer_2, _) = second
        .lock()
        .unwrap()
        .renew_offer(&channel_id, test_utils::OFFER_COLLATERAL, &contract_input_2, None)
        .expect("to be able to renew channel contract");

    first_send
        .send(Some(Message::Channel(ChannelMessage::RenewOffer(
            renew_offer,
        ))))
        .expect("to be able to send the renew offer");

    second_send
        .send(Some(Message::Channel(ChannelMessage::RenewOffer(
            renew_offer_2,
        ))))
        .expect("to be able to send the renew offer");

    // Process 2 offers + 2 rejects
    first_receive
        .recv_timeout(Duration::from_secs(2))
        .expect("Error synchronizing 1");
    second_receive
        .recv_timeout(Duration::from_secs(2))
        .expect("Error synchronizing 2");
    first_receive
        .recv_timeout(Duration::from_secs(2))
        .expect("Error synchronizing 3");
    second_receive
        .recv_timeout(Duration::from_secs(2))
        .expect("Error synchronizing 4");

    assert_channel_state!(first, channel_id, Signed, Settled);
    assert_channel_state!(second, channel_id, Signed, Settled);
}

fn collaborative_close<F: Fn(u64)>(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    channel_id: DlcChannelId,
    sync_receive: &Receiver<()>,
    generate_blocks: &F,
    accept_own_offer: bool
) {
    let contract_id = get_established_channel_contract_id(&first, &channel_id);
    let close_offer = first
        .lock()
        .unwrap()
        .offer_collaborative_close(&channel_id, test_utils::ACCEPT_COLLATERAL, None)
        .expect("to be able to propose a collaborative close");
    first_send
        .send(Some(Message::Channel(
            ChannelMessage::CollaborativeCloseOffer(close_offer),
        )))
        .expect("to be able to send collaborative close");
    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, CollaborativeCloseOffered);
    assert_channel_state!(second, channel_id, Signed, CollaborativeCloseOffered);

    if accept_own_offer {
        if let Err(e) = first.lock().unwrap().accept_collaborative_close(&channel_id) {
            assert_eq!("Invalid state: Cannot accept own collaborative close offer", e.to_string());
        } else {
            panic!("It should not be possible to accept own collaborative close offer");
        }

        return;
    }


    second
        .lock()
        .unwrap()
        .accept_collaborative_close(&channel_id)
        .expect("to be able to accept a collaborative close");

    assert_channel_state!(second, channel_id, CollaborativelyClosed);
    assert_contract_state!(second, contract_id, Closed);

    generate_blocks(2);

    periodic_check(first.clone());

    assert_channel_state!(first, channel_id, CollaborativelyClosed);
    assert_contract_state!(first, contract_id, Closed);
}

fn renew_timeout<F: Fn(u64)>(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    first_receive: &Receiver<()>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    second_receive: &Receiver<()>,
    channel_id: DlcChannelId,
    contract_input: &ContractInput,
    path: TestPath,
    generate_blocks: &F,
) {
    {
        let (renew_offer, _) = first
            .lock()
            .unwrap()
            .renew_offer(&channel_id, test_utils::ACCEPT_COLLATERAL, contract_input, None)
            .expect("to be able to offer a settlement of the contract.");

        first_send
            .send(Some(Message::Channel(ChannelMessage::RenewOffer(
                renew_offer,
            ))))
            .unwrap();

        second_receive.recv().expect("Error synchronizing");

        if let TestPath::RenewOfferTimeout = path {
            mocks::mock_time::set_time(
                (EVENT_MATURITY as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
            );
            periodic_check(first.clone());

            assert_channel_state!(first, channel_id, Closed);
        } else {
            let (renew_accept, _) = second
                .lock()
                .unwrap()
                .accept_renew_offer(&channel_id)
                .expect("to be able to accept a settlement offer");

            second_send
                .send(Some(Message::Channel(ChannelMessage::RenewAccept(
                    renew_accept,
                ))))
                .unwrap();

            // Process Accept
            first_receive.recv().expect("Error synchronizing");

            if let TestPath::RenewAcceptTimeout = path {
                mocks::mock_time::set_time(
                    (EVENT_MATURITY as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
                );
                periodic_check(second.clone());

                assert_channel_state!(second, channel_id, Closed);
            } else if let TestPath::RenewConfirmTimeout = path {
                // Process Confirm
                second_receive.recv().expect("Error synchronizing");
                mocks::mock_time::set_time(
                    (EVENT_MATURITY as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
                );
                periodic_check(first.clone());

                assert_channel_state!(first, channel_id, Closed);
            } else if let TestPath::RenewFinalizeTimeout = path {
                //Process confirm
                second_receive.recv().expect("Error synchronizing");
                // Process Finalize
                first_receive.recv().expect("Error synchronizing");
                mocks::mock_time::set_time(
                    (EVENT_MATURITY as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
                );
                periodic_check(second.clone());
                generate_blocks(289);
                periodic_check(second.clone());

                assert_channel_state!(second, channel_id, Closed);
            }
        }
    }
}

fn settle_timeout(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    first_receive: &Receiver<()>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    second_receive: &Receiver<()>,
    channel_id: DlcChannelId,
    path: TestPath,
) {
    let (settle_offer, _) = first
        .lock()
        .unwrap()
        .settle_offer(&channel_id, test_utils::ACCEPT_COLLATERAL, None)
        .expect("to be able to offer a settlement of the contract.");

    first_send
        .send(Some(Message::Channel(ChannelMessage::SettleOffer(
            settle_offer,
        ))))
        .unwrap();

    second_receive.recv().expect("Error synchronizing");

    if let TestPath::SettleOfferTimeout = path {
        mocks::mock_time::set_time(
            (EVENT_MATURITY as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
        );
        periodic_check(first.clone());

        assert_channel_state!(first, channel_id, Signed, Closing);
    } else {
        let (settle_accept, _) = second
            .lock()
            .unwrap()
            .accept_settle_offer(&channel_id)
            .expect("to be able to accept a settlement offer");

        second_send
            .send(Some(Message::Channel(ChannelMessage::SettleAccept(
                settle_accept,
            ))))
            .unwrap();

        // Process Accept
        first_receive.recv().expect("Error synchronizing");

        if let TestPath::SettleAcceptTimeout = path {
            mocks::mock_time::set_time(
                (EVENT_MATURITY as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
            );
            periodic_check(second.clone());

            second
                .lock()
                .unwrap()
                .get_store()
                .get_channel(&channel_id)
                .unwrap();
            assert_channel_state!(second, channel_id, Signed, Closing);
        } else if let TestPath::SettleConfirmTimeout = path {
            // Process Confirm
            second_receive.recv().expect("Error synchronizing");
            mocks::mock_time::set_time(
                (EVENT_MATURITY as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
            );
            periodic_check(first.clone());

            assert_channel_state!(first, channel_id, Signed, Closing);
        }
    }
}
