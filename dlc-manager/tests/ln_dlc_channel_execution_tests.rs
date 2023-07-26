#[macro_use]
mod test_utils;
mod console_logger;
mod custom_signer;

use std::{
    collections::HashMap,
    convert::TryInto,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use crate::test_utils::{
    get_enum_test_params_custom_collateral, refresh_wallet, TestParams, EVENT_MATURITY,
};
use bitcoin::{
    hashes::Hash, Address, Amount, Network, PackedLockTime, Script, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use bitcoin_bech32::WitnessProgram;
use bitcoin_test_utils::rpc_helpers::init_clients;
use bitcoincore_rpc::RpcApi;
use console_logger::ConsoleLogger;
use custom_signer::{CustomKeysManager, CustomSigner};
use dlc_manager::{
    channel::Channel,
    contract::Contract,
    manager::Manager,
    sub_channel_manager::SubChannelManager,
    subchannel::{SubChannel, SubChannelState},
    Blockchain, ChannelId, Oracle, Signer, Storage, Utxo, Wallet,
};
use dlc_messages::{
    sub_channel::{SubChannelAccept, SubChannelOffer},
    ChannelMessage, Message, SubChannelMessage,
};
use electrs_blockchain_provider::{ElectrsBlockchainProvider, OutSpendResp};
use lightning::{
    chain::{
        chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator},
        keysinterface::{EntropySource, KeysManager},
        BestBlock, Confirm,
    },
    ln::{
        channelmanager::{ChainParameters, PaymentId},
        peer_handler::{IgnoringMessageHandler, MessageHandler},
    },
    routing::{
        gossip::{NetworkGraph, NodeId},
        router::{DefaultRouter, RouteHop, RouteParameters},
        scoring::{ChannelUsage, Score},
    },
    util::{
        config::UserConfig,
        events::{Event, EventHandler, EventsProvider, PaymentPurpose},
        ser::Writeable,
    },
};
use lightning_persister::FilesystemPersister;
use lightning_transaction_sync::EsploraSyncClient;
use log::error;
use mocks::{
    memory_storage_provider::MemoryStorage,
    mock_blockchain::MockBlockchain,
    mock_oracle_provider::MockOracle,
    mock_time::{self, MockTime},
};
use secp256k1_zkp::{
    rand::{thread_rng, RngCore},
    Secp256k1,
};
use simple_wallet::SimpleWallet;
use simple_wallet::WalletStorage;

type ChainMonitor = lightning::chain::chainmonitor::ChainMonitor<
    CustomSigner,
    Arc<EsploraSyncClient<Arc<ConsoleLogger>>>,
    Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    Arc<ElectrsBlockchainProvider>,
    Arc<ConsoleLogger>,
    Arc<FilesystemPersister>,
>;

pub(crate) type ChannelManager = lightning::ln::channelmanager::ChannelManager<
    Arc<ChainMonitor>,
    Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    Arc<CustomKeysManager>,
    Arc<CustomKeysManager>,
    Arc<CustomKeysManager>,
    Arc<ElectrsBlockchainProvider>,
    Arc<
        DefaultRouter<
            Arc<NetworkGraph<Arc<ConsoleLogger>>>,
            Arc<ConsoleLogger>,
            Arc<Mutex<TestScorer>>,
        >,
    >,
    Arc<ConsoleLogger>,
>;

pub(crate) type PeerManager = lightning::ln::peer_handler::PeerManager<
    MockSocketDescriptor,
    Arc<DlcSubChannelManager>,
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<ConsoleLogger>,
    Arc<IgnoringMessageHandler>,
    Arc<CustomKeysManager>,
>;

type DlcChannelManager = Manager<
    Arc<SimpleWallet<Arc<ElectrsBlockchainProvider>, Arc<MemoryStorage>>>,
    Arc<ElectrsBlockchainProvider>,
    Arc<MemoryStorage>,
    Arc<MockOracle>,
    Arc<MockTime>,
    Arc<ElectrsBlockchainProvider>,
>;

type DlcSubChannelManager = SubChannelManager<
    Arc<SimpleWallet<Arc<ElectrsBlockchainProvider>, Arc<MemoryStorage>>>,
    Arc<ChannelManager>,
    Arc<MemoryStorage>,
    Arc<ElectrsBlockchainProvider>,
    Arc<MockOracle>,
    Arc<MockTime>,
    Arc<ElectrsBlockchainProvider>,
    Arc<DlcChannelManager>,
    CustomSigner,
>;

struct LnDlcParty {
    peer_manager: Arc<PeerManager>,
    channel_manager: Arc<ChannelManager>,
    chain_monitor: Arc<ChainMonitor>,
    keys_manager: Arc<CustomKeysManager>,
    logger: Arc<ConsoleLogger>,
    network_graph: NetworkGraph<Arc<ConsoleLogger>>,
    sub_channel_manager: Arc<DlcSubChannelManager>,
    dlc_manager: Arc<DlcChannelManager>,
    blockchain: Arc<ElectrsBlockchainProvider>,
    mock_blockchain: Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    wallet: Arc<SimpleWallet<Arc<ElectrsBlockchainProvider>, Arc<MemoryStorage>>>,
    persister: Arc<FilesystemPersister>,
    esplora_sync: Arc<EsploraSyncClient<Arc<ConsoleLogger>>>,
}

impl Drop for LnDlcParty {
    fn drop(&mut self) {
        let data_dir = self.persister.get_data_dir();
        std::fs::remove_dir_all(data_dir).unwrap();
    }
}

enum TestPath {
    EstablishedClose,
    RenewedClose,
    SettledClose,
    SettledRenewedClose,
    CheatPreSplitCommit,
    CheatPostSplitCommit,
    OffChainClosed,
    OffChainCloseOpenClose,
    SplitCheat,
    OfferRejected,
    CloseRejected,
    Reconnect,
    ReconnectReOfferAfterClose,
    DisconnectedForceClose,
    /// Force close triggered by the party who sent the subchannel offer.
    OfferedForceClose,
    /// Force close triggered by the party who received the subchannel offer.
    OfferedForceClose2,
    /// Force close triggered by the party who sent the subchannel offer, while the counterparty
    /// has accepted the offer (the offering party has not yet processed the accept message).
    AcceptedForceClose,
    /// Force close triggered by the party who accepted the subchannel offer (the counter party has
    /// not yet processed the accept message).
    AcceptedForceClose2,
    /// Force close triggered by the offer party, after processing the accept message from their
    /// counter party.
    ConfirmedForceClose,
    /// Force close triggered by the accept party, after their counter party processed the accepted
    /// message (but before they process the confirm message).
    ConfirmedForceClose2,
    /// Force close triggered by the offer party, after their counter party processed the confirm
    /// message (but before they process the finalize message).
    FinalizedForceClose,
    /// Force close triggered by the accept party, after processing the confirm message (but before
    /// their counter party has processed the finalize message).
    FinalizedForceClose2,
    /// Force close triggered by the party who offered to force close the channel, after their
    /// counter party received the offer.
    CloseOfferedForceClose,
    /// Force close triggered by the party who received the offer to force close the channel.
    CloseOfferedForceClose2,
    /// Force close triggered by the party who offered to force close the channel, after their
    /// counter party accepted the close offer, but before they processed the close accept message.
    CloseAcceptedForceClose,
    /// Force close triggered by the party who accepted the close offer, before their counter party
    /// processed the close offer message.
    CloseAcceptedForceClose2,
    /// Force close triggered by the party who offered to force close the channel, after they
    /// processed the close accept message.
    CloseConfirmedForceClose,
    /// Force close triggered by the party who accepted the close offer, after their counter party
    /// processed the close accept message.
    CloseConfirmedForceClose2,
    /// Force close triggered by the party who offered to force close the channel, after their
    /// counter party processed the close confirm message, but before they processed the close
    /// finalize message.
    CloseFinalizedForceClose,
}

impl LnDlcParty {
    fn update_to_chain_tip(&mut self) {
        let confirmables = vec![
            &*self.channel_manager as &(dyn Confirm + Sync + Send),
            &*self.chain_monitor as &(dyn Confirm + Sync + Send),
        ];

        self.esplora_sync.sync(confirmables).unwrap();
        self.sub_channel_manager.periodic_check();
        self.dlc_manager.periodic_check().unwrap();
    }

    fn process_events(&self) {
        self.peer_manager.process_events();
        self.channel_manager.process_pending_events(self);
        self.channel_manager.timer_tick_occurred();
        self.chain_monitor.process_pending_events(self);
    }
}

#[derive(Clone)]
struct MockSocketDescriptor {
    counter_peer_mng: Arc<PeerManager>,
    counter_descriptor: Option<Box<MockSocketDescriptor>>,
    id: u64,
}

impl std::hash::Hash for MockSocketDescriptor {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialEq for MockSocketDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for MockSocketDescriptor {}

impl MockSocketDescriptor {
    fn new(id: u64, counter_peer_mng: Arc<PeerManager>) -> Self {
        MockSocketDescriptor {
            counter_peer_mng,
            id,
            counter_descriptor: None,
        }
    }
}

impl lightning::ln::peer_handler::SocketDescriptor for MockSocketDescriptor {
    fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
        self.counter_peer_mng
            .clone()
            .read_event(self.counter_descriptor.as_mut().unwrap(), data)
            .unwrap();
        data.len()
    }

    fn disconnect_socket(&mut self) {}
}

#[derive(Clone)]
/// [`Score`] implementation that uses a fixed penalty.
pub struct TestScorer {
    penalty_msat: u64,
}

impl TestScorer {
    /// Creates a new scorer using `penalty_msat`.
    pub fn with_penalty(penalty_msat: u64) -> Self {
        Self { penalty_msat }
    }
}

impl Score for TestScorer {
    fn channel_penalty_msat(&self, _: u64, _: &NodeId, _: &NodeId, _: ChannelUsage) -> u64 {
        self.penalty_msat
    }

    fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}

    fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}

    fn probe_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}

    fn probe_successful(&mut self, _path: &[&RouteHop]) {}
}

impl EventHandler for LnDlcParty {
    fn handle_event(&self, event: lightning::util::events::Event) {
        match event {
            Event::FundingGenerationReady {
                temporary_channel_id,
                counterparty_node_id,
                channel_value_satoshis,
                output_script,
                ..
            } => {
                // Construct the raw transaction with one output, that is paid the amount of the
                // channel.
                let addr = WitnessProgram::from_scriptpubkey(
                    &output_script[..],
                    bitcoin_bech32::constants::Network::Regtest,
                )
                .expect("Lightning funding tx should always be to a SegWit output")
                .to_address();
                let address: Address = addr.parse().unwrap();
                let mut tx = Transaction {
                    version: 2,
                    lock_time: PackedLockTime::ZERO,
                    input: vec![TxIn::default()],
                    output: vec![TxOut {
                        value: channel_value_satoshis,
                        script_pubkey: address.script_pubkey(),
                    }],
                };

                let expected_size = (tx.weight() / 4) as u64;
                let required_amount = channel_value_satoshis
                    + expected_size
                        * (self
                            .blockchain
                            .get_est_sat_per_1000_weight(ConfirmationTarget::Normal)
                            / 25) as u64;

                let utxos: Vec<Utxo> = self
                    .wallet
                    .get_utxos_for_amount(required_amount, None, false)
                    .unwrap();

                tx.input = Vec::new();

                let change_address = self.wallet.get_new_address().unwrap();

                tx.output.push(TxOut {
                    value: utxos.iter().map(|x| x.tx_out.value).sum::<u64>() - required_amount,
                    script_pubkey: change_address.script_pubkey(),
                });

                for (i, utxo) in utxos.iter().enumerate() {
                    tx.input.push(TxIn {
                        previous_output: utxo.outpoint,
                        script_sig: Script::default(),
                        sequence: Sequence::MAX,
                        witness: Witness::default(),
                    });
                    self.wallet
                        .sign_tx_input(&mut tx, i, &utxo.tx_out, None)
                        .unwrap();
                }

                // Give the funding transaction back to LDK for opening the channel.
                self.channel_manager
                    .funding_transaction_generated(&temporary_channel_id, &counterparty_node_id, tx)
                    .unwrap();
            }
            Event::PendingHTLCsForwardable { .. } => {
                self.channel_manager.process_pending_htlc_forwards();
            }
            Event::PaymentClaimable { purpose, .. } => {
                let payment_preimage = match purpose {
                    PaymentPurpose::InvoicePayment {
                        payment_preimage, ..
                    } => payment_preimage,
                    PaymentPurpose::SpontaneousPayment(preimage) => Some(preimage),
                };
                self.channel_manager.claim_funds(payment_preimage.unwrap());
            }
            Event::SpendableOutputs { outputs } => {
                let destination_address = self.wallet.get_new_address().unwrap();
                let output_descriptors = &outputs.iter().collect::<Vec<_>>();
                let tx_feerate = self
                    .blockchain
                    .get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
                let spending_tx = self
                    .keys_manager
                    .spend_spendable_outputs(
                        output_descriptors,
                        Vec::new(),
                        destination_address.script_pubkey(),
                        tx_feerate,
                        &Secp256k1::new(),
                    )
                    .unwrap();
                self.blockchain.broadcast_transaction(&spending_tx);
            }
            Event::ChannelClosed { channel_id, .. } => {
                if let Err(error) = self
                    .sub_channel_manager
                    .notify_ln_channel_closed(channel_id)
                {
                    error!(
                        "Error notifying sub channel manager of LN channel closing: {}",
                        error
                    );
                }
            }
            _ => {
                //Ignore
            }
        }
    }
}

fn create_ln_node(
    name: String,
    data_dir: &str,
    test_params: &TestParams,
    blockchain_provider: &Arc<ElectrsBlockchainProvider>,
) -> LnDlcParty {
    let mut key = [0; 32];
    thread_rng().fill_bytes(&mut key);
    let cur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let keys_manager = Arc::new(KeysManager::new(&key, cur.as_secs(), cur.subsec_nanos()));
    let consistent_keys_manager = Arc::new(CustomKeysManager::new(keys_manager.clone()));
    let logger = Arc::new(console_logger::ConsoleLogger { name });

    std::fs::create_dir_all(data_dir).unwrap();
    let persister = Arc::new(FilesystemPersister::new(data_dir.to_string()));

    let mock_blockchain = Arc::new(MockBlockchain::new(blockchain_provider.clone()));

    let tx_sync = Arc::new(EsploraSyncClient::new(
        "http://localhost:3004".to_string(),
        Arc::clone(&logger),
    ));

    let chain_monitor: Arc<ChainMonitor> =
        Arc::new(lightning::chain::chainmonitor::ChainMonitor::new(
            Some(tx_sync.clone()),
            mock_blockchain.clone(),
            logger.clone(),
            blockchain_provider.clone(),
            persister.clone(),
        ));

    let mut user_config = UserConfig::default();
    user_config.channel_handshake_limits.max_funding_satoshis = 200000000;
    user_config
        .channel_handshake_limits
        .force_announced_channel_preference = false;
    user_config
        .channel_handshake_config
        .max_inbound_htlc_value_in_flight_percent_of_channel = 55;

    let network_graph = Arc::new(NetworkGraph::new(Network::Regtest, logger.clone()));
    let scorer = Arc::new(Mutex::new(TestScorer::with_penalty(0)));
    let router = Arc::new(DefaultRouter::new(
        network_graph,
        logger.clone(),
        keys_manager.get_secure_random_bytes(),
        scorer,
    ));

    let channel_manager = {
        let height = blockchain_provider.get_blockchain_height().unwrap();
        let last_block = blockchain_provider.get_block_at_height(height).unwrap();

        let chain_params = ChainParameters {
            network: Network::Regtest,
            best_block: BestBlock::new(last_block.block_hash(), height as u32),
        };

        Arc::new(ChannelManager::new(
            blockchain_provider.clone(),
            chain_monitor.clone(),
            mock_blockchain.clone(),
            router,
            logger.clone(),
            consistent_keys_manager.clone(),
            consistent_keys_manager.clone(),
            consistent_keys_manager.clone(),
            user_config,
            chain_params,
        ))
    };

    // Step 12: Initialize the PeerManager
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut ephemeral_bytes = [0; 32];
    thread_rng().fill_bytes(&mut ephemeral_bytes);

    let network_graph = NetworkGraph::new(Network::Regtest, logger.clone());

    let storage = Arc::new(MemoryStorage::new());

    let mut oracles = HashMap::with_capacity(1);

    for oracle in &test_params.oracles {
        let oracle = Arc::new(oracle.clone());
        oracles.insert(oracle.get_public_key(), oracle.clone());
    }

    let wallet = Arc::new(simple_wallet::SimpleWallet::new(
        blockchain_provider.clone(),
        storage.clone(),
        Network::Regtest,
    ));

    let dlc_manager = Arc::new(
        Manager::new(
            wallet.clone(),
            blockchain_provider.clone(),
            storage,
            oracles,
            Arc::new(mock_time::MockTime {}),
            blockchain_provider.clone(),
        )
        .unwrap(),
    );

    let sub_channel_manager =
        Arc::new(SubChannelManager::new(channel_manager.clone(), dlc_manager.clone()).unwrap());

    let lightning_msg_handler = MessageHandler {
        chan_handler: sub_channel_manager.clone(),
        route_handler: Arc::new(IgnoringMessageHandler {}),
        onion_message_handler: Arc::new(IgnoringMessageHandler {}),
    };
    let peer_manager = PeerManager::new(
        lightning_msg_handler,
        current_time.try_into().unwrap(),
        &ephemeral_bytes,
        logger.clone(),
        Arc::new(IgnoringMessageHandler {}),
        consistent_keys_manager.clone(),
    );

    LnDlcParty {
        peer_manager: Arc::new(peer_manager),
        channel_manager,
        chain_monitor,
        keys_manager: consistent_keys_manager,
        logger,
        network_graph,
        sub_channel_manager,
        dlc_manager,
        blockchain: blockchain_provider.clone(),
        mock_blockchain,
        wallet,
        persister,
        esplora_sync: tx_sync,
    }
}

#[test]
#[ignore]
fn ln_dlc_established_close() {
    ln_dlc_test(TestPath::EstablishedClose);
}

#[test]
#[ignore]
fn ln_dlc_renewed_close() {
    ln_dlc_test(TestPath::RenewedClose);
}

#[test]
#[ignore]
fn ln_dlc_settled_close() {
    ln_dlc_test(TestPath::SettledClose);
}

#[test]
#[ignore]
fn ln_dlc_settled_renewed_close() {
    ln_dlc_test(TestPath::SettledRenewedClose);
}

#[test]
#[ignore]
fn ln_dlc_pre_split_cheat() {
    ln_dlc_test(TestPath::CheatPreSplitCommit);
}

#[test]
#[ignore]
fn ln_dlc_post_split_cheat() {
    ln_dlc_test(TestPath::CheatPostSplitCommit);
}

#[test]
#[ignore]
fn ln_dlc_off_chain_close() {
    ln_dlc_test(TestPath::OffChainClosed);
}

#[test]
#[ignore]
fn ln_dlc_split_cheat() {
    ln_dlc_test(TestPath::SplitCheat);
}

#[test]
#[ignore]
fn ln_dlc_rejected_offer() {
    ln_dlc_test(TestPath::OfferRejected);
}

#[test]
#[ignore]
fn ln_dlc_rejected_close() {
    ln_dlc_test(TestPath::CloseRejected);
}

#[test]
#[ignore]
fn ln_dlc_reconnect() {
    ln_dlc_test(TestPath::Reconnect);
}

#[test]
#[ignore]
fn ln_dlc_off_chain_close_open_close() {
    ln_dlc_test(TestPath::OffChainCloseOpenClose);
}

#[test]
#[ignore]
fn ln_dlc_offer_after_offchain_close_disconnect() {
    ln_dlc_test(TestPath::ReconnectReOfferAfterClose);
}

#[test]
#[ignore]
fn ln_dlc_disconnected_force_close() {
    ln_dlc_test(TestPath::DisconnectedForceClose);
}

#[test]
#[ignore]
fn ln_dlc_offered_force_close() {
    ln_dlc_test(TestPath::OfferedForceClose);
}

#[test]
#[ignore]
fn ln_dlc_offered_force_close2() {
    ln_dlc_test(TestPath::OfferedForceClose2);
}

#[test]
#[ignore]
fn ln_dlc_accepted_force_close() {
    ln_dlc_test(TestPath::AcceptedForceClose);
}

#[test]
#[ignore]
fn ln_dlc_accepted_force_close2() {
    ln_dlc_test(TestPath::AcceptedForceClose2);
}

#[test]
#[ignore]
fn ln_dlc_confirmed_force_close() {
    ln_dlc_test(TestPath::ConfirmedForceClose);
}

#[test]
#[ignore]
fn ln_dlc_confirmed_force_close2() {
    ln_dlc_test(TestPath::ConfirmedForceClose2);
}

#[test]
#[ignore]
fn ln_dlc_finalized_force_close() {
    ln_dlc_test(TestPath::FinalizedForceClose);
}

#[test]
#[ignore]
fn ln_dlc_finalized_force_close2() {
    ln_dlc_test(TestPath::FinalizedForceClose2);
}

#[test]
#[ignore]
fn ln_dlc_close_offered_force_close() {
    ln_dlc_test(TestPath::CloseOfferedForceClose);
}

#[test]
#[ignore]
fn ln_dlc_close_offered_force_close2() {
    ln_dlc_test(TestPath::CloseOfferedForceClose2);
}

#[test]
#[ignore]
fn ln_dlc_close_accepted_force_close() {
    ln_dlc_test(TestPath::CloseAcceptedForceClose);
}

#[test]
#[ignore]
fn ln_dlc_close_accepted_force_close2() {
    ln_dlc_test(TestPath::CloseAcceptedForceClose2);
}

#[test]
#[ignore]
fn ln_dlc_close_confirmed_force_close() {
    ln_dlc_test(TestPath::CloseConfirmedForceClose);
}

#[test]
#[ignore]
fn ln_dlc_close_confirmed_force_close2() {
    ln_dlc_test(TestPath::CloseConfirmedForceClose2);
}

#[test]
#[ignore]
fn ln_dlc_close_finalized_force_close() {
    ln_dlc_test(TestPath::CloseFinalizedForceClose);
}

// #[derive(Debug)]
// pub struct TestParams {
//     pub oracles: Vec<p2pd_oracle_client::P2PDOracleClient>,
//     pub contract_input: ContractInput,
// }

fn ln_dlc_test(test_path: TestPath) {
    env_logger::init();
    let (_, _, sink_rpc) = init_clients();

    let test_params = get_enum_test_params_custom_collateral(1, 1, None, 60000, 40000);

    let electrs = Arc::new(ElectrsBlockchainProvider::new(
        "http://localhost:3004/".to_string(),
        Network::Regtest,
    ));

    let mut alice_node = create_ln_node(
        "Alice".to_string(),
        "./.ldk/.alicedir",
        &test_params,
        &electrs,
    );
    let mut bob_node = create_ln_node("Bob".to_string(), "./.ldk/.bobdir", &test_params, &electrs);

    let alice_fund_address = alice_node.wallet.get_new_address().unwrap();

    sink_rpc
        .send_to_address(
            &alice_fund_address,
            Amount::from_btc(0.002).unwrap(),
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

    refresh_wallet(&alice_node.wallet, 200000);

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    let mut alice_descriptor = MockSocketDescriptor::new(0, bob_node.peer_manager.clone());
    let mut bob_descriptor = MockSocketDescriptor::new(1, alice_node.peer_manager.clone());

    alice_descriptor.counter_descriptor = Some(Box::new(bob_descriptor.clone()));
    bob_descriptor.counter_descriptor = Some(Box::new(alice_descriptor.clone()));

    let initial_send = alice_node
        .peer_manager
        .new_outbound_connection(
            bob_node.channel_manager.get_our_node_id(),
            alice_descriptor.clone(),
            None,
        )
        .unwrap();

    bob_node
        .peer_manager
        .new_inbound_connection(bob_descriptor.clone(), None)
        .unwrap();

    // bob_node.peer_manager.timer_tick_occurred();

    bob_node
        .peer_manager
        .read_event(&mut bob_descriptor, &initial_send)
        .unwrap();
    bob_node.peer_manager.process_events();
    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();

    alice_node
        .channel_manager
        .create_channel(
            bob_node.channel_manager.get_our_node_id(),
            180000,
            0,
            1,
            None,
        )
        .unwrap();

    bob_node.peer_manager.process_events();
    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();

    alice_node
        .channel_manager
        .process_pending_events(&alice_node);
    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();

    let sink_address = sink_rpc.get_new_address(None, None).expect("RPC Error");
    sink_rpc
        .generate_to_address(6, &sink_address)
        .expect("RPC Error");

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();

    assert_eq!(1, alice_node.channel_manager.list_channels().len());

    while alice_node.channel_manager.list_usable_channels().len() != 1 {
        alice_node.update_to_chain_tip();
        bob_node.update_to_chain_tip();
        alice_node.peer_manager.process_events();
        bob_node.peer_manager.process_events();
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    assert_eq!(1, alice_node.channel_manager.list_usable_channels().len());

    let payment_params = lightning::routing::router::PaymentParameters::from_node_id(
        bob_node.channel_manager.get_our_node_id(),
        70,
    );

    let payment_preimage = lightning::ln::PaymentPreimage([0; 32]);
    let payment_hash = lightning::ln::PaymentHash(
        bitcoin::hashes::sha256::Hash::hash(&payment_preimage.0[..]).into_inner(),
    );
    let _ = bob_node
        .channel_manager
        .create_inbound_payment_for_hash(payment_hash, None, 7200, None)
        .unwrap();

    let scorer = TestScorer::with_penalty(0);
    let random_seed_bytes = bob_node.keys_manager.get_secure_random_bytes();
    let route_params = RouteParameters {
        payment_params: payment_params.clone(),
        final_value_msat: 90000000,
    };

    let route = lightning::routing::router::find_route(
        &alice_node.channel_manager.get_our_node_id(),
        &route_params,
        &alice_node.network_graph,
        Some(
            &alice_node
                .channel_manager
                .list_usable_channels()
                .iter()
                .collect::<Vec<_>>(),
        ),
        alice_node.logger.clone(),
        &scorer,
        &random_seed_bytes,
    )
    .unwrap();

    let payment_id = PaymentId([0u8; 32]);

    alice_node
        .channel_manager
        .send_spontaneous_payment(&route, Some(payment_preimage), payment_id)
        .unwrap();

    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();

    std::thread::sleep(std::time::Duration::from_secs(2));

    let get_commit_tx_from_node = |node: &LnDlcParty| {
        let mut res = node
            .persister
            .read_channelmonitors(node.keys_manager.clone(), node.keys_manager.clone())
            .unwrap();
        assert!(res.len() == 1);
        let (_, channel_monitor) = res.remove(0);
        channel_monitor.get_latest_holder_commitment_txn(&node.logger)
    };

    let pre_split_commit_tx = if let TestPath::CheatPreSplitCommit = test_path {
        Some(get_commit_tx_from_node(&alice_node))
    } else {
        None
    };

    let bob_channel_details = bob_node.channel_manager.list_usable_channels().remove(0);
    let channel_id = bob_channel_details.channel_id;

    if let TestPath::OfferRejected = test_path {
        reject_offer(&test_params, &alice_node, &bob_node, &channel_id);
        return;
    }

    offer_sub_channel(
        &test_path,
        &test_params,
        &alice_node,
        &bob_node,
        &channel_id,
        alice_descriptor.clone(),
        bob_descriptor.clone(),
    );

    if let TestPath::CheatPreSplitCommit = test_path {
        let revoked_tx = pre_split_commit_tx.unwrap();

        ln_cheated_check(
            &revoked_tx[0],
            &mut bob_node,
            electrs.clone(),
            &generate_blocks,
        );

        return;
    }

    let route_params = RouteParameters {
        payment_params,
        final_value_msat: 900000,
    };

    let route = lightning::routing::router::find_route(
        &alice_node.channel_manager.get_our_node_id(),
        &route_params,
        &alice_node.network_graph,
        Some(
            &alice_node
                .channel_manager
                .list_usable_channels()
                .iter()
                .collect::<Vec<_>>(),
        ),
        alice_node.logger.clone(),
        &scorer,
        &random_seed_bytes,
    )
    .unwrap();

    let post_split_commit_tx = if let TestPath::CheatPostSplitCommit = test_path {
        alice_node.mock_blockchain.start_discard();
        Some(get_commit_tx_from_node(&alice_node))
    } else {
        None
    };

    let mut payment_id = PaymentId([0u8; 32]);
    payment_id.0[31] += 1;

    alice_node
        .channel_manager
        .send_spontaneous_payment(&route, Some(payment_preimage), payment_id)
        .unwrap();

    bob_node.process_events();
    alice_node.process_events();

    bob_node.process_events();
    alice_node.process_events();

    bob_node.process_events();
    alice_node.process_events();

    bob_node.process_events();
    alice_node.process_events();

    std::thread::sleep(std::time::Duration::from_secs(1));

    bob_node.process_events();
    alice_node.process_events();

    bob_node.process_events();
    alice_node.process_events();

    let sub_channel = alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(channel_id)
        .unwrap()
        .unwrap();

    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();

    let contract_id = if let TestPath::RenewedClose = test_path {
        let contract_id =
            assert_channel_contract_state!(alice_node.dlc_manager, dlc_channel_id, Confirmed);
        renew(&alice_node, &bob_node, dlc_channel_id, &test_params);
        assert_contract_state_unlocked!(alice_node.dlc_manager, contract_id, Closed);
        assert_contract_state_unlocked!(bob_node.dlc_manager, contract_id, Closed);
        Some(assert_channel_contract_state!(
            alice_node.dlc_manager,
            dlc_channel_id,
            Confirmed
        ))
    } else if let TestPath::SettledClose | TestPath::SettledRenewedClose = test_path {
        let contract_id =
            assert_channel_contract_state!(alice_node.dlc_manager, dlc_channel_id, Confirmed);
        settle(&alice_node, &bob_node, dlc_channel_id, &test_params);
        assert_contract_state_unlocked!(alice_node.dlc_manager, contract_id, Closed);
        assert_contract_state_unlocked!(bob_node.dlc_manager, contract_id, Closed);

        if let TestPath::SettledRenewedClose = test_path {
            renew(&alice_node, &bob_node, dlc_channel_id, &test_params);
            Some(assert_channel_contract_state!(
                alice_node.dlc_manager,
                dlc_channel_id,
                Confirmed
            ))
        } else {
            None
        }
    } else {
        Some(assert_channel_contract_state!(
            alice_node.dlc_manager,
            dlc_channel_id,
            Confirmed
        ))
    };

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    if let TestPath::OffChainClosed
    | TestPath::SplitCheat
    | TestPath::CloseRejected
    | TestPath::OffChainCloseOpenClose
    | TestPath::Reconnect
    | TestPath::ReconnectReOfferAfterClose = test_path
    {
        if let TestPath::SplitCheat = test_path {
            alice_node.dlc_manager.get_store().save();
        }

        off_chain_close_offer(
            &test_path,
            &test_params,
            &alice_node,
            &bob_node,
            channel_id,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
        );

        if let TestPath::CloseRejected = test_path {
            let reject = bob_node
                .sub_channel_manager
                .reject_sub_channel_close_offer(channel_id)
                .unwrap();

            alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &SubChannelMessage::Reject(reject),
                    &bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap();

            assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id, Signed);
            assert_sub_channel_state!(bob_node.sub_channel_manager, &channel_id, Signed);

            return;
        }

        off_chain_close_finalize(
            &test_path,
            &alice_node,
            &bob_node,
            channel_id,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
            &test_params,
        );

        if let TestPath::ReconnectReOfferAfterClose = test_path {
            return;
        }

        if let TestPath::OffChainCloseOpenClose = test_path {
            offer_sub_channel(
                &test_path,
                &test_params,
                &alice_node,
                &bob_node,
                &channel_id,
                alice_descriptor.clone(),
                bob_descriptor.clone(),
            );
            off_chain_close_offer(
                &test_path,
                &test_params,
                &alice_node,
                &bob_node,
                channel_id,
                alice_descriptor.clone(),
                bob_descriptor.clone(),
            );
            off_chain_close_finalize(
                &test_path,
                &alice_node,
                &bob_node,
                channel_id,
                alice_descriptor.clone(),
                bob_descriptor.clone(),
                &test_params,
            );
        }

        offer_sub_channel(
            &test_path,
            &test_params,
            &alice_node,
            &bob_node,
            &channel_id,
            alice_descriptor,
            bob_descriptor,
        );

        if let TestPath::SplitCheat = test_path {
            alice_node.dlc_manager.get_store().rollback();
            let split_tx_id = match alice_node
                .dlc_manager
                .get_store()
                .get_sub_channel(channel_id)
                .unwrap()
                .unwrap()
                .state
            {
                SubChannelState::Signed(s) => s.split_tx.transaction.txid(),
                a => panic!("Unexpected state {:?}", a),
            };
            alice_node
                .sub_channel_manager
                .force_close_sub_channel(&channel_id)
                .unwrap();

            generate_blocks(1);

            bob_node.update_to_chain_tip();

            let outspends = electrs.get_outspends(&split_tx_id).unwrap();

            let spent = outspends
                .iter()
                .filter_map(|x| {
                    if let OutSpendResp::Spent(s) = x {
                        Some(s)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            assert_eq!(spent.len(), 2);
            assert_eq!(spent[0].txid, spent[1].txid);
            let spending_tx = electrs.get_transaction(&spent[0].txid).unwrap();

            let receive_addr =
                Address::from_script(&spending_tx.output[0].script_pubkey, Network::Regtest)
                    .unwrap();

            assert!(bob_node
                .dlc_manager
                .get_store()
                .get_addresses()
                .unwrap()
                .iter()
                .any(|x| *x == receive_addr));
        } else {
            alice_node
                .channel_manager
                .force_close_broadcasting_latest_txn(
                    &channel_id,
                    &bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap();
        }

        return;
    }

    if let TestPath::OfferedForceClose
    | TestPath::OfferedForceClose2
    | TestPath::AcceptedForceClose
    | TestPath::AcceptedForceClose2
    | TestPath::ConfirmedForceClose
    | TestPath::ConfirmedForceClose2
    | TestPath::FinalizedForceClose
    | TestPath::FinalizedForceClose2 = test_path
    {
        force_close_establish_tests(
            &test_path,
            &test_params,
            &mut alice_node,
            &mut bob_node,
            channel_id,
            alice_descriptor,
            bob_descriptor,
            electrs.clone(),
            &get_commit_tx_from_node,
            &generate_blocks,
        );
        return;
    }

    if let TestPath::CloseOfferedForceClose
    | TestPath::CloseOfferedForceClose2
    | TestPath::CloseAcceptedForceClose
    | TestPath::CloseAcceptedForceClose2
    | TestPath::CloseConfirmedForceClose
    | TestPath::CloseConfirmedForceClose2
    | TestPath::CloseFinalizedForceClose = test_path
    {
        force_close_off_chain_close_tests(
            &test_path,
            &test_params,
            &mut alice_node,
            &mut bob_node,
            channel_id,
            electrs.clone(),
            &get_commit_tx_from_node,
            &generate_blocks,
        );
        return;
    }

    let commit_tx = get_commit_tx_from_node(&alice_node).remove(0);

    if let TestPath::CheatPostSplitCommit = test_path {
        let alice_commit = get_commit_tx_from_node(&alice_node);
        alice_node
            .mock_blockchain
            .discard_id(alice_commit[0].txid());

        let bob_commit = get_commit_tx_from_node(&bob_node);
        bob_node.mock_blockchain.discard_id(bob_commit[0].txid());
    }

    if let TestPath::DisconnectedForceClose = test_path {
        alice_node
            .peer_manager
            .socket_disconnected(&alice_descriptor);

        bob_node.peer_manager.socket_disconnected(&bob_descriptor);
    }

    alice_node
        .sub_channel_manager
        .force_close_sub_channel(&channel_id)
        .unwrap();

    assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id, Closing);

    generate_blocks(1);

    assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id, Closing);

    generate_blocks(500);

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    alice_node.sub_channel_manager.periodic_check();

    generate_blocks(1);

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    if let TestPath::CheatPostSplitCommit = test_path {
        let cheat_tx = post_split_commit_tx.unwrap()[0].clone();
        ln_cheated_check(&cheat_tx, &mut bob_node, electrs.clone(), &generate_blocks);
        return;
    } else {
        assert_eq!(
            1,
            electrs
                .get_transaction_confirmations(&commit_tx.txid())
                .unwrap()
        );
    }

    generate_blocks(1);

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id; OnChainClosed);
    assert_sub_channel_state!(bob_node.sub_channel_manager, &channel_id; CounterOnChainClosed);

    if let Some(contract_id) = contract_id {
        assert_channel_state_unlocked!(alice_node.dlc_manager, dlc_channel_id, Signed, Closing);
        assert_channel_state_unlocked!(bob_node.dlc_manager, dlc_channel_id, Signed, Closing);

        generate_blocks(dlc_manager::manager::CET_NSEQUENCE as u64);

        alice_node.update_to_chain_tip();
        generate_blocks(1);
        bob_node.update_to_chain_tip();

        assert_channel_state_unlocked!(alice_node.dlc_manager, dlc_channel_id, Closed);
        assert_channel_state_unlocked!(bob_node.dlc_manager, dlc_channel_id, CounterClosed);

        assert_contract_state_unlocked!(alice_node.dlc_manager, contract_id, PreClosed);
        assert_contract_state_unlocked!(bob_node.dlc_manager, contract_id, PreClosed);

        alice_node.update_to_chain_tip();
        bob_node.update_to_chain_tip();

        generate_blocks(6);

        alice_node.update_to_chain_tip();
        bob_node.update_to_chain_tip();

        assert_contract_state_unlocked!(alice_node.dlc_manager, contract_id, Closed);
        assert_contract_state_unlocked!(bob_node.dlc_manager, contract_id, Closed);
    } else {
        assert_channel_state_unlocked!(alice_node.dlc_manager, dlc_channel_id, Closed);
        assert_channel_state_unlocked!(bob_node.dlc_manager, dlc_channel_id, CounterClosed);
    }

    generate_blocks(500);

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    alice_node.process_events();
    bob_node.process_events();

    generate_blocks(1);

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    alice_node.process_events();
    bob_node.process_events();

    let all_spent = electrs
        .get_outspends(&commit_tx.txid())
        .unwrap()
        .into_iter()
        .all(|x| {
            if let OutSpendResp::Spent(_) = x {
                true
            } else {
                false
            }
        });

    assert!(all_spent);

    assert!(alice_node
        .dlc_manager
        .get_chain_monitor()
        .lock()
        .unwrap()
        .is_empty());
    assert!(bob_node
        .dlc_manager
        .get_chain_monitor()
        .lock()
        .unwrap()
        .is_empty());
}

fn settle(
    alice_node: &LnDlcParty,
    bob_node: &LnDlcParty,
    channel_id: ChannelId,
    test_params: &TestParams,
) {
    let (settle_offer, bob_key) = alice_node
        .dlc_manager
        .settle_offer(&channel_id, test_params.contract_input.accept_collateral)
        .unwrap();

    bob_node
        .dlc_manager
        .on_dlc_message(
            &Message::Channel(ChannelMessage::SettleOffer(settle_offer)),
            alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    let (settle_accept, alice_key) = bob_node
        .dlc_manager
        .accept_settle_offer(&channel_id)
        .unwrap();

    let msg = alice_node
        .dlc_manager
        .on_dlc_message(
            &Message::Channel(ChannelMessage::SettleAccept(settle_accept)),
            bob_key,
        )
        .unwrap()
        .unwrap();

    let msg = bob_node
        .dlc_manager
        .on_dlc_message(&msg, alice_key)
        .unwrap()
        .unwrap();

    alice_node
        .dlc_manager
        .on_dlc_message(&msg, bob_key)
        .unwrap();
}

fn renew(
    alice_node: &LnDlcParty,
    bob_node: &LnDlcParty,
    channel_id: ChannelId,
    test_params: &TestParams,
) {
    let (renew_offer, _) = alice_node
        .dlc_manager
        .renew_offer(
            &channel_id,
            test_params.contract_input.accept_collateral,
            &test_params.contract_input,
        )
        .unwrap();

    bob_node
        .dlc_manager
        .on_dlc_message(
            &Message::Channel(ChannelMessage::RenewOffer(renew_offer)),
            alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    let (accept, bob_key) = bob_node
        .dlc_manager
        .accept_renew_offer(&channel_id)
        .unwrap();

    let msg = alice_node
        .dlc_manager
        .on_dlc_message(
            &Message::Channel(ChannelMessage::RenewAccept(accept)),
            bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    let msg = bob_node
        .dlc_manager
        .on_dlc_message(&msg, bob_key)
        .unwrap()
        .unwrap();

    alice_node
        .dlc_manager
        .on_dlc_message(&msg, bob_node.channel_manager.get_our_node_id())
        .unwrap();
}

fn ln_cheated_check<F>(
    cheat_tx: &Transaction,
    bob_node: &mut LnDlcParty,
    electrs: Arc<ElectrsBlockchainProvider>,
    generate_block: &F,
) where
    F: Fn(u64),
{
    electrs.broadcast_transaction(cheat_tx);

    // wait for cheat tx to be confirmed
    generate_block(6);

    bob_node.update_to_chain_tip();

    bob_node.process_events();

    // LDK should have reacted, this should include a punish tx
    generate_block(1);

    bob_node.update_to_chain_tip();

    bob_node.process_events();

    std::thread::sleep(std::time::Duration::from_secs(1));

    let vout = cheat_tx
        .output
        .iter()
        .position(|x| x.script_pubkey.is_v0_p2wsh())
        .expect("to have a p2wsh output");

    let outspends = electrs.get_outspends(&cheat_tx.txid()).unwrap();

    let outspend_info = outspends
        .iter()
        .filter_map(|x| {
            if let OutSpendResp::Spent(s) = x {
                Some(s)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let spend_tx = electrs.get_transaction(&outspend_info[vout].txid).unwrap();

    generate_block(6);

    bob_node.update_to_chain_tip();

    bob_node.process_events();

    let mut outspend_info = vec![];
    while outspend_info.is_empty() {
        let outspends = electrs.get_outspends(&spend_tx.txid()).unwrap();
        outspend_info = outspends
            .iter()
            .filter_map(|x| {
                if let OutSpendResp::Spent(s) = x {
                    Some(s)
                } else {
                    None
                }
            })
            .cloned()
            .collect::<Vec<_>>();
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    let claim_tx = electrs.get_transaction(&outspend_info[0].txid).unwrap();

    let receive_addr =
        Address::from_script(&claim_tx.output[0].script_pubkey, Network::Regtest).unwrap();

    assert!(bob_node
        .dlc_manager
        .get_store()
        .get_addresses()
        .unwrap()
        .iter()
        .any(|x| *x == receive_addr));
}

fn offer_common(
    test_params: &TestParams,
    alice_node: &LnDlcParty,
    channel_id: &ChannelId,
) -> SubChannelOffer {
    let oracle_announcements = test_params
        .oracles
        .iter()
        .map(|x| {
            x.get_announcement(
                &test_params.contract_input.contract_infos[0]
                    .oracles
                    .event_id,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let offer = alice_node
        .sub_channel_manager
        .offer_sub_channel(
            channel_id,
            &test_params.contract_input,
            &[oracle_announcements],
        )
        .unwrap();

    assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id, Offered);

    offer
}

fn offer_sub_channel(
    test_path: &TestPath,
    test_params: &TestParams,
    alice_node: &LnDlcParty,
    bob_node: &LnDlcParty,
    channel_id: &ChannelId,
    alice_descriptor: MockSocketDescriptor,
    bob_descriptor: MockSocketDescriptor,
) {
    let offer = offer_common(test_params, alice_node, channel_id);

    if let TestPath::Reconnect = test_path {
        reconnect(
            alice_node,
            bob_node,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
        );
        // Alice should resend the offer message to bob as he has not received it yet.
        let mut msgs = alice_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::Offer(o), p) = msgs.pop().unwrap() {
            assert_eq!(p, bob_node.channel_manager.get_our_node_id());
            assert_eq!(o, offer);
        } else {
            panic!("Expected an offer message");
        }

        assert_eq!(0, bob_node.sub_channel_manager.periodic_check().len());
    }

    bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Offer(offer),
            &alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    if let TestPath::Reconnect = test_path {
        reconnect(
            alice_node,
            bob_node,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
        );
        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
        assert_eq!(0, bob_node.sub_channel_manager.periodic_check().len());
    }

    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Offered);

    let (_, mut accept) = bob_node
        .sub_channel_manager
        .accept_sub_channel(channel_id)
        .unwrap();

    if let TestPath::Reconnect = test_path {
        reconnect(
            alice_node,
            bob_node,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
        );

        assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id, Offered);
        assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Offered);

        // Bob should re-send the accept message
        let mut msgs = bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::Accept(a), p) = msgs.pop().unwrap() {
            assert_eq!(p, alice_node.channel_manager.get_our_node_id());
            assert_eq_accept(&a, &accept);
            accept = a;
        } else {
            panic!("Expected an accept message");
        }

        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
    }

    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Accepted);
    let mut confirm = alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Accept(accept),
            &bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    if let TestPath::Reconnect = test_path {
        reconnect(
            alice_node,
            bob_node,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
        );

        assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id, Offered);
        assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Offered);

        // Bob should re-send the accept message
        let mut msgs = bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
        if let (SubChannelMessage::Accept(a), p) = msgs.pop().unwrap() {
            assert_eq!(p, alice_node.channel_manager.get_our_node_id());
            confirm = alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &SubChannelMessage::Accept(a),
                    &bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap()
                .unwrap();
        } else {
            panic!("Expected an accept message");
        }
    }

    alice_node.process_events();
    let mut finalize = bob_node
        .sub_channel_manager
        .on_sub_channel_message(&confirm, &alice_node.channel_manager.get_our_node_id())
        .unwrap()
        .unwrap();

    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Finalized);

    bob_node.process_events();
    assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id, Confirmed);

    if let TestPath::Reconnect = test_path {
        reconnect(
            alice_node,
            bob_node,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
        );
        assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id, Offered);
        assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Offered);

        // Bob should re-send the accept message
        let mut msgs = bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
        if let (SubChannelMessage::Accept(a), p) = msgs.pop().unwrap() {
            assert_eq!(p, alice_node.channel_manager.get_our_node_id());
            let confirm = alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &SubChannelMessage::Accept(a),
                    &bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap()
                .unwrap();
            finalize = bob_node
                .sub_channel_manager
                .on_sub_channel_message(&confirm, &alice_node.channel_manager.get_our_node_id())
                .unwrap()
                .unwrap();
        } else {
            panic!("Expected an accept message");
        }
    }

    let revoke = alice_node
        .sub_channel_manager
        .on_sub_channel_message(&finalize, &bob_node.channel_manager.get_our_node_id())
        .unwrap()
        .unwrap();
    assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id, Signed);
    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Finalized);

    if let TestPath::Reconnect = test_path {
        reconnect(alice_node, bob_node, alice_descriptor, bob_descriptor);

        assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id, Signed);
        assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Finalized);

        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
        assert_eq!(0, bob_node.sub_channel_manager.periodic_check().len());
    } else {
        bob_node
            .sub_channel_manager
            .on_sub_channel_message(&revoke, &alice_node.channel_manager.get_our_node_id())
            .unwrap();
    }
    assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id, Signed);
    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Signed);

    alice_node.process_events();
}

fn reconnect(
    alice_node: &LnDlcParty,
    bob_node: &LnDlcParty,
    alice_descriptor: MockSocketDescriptor,
    mut bob_descriptor: MockSocketDescriptor,
) {
    alice_node
        .peer_manager
        .socket_disconnected(&alice_descriptor);

    bob_node.peer_manager.socket_disconnected(&bob_descriptor);

    let initial_send = alice_node
        .peer_manager
        .new_outbound_connection(
            bob_node.channel_manager.get_our_node_id(),
            alice_descriptor,
            None,
        )
        .unwrap();

    bob_node
        .peer_manager
        .new_inbound_connection(bob_descriptor.clone(), None)
        .unwrap();

    bob_node
        .peer_manager
        .read_event(&mut bob_descriptor, &initial_send)
        .unwrap();
    bob_node.peer_manager.process_events();
    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();
    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();

    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
}

fn reject_offer(
    test_params: &TestParams,
    alice_node: &LnDlcParty,
    bob_node: &LnDlcParty,
    channel_id: &ChannelId,
) {
    let offer = offer_common(test_params, alice_node, channel_id);

    bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Offer(offer),
            &alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Offered);

    let reject = bob_node
        .sub_channel_manager
        .reject_sub_channel_offer(*channel_id)
        .unwrap();

    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id; Rejected);

    alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Reject(reject),
            &bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id; Rejected);
}

fn assert_eq_accept(a: &SubChannelAccept, b: &SubChannelAccept) {
    assert_eq_fields!(
        a,
        b,
        channel_id,
        revocation_basepoint,
        publish_basepoint,
        own_basepoint,
        first_per_split_point,
        channel_revocation_basepoint,
        channel_publish_basepoint,
        channel_own_basepoint,
        first_per_update_point,
        payout_spk,
        payout_serial_id
    );
}

fn off_chain_close_offer(
    test_path: &TestPath,
    test_params: &TestParams,
    alice_node: &LnDlcParty,
    bob_node: &LnDlcParty,
    channel_id: ChannelId,
    alice_descriptor: MockSocketDescriptor,
    bob_descriptor: MockSocketDescriptor,
) {
    let sub_channel = alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(channel_id)
        .unwrap()
        .unwrap();

    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    assert_channel_contract_state!(alice_node.dlc_manager, dlc_channel_id, Confirmed);

    let (close_offer, _) = alice_node
        .sub_channel_manager
        .offer_subchannel_close(&channel_id, test_params.contract_input.accept_collateral)
        .unwrap();

    if let TestPath::Reconnect = test_path {
        reconnect(
            alice_node,
            bob_node,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
        );

        assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id, CloseOffered);
        assert_sub_channel_state!(bob_node.sub_channel_manager, &channel_id, Signed);
        let mut msgs = alice_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::CloseOffer(c), p) = msgs.pop().unwrap() {
            assert_eq!(p, bob_node.channel_manager.get_our_node_id());
            assert_eq!(c, close_offer);
        } else {
            panic!("Expected a close offer message");
        }
    }

    bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::CloseOffer(close_offer),
            &alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    if let TestPath::Reconnect = test_path {
        reconnect(alice_node, bob_node, alice_descriptor, bob_descriptor);

        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
        assert_eq!(0, bob_node.sub_channel_manager.periodic_check().len());
    }
}

fn off_chain_close_finalize(
    test_path: &TestPath,
    alice_node: &LnDlcParty,
    bob_node: &LnDlcParty,
    channel_id: ChannelId,
    alice_descriptor: MockSocketDescriptor,
    bob_descriptor: MockSocketDescriptor,
    test_params: &TestParams,
) {
    let sub_channel = alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(channel_id)
        .unwrap()
        .unwrap();

    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    let contract_id =
        assert_channel_contract_state!(alice_node.dlc_manager, dlc_channel_id, Confirmed);
    let (mut close_accept, _) = bob_node
        .sub_channel_manager
        .accept_subchannel_close_offer(&channel_id)
        .unwrap();

    if let TestPath::Reconnect = test_path {
        reconnect(
            alice_node,
            bob_node,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
        );

        assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id, CloseOffered);
        assert_sub_channel_state!(bob_node.sub_channel_manager, &channel_id, CloseOffered);

        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
        let mut msgs = bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::CloseAccept(c), p) = msgs.pop().unwrap() {
            assert_eq!(p, alice_node.channel_manager.get_our_node_id());
            close_accept = c;
        } else {
            panic!("Expected a close accept message");
        }
    }

    let mut close_confirm = alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::CloseAccept(close_accept),
            &bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    if let TestPath::Reconnect = test_path {
        reconnect(
            alice_node,
            bob_node,
            alice_descriptor.clone(),
            bob_descriptor.clone(),
        );

        assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id, CloseOffered);
        assert_sub_channel_state!(bob_node.sub_channel_manager, &channel_id, CloseOffered);

        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
        let mut msgs = bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::CloseAccept(c), _) = msgs.pop().unwrap() {
            let close_confirm2 = alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &SubChannelMessage::CloseAccept(c),
                    &bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap()
                .unwrap();
            close_confirm = close_confirm2;
        } else {
            panic!("Expected a close accept message");
        }
    }

    let mut close_finalize = bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &close_confirm,
            &alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    if let TestPath::Reconnect = test_path {
        reconnect(alice_node, bob_node, alice_descriptor, bob_descriptor);

        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
        let mut msgs = bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::CloseFinalize(c), _) = msgs.pop().unwrap() {
            close_finalize = SubChannelMessage::CloseFinalize(c);
        } else {
            panic!("Expected a close finalize message");
        }
    } else if let TestPath::ReconnectReOfferAfterClose = test_path {
        offer_common(test_params, bob_node, &channel_id);
        assert_sub_channel_state!(bob_node.sub_channel_manager, &channel_id, Offered);

        reconnect(alice_node, bob_node, alice_descriptor, bob_descriptor);

        assert_sub_channel_state!(bob_node.sub_channel_manager, &channel_id, Offered);

        assert_eq!(0, alice_node.sub_channel_manager.periodic_check().len());
        let mut msgs = bob_node.sub_channel_manager.periodic_check();
        assert_eq!(2, msgs.len());
        if let (SubChannelMessage::CloseFinalize(c), _) = msgs.remove(0) {
            close_finalize = SubChannelMessage::CloseFinalize(c);
            alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &close_finalize,
                    &bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap();
            assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id; OffChainClosed);
            if let (SubChannelMessage::Offer(o), _) = msgs.pop().unwrap() {
                alice_node
                    .sub_channel_manager
                    .on_sub_channel_message(
                        &SubChannelMessage::Offer(o),
                        &bob_node.channel_manager.get_our_node_id(),
                    )
                    .unwrap();
                assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id, Offered);
                return;
            } else {
                panic!("Expected an offer message");
            }
        } else {
            panic!("Expected a close finalize message");
        }
    }

    alice_node
        .sub_channel_manager
        .on_sub_channel_message(&close_finalize, &bob_node.channel_manager.get_our_node_id())
        .unwrap();

    assert_contract_state_unlocked!(alice_node.dlc_manager, contract_id, Closed);
    assert_contract_state_unlocked!(bob_node.dlc_manager, contract_id, Closed);

    assert_channel_state_unlocked!(
        alice_node.dlc_manager,
        dlc_channel_id,
        CollaborativelyClosed
    );
    assert_channel_state_unlocked!(bob_node.dlc_manager, dlc_channel_id, CollaborativelyClosed);

    assert_sub_channel_state!(alice_node.sub_channel_manager, &channel_id; OffChainClosed);
    assert_sub_channel_state!(bob_node.sub_channel_manager, &channel_id; OffChainClosed);
}

fn force_close_establish_tests<F, G>(
    test_path: &TestPath,
    test_params: &TestParams,
    alice_node: &mut LnDlcParty,
    bob_node: &mut LnDlcParty,
    channel_id: ChannelId,
    alice_descriptor: MockSocketDescriptor,
    bob_descriptor: MockSocketDescriptor,
    electrs: Arc<ElectrsBlockchainProvider>,
    get_commit_tx_from_node: &F,
    generate_blocks: &G,
) where
    F: Fn(&LnDlcParty) -> Vec<Transaction>,
    G: Fn(u64),
{
    off_chain_close_offer(
        test_path,
        test_params,
        alice_node,
        bob_node,
        channel_id,
        alice_descriptor.clone(),
        bob_descriptor.clone(),
    );
    off_chain_close_finalize(
        test_path,
        alice_node,
        bob_node,
        channel_id,
        alice_descriptor.clone(),
        bob_descriptor.clone(),
        test_params,
    );

    let offer = offer_common(test_params, alice_node, &channel_id);
    bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Offer(offer),
            &alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();
    if let TestPath::AcceptedForceClose
    | TestPath::AcceptedForceClose2
    | TestPath::ConfirmedForceClose
    | TestPath::ConfirmedForceClose2
    | TestPath::FinalizedForceClose
    | TestPath::FinalizedForceClose2 = test_path
    {
        let (_, accept) = bob_node
            .sub_channel_manager
            .accept_sub_channel(&channel_id)
            .unwrap();
        if let TestPath::ConfirmedForceClose
        | TestPath::ConfirmedForceClose2
        | TestPath::FinalizedForceClose
        | TestPath::FinalizedForceClose2 = test_path
        {
            let confirm = alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &SubChannelMessage::Accept(accept),
                    &bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap()
                .unwrap();
            if let TestPath::FinalizedForceClose | TestPath::FinalizedForceClose2 = test_path {
                bob_node
                    .sub_channel_manager
                    .on_sub_channel_message(&confirm, &alice_node.channel_manager.get_our_node_id())
                    .unwrap();
            }
        }
    }

    let (closer, closee) = if let TestPath::OfferedForceClose
    | TestPath::AcceptedForceClose
    | TestPath::ConfirmedForceClose
    | TestPath::FinalizedForceClose = test_path
    {
        (alice_node, bob_node)
    } else {
        (bob_node, alice_node)
    };

    let sub_channel = closer
        .dlc_manager
        .get_store()
        .get_sub_channel(channel_id)
        .unwrap()
        .unwrap();

    let commit_tx = if let TestPath::OfferedForceClose
    | TestPath::OfferedForceClose2
    | TestPath::AcceptedForceClose = test_path
    {
        get_commit_tx_from_node(&closer).remove(0)
    } else if let TestPath::AcceptedForceClose2 | TestPath::ConfirmedForceClose2 = test_path {
        if let SubChannelState::Accepted(a) = &sub_channel.state {
            a.commitment_transactions[0].clone()
        } else {
            unreachable!();
        }
    } else if let TestPath::ConfirmedForceClose | TestPath::FinalizedForceClose = test_path {
        if let SubChannelState::Confirmed(c) = &sub_channel.state {
            c.commitment_transactions[0].clone()
        } else {
            unreachable!();
        }
    } else {
        get_commit_tx_from_node(&closer).remove(0)
    };

    force_close_common(
        sub_channel,
        closer,
        closee,
        &commit_tx,
        &electrs,
        generate_blocks,
    );
}

fn force_close_off_chain_close_tests<F, G>(
    test_path: &TestPath,
    test_params: &TestParams,
    alice_node: &mut LnDlcParty,
    bob_node: &mut LnDlcParty,
    channel_id: ChannelId,
    electrs: Arc<ElectrsBlockchainProvider>,
    get_commit_tx_from_node: &F,
    generate_blocks: &G,
) where
    F: Fn(&LnDlcParty) -> Vec<Transaction>,
    G: Fn(u64),
{
    let sub_channel = alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(channel_id)
        .unwrap()
        .unwrap();

    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    assert_channel_contract_state!(alice_node.dlc_manager, dlc_channel_id, Confirmed);

    let (close_offer, _) = alice_node
        .sub_channel_manager
        .offer_subchannel_close(&channel_id, test_params.contract_input.accept_collateral)
        .unwrap();

    if let TestPath::CloseAcceptedForceClose
    | TestPath::CloseAcceptedForceClose2
    | TestPath::CloseConfirmedForceClose
    | TestPath::CloseConfirmedForceClose2
    | TestPath::CloseFinalizedForceClose = test_path
    {
        bob_node
            .sub_channel_manager
            .on_sub_channel_message(
                &SubChannelMessage::CloseOffer(close_offer),
                &alice_node.channel_manager.get_our_node_id(),
            )
            .unwrap();
        let (accept, _) = bob_node
            .sub_channel_manager
            .accept_subchannel_close_offer(&channel_id)
            .unwrap();
        if let TestPath::CloseConfirmedForceClose
        | TestPath::CloseConfirmedForceClose2
        | TestPath::CloseFinalizedForceClose = test_path
        {
            let confirm = alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &SubChannelMessage::CloseAccept(accept),
                    &bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap()
                .unwrap();
            if let TestPath::CloseFinalizedForceClose = test_path {
                bob_node
                    .sub_channel_manager
                    .on_sub_channel_message(&confirm, &alice_node.channel_manager.get_our_node_id())
                    .unwrap();
            }
        }
    }

    let (closer, closee) = if let TestPath::CloseOfferedForceClose
    | TestPath::CloseAcceptedForceClose
    | TestPath::CloseConfirmedForceClose
    | TestPath::CloseFinalizedForceClose = test_path
    {
        (alice_node, bob_node)
    } else {
        (bob_node, alice_node)
    };

    let commit_tx = get_commit_tx_from_node(&closer).remove(0);

    force_close_common(
        sub_channel,
        closer,
        closee,
        &commit_tx,
        &electrs,
        generate_blocks,
    );
}

fn force_close_common<F>(
    sub_channel: SubChannel,
    closer: &mut LnDlcParty,
    closee: &mut LnDlcParty,
    commit_tx: &Transaction,
    electrs: &Arc<ElectrsBlockchainProvider>,
    generate_blocks: &F,
) where
    F: Fn(u64),
{
    let dlc_channel_id_closer = sub_channel.get_dlc_channel_id(0).unwrap();

    let sub_channel = closee
        .dlc_manager
        .get_store()
        .get_sub_channel(sub_channel.channel_id)
        .unwrap()
        .unwrap();
    let dlc_channel_id_closee = sub_channel.get_dlc_channel_id(0);

    let channel_id = sub_channel.channel_id;

    closer
        .sub_channel_manager
        .force_close_sub_channel(&channel_id)
        .expect("To be able to force close offered channel");

    generate_blocks(500);
    closer.update_to_chain_tip();
    closer.process_events();

    assert_sub_channel_state!(closer.sub_channel_manager, &channel_id; OnChainClosed);

    generate_blocks(3);

    closer.update_to_chain_tip();
    closee.update_to_chain_tip();
    closee.process_events();

    assert_sub_channel_state!(closee.sub_channel_manager, &channel_id; CounterOnChainClosed);

    generate_blocks(500);

    closer.update_to_chain_tip();
    closer.process_events();
    closee.update_to_chain_tip();
    closee.process_events();

    generate_blocks(2);

    closer.update_to_chain_tip();
    closer.process_events();
    closee.update_to_chain_tip();
    closee.process_events();

    assert_channel_state_unlocked!(closer.dlc_manager, dlc_channel_id_closer, Closed);
    if let Some(dlc_channel_id_closee) = dlc_channel_id_closee {
        assert_channel_state_unlocked!(closee.dlc_manager, dlc_channel_id_closee, CounterClosed);
    }

    assert!(closer
        .dlc_manager
        .get_chain_monitor()
        .lock()
        .unwrap()
        .is_empty());
    assert!(closee
        .dlc_manager
        .get_chain_monitor()
        .lock()
        .unwrap()
        .is_empty());

    let all_spent = electrs
        .get_outspends(&commit_tx.txid())
        .unwrap()
        .into_iter()
        .all(|x| {
            if let OutSpendResp::Spent(_) = x {
                true
            } else {
                false
            }
        });

    assert!(all_spent);
}
