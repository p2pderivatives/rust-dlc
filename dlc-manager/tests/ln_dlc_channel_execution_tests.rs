#[macro_use]
mod test_utils;
mod console_logger;
mod custom_signer;

use std::{collections::HashMap, convert::TryInto, sync::Arc, time::SystemTime};

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
    channel::Channel, manager::Manager, sub_channel_manager::SubChannelManager,
    subchannel::SubChannelState, Blockchain, ChannelId, Oracle, Signer, Storage, Utxo, Wallet,
};
use dlc_messages::{ChannelMessage, Message, SubChannelMessage};
use electrs_blockchain_provider::{ElectrsBlockchainProvider, OutSpendResp};
use lightning::{
    chain::{
        chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator},
        keysinterface::{KeysInterface, KeysManager, Recipient},
        BestBlock, Filter, Listen,
    },
    ln::{
        channelmanager::{ChainParameters, PaymentId},
        peer_handler::{IgnoringMessageHandler, MessageHandler},
    },
    routing::{
        gossip::{NetworkGraph, NodeId},
        router::{RouteHop, RouteParameters},
        scoring::{ChannelUsage, Score},
    },
    util::{
        config::UserConfig,
        events::{Event, EventHandler, EventsProvider, PaymentPurpose},
        ser::Writeable,
    },
};
use lightning_persister::FilesystemPersister;
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
    Arc<dyn Filter>,
    Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    Arc<ElectrsBlockchainProvider>,
    Arc<ConsoleLogger>,
    Arc<FilesystemPersister>,
>;

pub(crate) type ChannelManager = lightning::ln::channelmanager::ChannelManager<
    Arc<ChainMonitor>,
    Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    Arc<CustomKeysManager>,
    Arc<ElectrsBlockchainProvider>,
    Arc<ConsoleLogger>,
>;

pub(crate) type PeerManager = lightning::ln::peer_handler::PeerManager<
    MockSocketDescriptor,
    Arc<ChannelManager>,
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<ConsoleLogger>,
    Arc<IgnoringMessageHandler>,
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
>;

struct LnDlcParty {
    peer_manager: Arc<PeerManager>,
    channel_manager: Arc<ChannelManager>,
    chain_monitor: Arc<ChainMonitor>,
    keys_manager: Arc<CustomKeysManager>,
    logger: Arc<ConsoleLogger>,
    network_graph: NetworkGraph<Arc<ConsoleLogger>>,
    chain_height: u64,
    sub_channel_manager: DlcSubChannelManager,
    dlc_manager: Arc<DlcChannelManager>,
    blockchain: Arc<ElectrsBlockchainProvider>,
    mock_blockchain: Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    wallet: Arc<SimpleWallet<Arc<ElectrsBlockchainProvider>, Arc<MemoryStorage>>>,
    persister: Arc<FilesystemPersister>,
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
    SplitCheat,
}

impl LnDlcParty {
    fn update_to_chain_tip(&mut self) {
        let chain_tip_height = self.blockchain.get_blockchain_height().unwrap();
        for i in self.chain_height + 1..=chain_tip_height {
            let block = self.blockchain.get_block_at_height(i).unwrap();
            self.channel_manager.block_connected(&block, i as u32);
            for ftxo in self.chain_monitor.list_monitors() {
                self.chain_monitor
                    .get_monitor(ftxo)
                    .unwrap()
                    .block_connected(
                        &block.header,
                        &block.txdata.iter().enumerate().collect::<Vec<_>>(),
                        i as u32,
                        self.blockchain.clone(),
                        self.blockchain.clone(),
                        self.logger.clone(),
                    );
            }
        }
        self.chain_height = chain_tip_height;
        self.sub_channel_manager.check_for_watched_tx().unwrap();
    }

    fn process_events(&self) {
        self.peer_manager.process_events();
        self.channel_manager.process_pending_events(self);
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
    let keys_manager = KeysManager::new(&key, cur.as_secs(), cur.subsec_nanos());
    let consistent_keys_manager = Arc::new(CustomKeysManager::new(keys_manager));
    let logger = Arc::new(console_logger::ConsoleLogger { name });

    std::fs::create_dir_all(data_dir).unwrap();
    let persister = Arc::new(FilesystemPersister::new(data_dir.to_string()));

    let mock_blockchain = Arc::new(MockBlockchain::new(blockchain_provider.clone()));

    let chain_monitor: Arc<ChainMonitor> =
        Arc::new(lightning::chain::chainmonitor::ChainMonitor::new(
            None,
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
    let (blockhash, chain_height, channel_manager) = {
        let height = blockchain_provider.get_blockchain_height().unwrap();
        let last_block = blockchain_provider.get_block_at_height(height).unwrap();

        let chain_params = ChainParameters {
            network: Network::Regtest,
            best_block: BestBlock::new(last_block.block_hash(), height as u32),
        };

        let fresh_channel_manager = Arc::new(ChannelManager::new(
            blockchain_provider.clone(),
            chain_monitor.clone(),
            mock_blockchain.clone(),
            logger.clone(),
            consistent_keys_manager.clone(),
            user_config,
            chain_params,
        ));
        (last_block.block_hash(), height, fresh_channel_manager)
    };

    // Step 12: Initialize the PeerManager
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut ephemeral_bytes = [0; 32];
    thread_rng().fill_bytes(&mut ephemeral_bytes);
    let lightning_msg_handler = MessageHandler {
        chan_handler: channel_manager.clone(),
        route_handler: Arc::new(IgnoringMessageHandler {}),
        onion_message_handler: Arc::new(IgnoringMessageHandler {}),
    };
    let peer_manager = PeerManager::new(
        lightning_msg_handler,
        consistent_keys_manager
            .get_node_secret(Recipient::Node)
            .unwrap(),
        current_time.try_into().unwrap(),
        &ephemeral_bytes,
        logger.clone(),
        Arc::new(IgnoringMessageHandler {}),
    );

    let network_graph = NetworkGraph::new(blockhash, logger.clone());

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

    let sub_channel_manager = SubChannelManager::new(
        channel_manager.clone(),
        dlc_manager.clone(),
        blockchain_provider.get_blockchain_height().unwrap(),
    );

    LnDlcParty {
        peer_manager: Arc::new(peer_manager),
        channel_manager: channel_manager.clone(),
        chain_monitor,
        keys_manager: consistent_keys_manager,
        logger,
        network_graph,
        chain_height,
        sub_channel_manager,
        dlc_manager,
        blockchain: blockchain_provider.clone(),
        mock_blockchain,
        wallet,
        persister,
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

// #[derive(Debug)]
// pub struct TestParams {
//     pub oracles: Vec<p2pd_oracle_client::P2PDOracleClient>,
//     pub contract_input: ContractInput,
// }

fn ln_dlc_test(test_path: TestPath) {
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
            alice_descriptor,
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
    );

    let payment_preimage = lightning::ln::PaymentPreimage([0; 32]);
    let payment_hash = lightning::ln::PaymentHash(
        bitcoin::hashes::sha256::Hash::hash(&payment_preimage.0[..]).into_inner(),
    );
    let _ = bob_node
        .channel_manager
        .create_inbound_payment_for_hash(payment_hash, None, 7200)
        .unwrap();

    let scorer = TestScorer::with_penalty(0);
    let random_seed_bytes = bob_node.keys_manager.get_secure_random_bytes();
    let route_params = RouteParameters {
        payment_params: payment_params.clone(),
        final_value_msat: 90000000,
        final_cltv_expiry_delta: 70,
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
            .read_channelmonitors(alice_node.keys_manager.clone())
            .unwrap();
        assert!(res.len() == 1);
        let (_, channel_monitor) = res.remove(0);
        channel_monitor.get_latest_holder_commitment_txn(&alice_node.logger)
    };

    let pre_split_commit_tx = if let TestPath::CheatPreSplitCommit = test_path {
        Some(get_commit_tx_from_node(&alice_node))
    } else {
        None
    };

    let bob_channel_details = bob_node.channel_manager.list_usable_channels().remove(0);
    let channel_id = bob_channel_details.channel_id;

    offer_sub_channel(&test_params, &alice_node, &bob_node, &channel_id);

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
        final_cltv_expiry_delta: 70,
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

    std::thread::sleep(std::time::Duration::from_secs(1));

    let sub_channel = alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(channel_id)
        .unwrap()
        .unwrap();

    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();

    if let TestPath::RenewedClose = test_path {
        renew(&alice_node, &bob_node, dlc_channel_id, &test_params);
    } else if let TestPath::SettledClose | TestPath::SettledRenewedClose = test_path {
        settle(&alice_node, &bob_node, dlc_channel_id, &test_params);

        if let TestPath::SettledRenewedClose = test_path {
            renew(&alice_node, &bob_node, dlc_channel_id, &test_params);
        }
    }

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    if let TestPath::OffChainClosed | TestPath::SplitCheat = test_path {
        if let TestPath::SplitCheat = test_path {
            alice_node.dlc_manager.get_store().save();
        }

        let (close_offer, _) = alice_node
            .sub_channel_manager
            .offer_subchannel_close(&channel_id, test_params.contract_input.accept_collateral)
            .unwrap();

        bob_node
            .sub_channel_manager
            .on_sub_channel_message(
                &SubChannelMessage::CloseOffer(close_offer),
                &alice_node.channel_manager.get_our_node_id(),
            )
            .unwrap();

        let (close_accept, _) = bob_node
            .sub_channel_manager
            .accept_subchannel_close_offer(&channel_id)
            .unwrap();

        let close_confirm = alice_node
            .sub_channel_manager
            .on_sub_channel_message(
                &SubChannelMessage::CloseAccept(close_accept),
                &bob_node.channel_manager.get_our_node_id(),
            )
            .unwrap()
            .unwrap();

        let close_finalize = bob_node
            .sub_channel_manager
            .on_sub_channel_message(
                &close_confirm,
                &alice_node.channel_manager.get_our_node_id(),
            )
            .unwrap()
            .unwrap();

        alice_node
            .sub_channel_manager
            .on_sub_channel_message(&close_finalize, &bob_node.channel_manager.get_our_node_id())
            .unwrap();

        offer_sub_channel(&test_params, &alice_node, &bob_node, &channel_id);

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
                .initiate_force_close_sub_channel(&channel_id)
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

    alice_node
        .sub_channel_manager
        .initiate_force_close_sub_channel(&channel_id)
        .unwrap();

    generate_blocks(500);

    alice_node
        .sub_channel_manager
        .finalize_force_close_sub_channels(&channel_id)
        .unwrap();

    generate_blocks(1);

    bob_node.update_to_chain_tip();

    if let TestPath::CheatPostSplitCommit = test_path {
        let cheat_tx = post_split_commit_tx.unwrap()[0].clone();
        ln_cheated_check(&cheat_tx, &mut bob_node, electrs.clone(), &generate_blocks);
    }
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

fn offer_sub_channel(
    test_params: &TestParams,
    alice_node: &LnDlcParty,
    bob_node: &LnDlcParty,
    channel_id: &ChannelId,
) {
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

    bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Offer(offer),
            &alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Offered);

    let (_, accept) = bob_node
        .sub_channel_manager
        .accept_sub_channel(channel_id)
        .unwrap();

    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Accepted);

    bob_node.process_events();
    let confirm = alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Accept(accept),
            &bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    assert_sub_channel_state!(alice_node.sub_channel_manager, channel_id, Signed);

    alice_node.process_events();
    let finalize = bob_node
        .sub_channel_manager
        .on_sub_channel_message(&confirm, &alice_node.channel_manager.get_our_node_id())
        .unwrap()
        .unwrap();

    assert_sub_channel_state!(bob_node.sub_channel_manager, channel_id, Signed);

    bob_node.process_events();
    alice_node
        .sub_channel_manager
        .on_sub_channel_message(&finalize, &bob_node.channel_manager.get_our_node_id())
        .unwrap();
    alice_node.process_events();
}
