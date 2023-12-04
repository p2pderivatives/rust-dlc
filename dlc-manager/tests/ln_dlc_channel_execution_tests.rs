#[macro_use]
mod test_utils;
mod console_logger;
mod custom_signer;

use std::{
    collections::HashMap,
    convert::TryInto,
    sync::{atomic::AtomicU8, Arc, Mutex},
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
use bitcoincore_rpc::{Client, RpcApi};
use console_logger::ConsoleLogger;
use custom_signer::{CustomKeysManager, CustomSigner};
use dlc_manager::{
    channel::Channel, contract::Contract, manager::Manager, sub_channel_manager::SubChannelManager,
    subchannel::SubChannelState, Blockchain, DlcChannelId, Oracle, Signer, Storage, Utxo, Wallet,
};
use dlc_messages::{
    sub_channel::{SubChannelAccept, SubChannelOffer},
    ChannelMessage, Message, SubChannelMessage,
};
use electrs_blockchain_provider::{ElectrsBlockchainProvider, OutSpendResp};
use lightning::{
    chain::{
        chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator},
        BestBlock, Confirm,
    },
    events::{Event, EventHandler, EventsProvider, PaymentPurpose},
    ln::{
        channelmanager::{ChainParameters, PaymentId, RecipientOnionFields},
        peer_handler::{IgnoringMessageHandler, MessageHandler},
        ChannelId,
    },
    routing::{
        gossip::{NetworkGraph, NodeId},
        router::{DefaultRouter, Path, RouteParameters},
        scoring::{ChannelUsage, ScoreLookUp, ScoreUpdate},
    },
    sign::{EntropySource, KeysManager},
    util::{config::UserConfig, ser::Writeable},
};
use lightning_persister::fs_store::FilesystemStore;
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
    PublicKey, Secp256k1,
};
use simple_wallet::SimpleWallet;
use simple_wallet::WalletStorage;

type ChainMonitor = lightning::chain::chainmonitor::ChainMonitor<
    CustomSigner,
    Arc<EsploraSyncClient<Arc<ConsoleLogger>>>,
    Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    Arc<ConsoleLogger>,
    Arc<FilesystemStore>,
>;

pub(crate) type ChannelManager = lightning::ln::channelmanager::ChannelManager<
    Arc<ChainMonitor>,
    Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    Arc<CustomKeysManager>,
    Arc<CustomKeysManager>,
    Arc<CustomKeysManager>,
    Arc<MockBlockchain<Arc<ElectrsBlockchainProvider>>>,
    Arc<
        DefaultRouter<
            Arc<NetworkGraph<Arc<ConsoleLogger>>>,
            Arc<ConsoleLogger>,
            Arc<Mutex<TestScorer>>,
            (),
            TestScorer,
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
    Arc<ChainMonitor>,
    Arc<MemoryStorage>,
    Arc<ElectrsBlockchainProvider>,
    Arc<MockOracle>,
    Arc<MockTime>,
    Arc<ElectrsBlockchainProvider>,
    Arc<DlcChannelManager>,
    CustomSigner,
    Arc<CustomKeysManager>,
    CustomSigner,
    Arc<CustomKeysManager>,
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
    persister: Arc<FilesystemStore>,
    esplora_sync: Arc<EsploraSyncClient<Arc<ConsoleLogger>>>,
}

impl Drop for LnDlcParty {
    fn drop(&mut self) {
        let data_dir = self.persister.get_data_dir();
        std::fs::remove_dir_all(data_dir).unwrap();
    }
}

impl LnDlcParty {
    fn update_to_chain_tip(&mut self) {
        let confirmables = vec![
            &*self.channel_manager as &(dyn Confirm + Sync + Send),
            &*self.chain_monitor as &(dyn Confirm + Sync + Send),
        ];

        self.esplora_sync.sync(confirmables).unwrap();
        self.dlc_manager.periodic_chain_monitor().unwrap();

        self.sub_channel_manager.periodic_check();
        self.dlc_manager.periodic_check().unwrap();
    }

    fn process_events(&self) {
        self.channel_manager.process_pending_events(self);
        self.peer_manager.process_events();
        self.channel_manager.timer_tick_occurred();
        self.chain_monitor.process_pending_events(self);
    }
}

struct LnDlcTestParams {
    alice_node: LnDlcParty,
    bob_node: LnDlcParty,
    alice_node_id: PublicKey,
    bob_node_id: PublicKey,
    alice_descriptor: MockSocketDescriptor,
    bob_descriptor: MockSocketDescriptor,
    electrs: Arc<ElectrsBlockchainProvider>,
    sink_rpc: Client,
    funding_txo: lightning::chain::transaction::OutPoint,
    channel_id: ChannelId,
    test_params: TestParams,
}

impl LnDlcTestParams {
    fn generate_blocks(&self, nb_blocks: u64) {
        generate_blocks(nb_blocks, &self.electrs, &self.sink_rpc);
    }
}

#[derive(PartialEq, Eq)]
enum TargetState {
    OfferSent,
    OfferReceived,
    Accepted,
    Confirmed,
    Finalized,
}

static PAYMENT_COUNTER: AtomicU8 = AtomicU8::new(0);

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
/// [`ScoreLookUp`] implementation that uses a fixed penalty.
pub struct TestScorer {
    penalty_msat: u64,
}

impl TestScorer {
    /// Creates a new scorer using `penalty_msat`.
    pub fn with_penalty(penalty_msat: u64) -> Self {
        Self { penalty_msat }
    }
}

impl ScoreLookUp for TestScorer {
    type ScoreParams = ();
    fn channel_penalty_msat(
        &self,
        _: u64,
        _: &NodeId,
        _: &NodeId,
        _: ChannelUsage,
        _score_params: &Self::ScoreParams,
    ) -> u64 {
        self.penalty_msat
    }
}

impl ScoreUpdate for TestScorer {
    fn payment_path_failed(&mut self, _path: &Path, _short_channel_id: u64) {}

    fn payment_path_successful(&mut self, _path: &Path) {}

    fn probe_failed(&mut self, _path: &Path, _short_channel_id: u64) {}

    fn probe_successful(&mut self, _path: &Path) {}
}

impl EventHandler for LnDlcParty {
    fn handle_event(&self, event: lightning::events::Event) {
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
            Event::SpendableOutputs { outputs, .. } => {
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
                self.blockchain.broadcast_transactions(&[&spending_tx]);
            }
            Event::ChannelClosed {
                channel_id, reason, ..
            } => {
                if let Err(error) = self
                    .sub_channel_manager
                    .notify_ln_channel_closed(channel_id, &reason)
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
    let persister = Arc::new(FilesystemStore::new(data_dir.to_string().into()));

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
            mock_blockchain.clone(),
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
        (),
    ));

    let channel_manager = {
        let height = blockchain_provider.get_blockchain_height().unwrap();
        let last_block = blockchain_provider.get_block_at_height(height).unwrap();

        let chain_params = ChainParameters {
            network: Network::Regtest,
            best_block: BestBlock::new(last_block.block_hash(), height as u32),
        };

        Arc::new(ChannelManager::new(
            mock_blockchain.clone(),
            chain_monitor.clone(),
            mock_blockchain.clone(),
            router,
            logger.clone(),
            consistent_keys_manager.clone(),
            consistent_keys_manager.clone(),
            consistent_keys_manager.clone(),
            user_config,
            chain_params,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
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

    let sub_channel_manager = Arc::new(
        SubChannelManager::new(
            channel_manager.clone(),
            dlc_manager.clone(),
            chain_monitor.clone(),
            consistent_keys_manager.clone(),
        )
        .unwrap(),
    );

    let lightning_msg_handler = MessageHandler {
        chan_handler: sub_channel_manager.clone(),
        route_handler: Arc::new(IgnoringMessageHandler {}),
        onion_message_handler: Arc::new(IgnoringMessageHandler {}),
        custom_message_handler: Arc::new(IgnoringMessageHandler {}),
    };
    let peer_manager = PeerManager::new(
        lightning_msg_handler,
        current_time.try_into().unwrap(),
        &ephemeral_bytes,
        logger.clone(),
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
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_stable(&mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_renewed_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);
    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    let contract_id = assert_channel_contract_state!(
        test_params.alice_node.dlc_manager,
        dlc_channel_id,
        Confirmed
    );

    renew(&test_params, &dlc_channel_id);

    assert_contract_state_unlocked!(test_params.alice_node.dlc_manager, contract_id, Closed);
    assert_contract_state_unlocked!(test_params.bob_node.dlc_manager, contract_id, Closed);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_stable(&mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_open_disconnect_renewed_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    offer_sub_channel_with_reconnect(&test_params);
    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    let contract_id = assert_channel_contract_state!(
        test_params.alice_node.dlc_manager,
        dlc_channel_id,
        Confirmed
    );

    renew(&test_params, &dlc_channel_id);

    assert_contract_state_unlocked!(test_params.alice_node.dlc_manager, contract_id, Closed);
    assert_contract_state_unlocked!(test_params.bob_node.dlc_manager, contract_id, Closed);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_stable(&mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_open_disconnect_settled_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    offer_sub_channel_with_reconnect(&test_params);
    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    let contract_id = assert_channel_contract_state!(
        test_params.alice_node.dlc_manager,
        dlc_channel_id,
        Confirmed
    );

    settle(&test_params, &dlc_channel_id);

    assert_contract_state_unlocked!(test_params.alice_node.dlc_manager, contract_id, Closed);
    assert_contract_state_unlocked!(test_params.bob_node.dlc_manager, contract_id, Closed);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_stable(&mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_settled_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);
    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    let contract_id = assert_channel_contract_state!(
        test_params.alice_node.dlc_manager,
        dlc_channel_id,
        Confirmed
    );

    settle(&test_params, &dlc_channel_id);

    assert_contract_state_unlocked!(test_params.alice_node.dlc_manager, contract_id, Closed);
    assert_contract_state_unlocked!(test_params.bob_node.dlc_manager, contract_id, Closed);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_stable(&mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_settled_renewed_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);
    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    let contract_id = assert_channel_contract_state!(
        test_params.alice_node.dlc_manager,
        dlc_channel_id,
        Confirmed
    );

    settle(&test_params, &dlc_channel_id);
    renew(&test_params, &dlc_channel_id);

    assert_contract_state_unlocked!(test_params.alice_node.dlc_manager, contract_id, Closed);
    assert_contract_state_unlocked!(test_params.bob_node.dlc_manager, contract_id, Closed);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_stable(&mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_pre_split_cheat() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    let pre_split_commit_tx =
        get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo);
    open_sub_channel(&test_params);
    cheat_with_revoked_tx(&pre_split_commit_tx[0], &mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_post_split_cheat() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    test_params.alice_node.mock_blockchain.start_discard();

    let post_split_commit_tx =
        get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo);

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 90000);

    let alice_commit = get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo);
    test_params
        .alice_node
        .mock_blockchain
        .discard_id(alice_commit[0].txid());

    let bob_commit = get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo);
    test_params
        .bob_node
        .mock_blockchain
        .discard_id(bob_commit[0].txid());

    mocks::mock_time::set_time(EVENT_MATURITY as u64);
    test_params
        .alice_node
        .sub_channel_manager
        .force_close_sub_channel(&test_params.channel_id)
        .unwrap();

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Closing
    );

    test_params.generate_blocks(1);

    test_params.alice_node.update_to_chain_tip();
    test_params.bob_node.update_to_chain_tip();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();

    test_params.generate_blocks(700);

    test_params.alice_node.update_to_chain_tip();
    test_params.bob_node.update_to_chain_tip();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();

    test_params.generate_blocks(1);

    test_params.alice_node.update_to_chain_tip();
    test_params.bob_node.update_to_chain_tip();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();

    test_params.generate_blocks(1);

    cheat_with_revoked_tx(&post_split_commit_tx[0], &mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_force_close_after_off_chain_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    off_chain_close(&test_params);

    let alice_commit = get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo);

    test_params
        .alice_node
        .channel_manager
        .force_close_broadcasting_latest_txn(&test_params.channel_id, &test_params.bob_node_id)
        .unwrap();

    test_params.generate_blocks(501);
    test_params.alice_node.update_to_chain_tip();
    test_params.bob_node.update_to_chain_tip();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();

    test_params.generate_blocks(1);

    let all_spent = test_params
        .electrs
        .get_outspends(&alice_commit[0].txid())
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

#[test]
#[ignore]
fn ln_dlc_split_cheat() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    // Open DLC sub-channel.
    open_sub_channel(&test_params);
    // Save the state after first sub-channel opening.
    test_params.alice_node.dlc_manager.get_store().save();

    // Close the DLC sub-channel off-chain (reverting to regular LN channel).
    off_chain_close(&test_params);

    // Re-open a DLC sub-channel.
    open_sub_channel(&test_params);

    // Restore the state of alice storage to that of the first opened DLC sub-channel.
    test_params.alice_node.dlc_manager.get_store().rollback();

    // Get the transaction id of the split transaction for the first DLC sub-channel.
    let split_tx_id = match test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap()
        .state
    {
        SubChannelState::Signed(s) => s.split_tx.transaction.txid(),
        a => panic!("Unexpected state {:?}", a),
    };

    // Make Alice close the transaction. She will force close with the first split transaction
    // which has already been revoked because we rolled back her state.
    test_params
        .alice_node
        .sub_channel_manager
        .force_close_sub_channel(&test_params.channel_id)
        .unwrap();

    test_params.generate_blocks(1);

    // On seeing the revoked split transaction, Bob should react by spending both outputs.
    test_params.bob_node.update_to_chain_tip();

    let outspends = test_params.electrs.get_outspends(&split_tx_id).unwrap();

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
    // Bob should have used the same transaction to spend both outputs.
    assert_eq!(spent[0].txid, spent[1].txid);

    let spending_tx = test_params.electrs.get_transaction(&spent[0].txid).unwrap();

    // We make sure that the output address of the penalty transaction belongs to Bob.
    let receive_addr =
        Address::from_script(&spending_tx.output[0].script_pubkey, Network::Regtest).unwrap();

    assert!(test_params
        .bob_node
        .dlc_manager
        .get_store()
        .get_addresses()
        .unwrap()
        .iter()
        .any(|x| *x == receive_addr));
}

#[test]
#[ignore]
fn ln_dlc_rejected_offer() {
    let test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    reject_offer(&test_params);
}

#[test]
#[ignore]
fn ln_dlc_rejected_close() {
    let test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    off_chain_close_offer(&test_params, false);

    let reject = test_params
        .bob_node
        .sub_channel_manager
        .reject_sub_channel_close_offer(test_params.channel_id)
        .unwrap();

    test_params
        .alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Reject(reject),
            &test_params.bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Signed
    );
    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Signed
    );
}

#[test]
#[ignore]
fn ln_dlc_reconnect() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    offer_sub_channel_with_reconnect(&test_params);

    off_chain_close_with_reconnect(&test_params);

    offer_sub_channel_with_reconnect(&test_params);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_stable(&mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_force_close_after_three_sub_channel_open() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    off_chain_close(&test_params);

    open_sub_channel(&test_params);

    off_chain_close(&test_params);

    open_sub_channel(&test_params);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_stable(&mut test_params);
}

#[test]
#[ignore]
fn ln_dlc_offer_after_offchain_close_disconnect() {
    let test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    off_chain_close_offer(&test_params, false);

    let (close_accept, _) = test_params
        .bob_node
        .sub_channel_manager
        .accept_subchannel_close_offer(&test_params.channel_id)
        .unwrap();

    let close_confirm = test_params
        .alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::CloseAccept(close_accept),
            &test_params.bob_node_id,
        )
        .unwrap()
        .unwrap();
    let _ = test_params
        .bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &close_confirm,
            &test_params.alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    generate_offer(
        &test_params.test_params,
        &test_params.bob_node,
        &test_params.channel_id,
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    reconnect(&test_params);

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    assert_eq!(
        0,
        test_params
            .alice_node
            .sub_channel_manager
            .periodic_check()
            .len()
    );
    let msgs = test_params.bob_node.sub_channel_manager.periodic_check();

    let (close_finalize, offer) = match msgs.as_slice() {
        [(c @ SubChannelMessage::CloseFinalize(_), _), (o @ SubChannelMessage::Offer(_), _)] => {
            (c, o)
        }
        msgs => panic!("Unexpected messages: {:?}", msgs),
    };

    test_params
        .alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            close_finalize,
            &test_params.bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap();
    assert_sub_channel_state!(test_params.alice_node.sub_channel_manager, &test_params.channel_id; OffChainClosed);

    test_params
        .alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            offer,
            &test_params.bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap();
    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );
}

#[test]
#[ignore]
fn ln_dlc_disconnected_force_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    test_params
        .alice_node
        .peer_manager
        .socket_disconnected(&test_params.alice_descriptor);

    test_params
        .bob_node
        .peer_manager
        .socket_disconnected(&test_params.bob_descriptor);

    force_close_stable(&mut test_params);
}

#[test]
#[ignore]
/// Force close triggered by the party who sent the subchannel offer.
fn ln_dlc_offered_force_close() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::OfferReceived, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    let commit_tx = get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo);
    force_close_mid_protocol(&mut test_params, false, &commit_tx[0]);
}

#[test]
#[ignore]
/// Force close triggered by the party who received the subchannel offer.
fn ln_dlc_offered_force_close2() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::OfferReceived, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    let commit_tx = get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo);
    force_close_mid_protocol(&mut test_params, true, &commit_tx[0]);
}

#[test]
#[ignore]
/// Force close triggered by the party who sent the subchannel offer, while the counterparty
/// has accepted the offer (the offering party has not yet processed the accept message).
fn ln_dlc_accepted_force_close() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::Accepted, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Accepted
    );

    let commit_tx = get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo);
    force_close_mid_protocol(&mut test_params, false, &commit_tx[0]);
}

#[test]
#[ignore]
/// Force close triggered by the party who accepted the subchannel offer (the counter party has
/// not yet processed the accept message).
fn ln_dlc_accepted_force_close2() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::Accepted, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Accepted
    );

    let sub_channel = test_params
        .bob_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let commit_tx = if let SubChannelState::Accepted(a) = &sub_channel.state {
        a.commitment_transactions[0].clone()
    } else {
        unreachable!();
    };
    force_close_mid_protocol(&mut test_params, true, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the offer party, after processing the accept message from their
/// counter party.
fn ln_dlc_confirmed_force_close() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::Confirmed, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Confirmed
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Accepted
    );

    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let commit_tx = if let SubChannelState::Confirmed(c) = &sub_channel.state {
        c.commitment_transactions[0].clone()
    } else {
        unreachable!();
    };

    force_close_mid_protocol(&mut test_params, false, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the accept party, after their counter party processed the accepted
/// message (but before they process the confirm message).
fn ln_dlc_confirmed_force_close2() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::Confirmed, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Confirmed
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Accepted
    );

    let sub_channel = test_params
        .bob_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let commit_tx = if let SubChannelState::Accepted(a) = &sub_channel.state {
        a.commitment_transactions[0].clone()
    } else {
        unreachable!();
    };

    force_close_mid_protocol(&mut test_params, true, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the offer party, after their counter party processed the confirm
/// message (but before they process the finalize message).
fn ln_dlc_finalized_force_close() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::Finalized, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Confirmed
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Finalized
    );

    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let commit_tx = if let SubChannelState::Confirmed(c) = &sub_channel.state {
        c.commitment_transactions[0].clone()
    } else {
        unreachable!();
    };

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_mid_protocol(&mut test_params, false, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the accept party, after processing the confirm message (but before
/// their counter party has processed the finalize message).
fn ln_dlc_finalized_force_close2() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::Finalized, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Confirmed
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Finalized
    );

    let commit_tx = get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_mid_protocol(&mut test_params, true, &commit_tx[0]);
}

#[test]
#[ignore]
/// Force close triggered by the party who offered to force close the channel, before their
/// counter party received the offer.
fn ln_dlc_close_offered_force_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::OfferSent, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Signed
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo).remove(0);

    force_close_mid_protocol(&mut test_params, false, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the counter party of the node who made the offer to close the channel
/// off-chain, before the offer was processed.
fn ln_dlc_close_offered_force_close2() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::OfferSent, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Signed
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo).remove(0);

    force_close_mid_protocol(&mut test_params, true, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the party who offered to force close the channel, after their
/// counter party received the offer.
fn ln_dlc_close_offered_force_close3() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::OfferReceived, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo).remove(0);

    force_close_mid_protocol(&mut test_params, false, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the party who received the offer to force close the channel.
fn ln_dlc_close_offered_force_close4() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::OfferReceived, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo).remove(0);

    force_close_mid_protocol(&mut test_params, true, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the party who offered to force close the channel, after their
/// counter party accepted the close offer, but before they processed the close accept message.
fn ln_dlc_close_accepted_force_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::Accepted, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseAccepted
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo).remove(0);

    force_close_mid_protocol(&mut test_params, false, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the party who accepted the close offer, before their counter party
/// processed the close offer message.
fn ln_dlc_close_accepted_force_close2() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::Accepted, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseAccepted
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo).remove(0);

    force_close_mid_protocol(&mut test_params, true, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the party who offered to force close the channel, after they
/// processed the close accept message.
fn ln_dlc_close_confirmed_force_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::Confirmed, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseConfirmed
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseAccepted
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo).remove(0);

    force_close_mid_protocol(&mut test_params, false, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the party who accepted the close offer, after their counter party
/// processed the close accept message.
fn ln_dlc_close_confirmed_force_close2() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::Confirmed, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseConfirmed
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseAccepted
    );

    let commit_tx =
        get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo).remove(0);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    force_close_mid_protocol(&mut test_params, true, &commit_tx);
}

#[test]
#[ignore]
/// Force close triggered by the party who offered to force close the channel, after their
/// counter party processed the close confirm message, but before they processed the close
/// finalize message.
fn ln_dlc_close_finalized_force_close() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    go_to_off_chain_close_state(&test_params, TargetState::Finalized, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseConfirmed
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id;
        OffChainClosed
    );

    let commit_tx =
        get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo).remove(0);

    force_close_mid_protocol(&mut test_params, false, &commit_tx);
}

#[test]
#[ignore]
fn ln_dlc_ldk_auto_close_established_test() {
    let mut test_params = test_init();

    open_sub_channel(&test_params);

    let commit_tx = get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    ldk_auto_close(&mut test_params, &commit_tx[0]);
}

#[test]
#[ignore]
fn ln_dlc_ldk_auto_close_offered_test() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::OfferReceived, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    let commit_tx = get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo);
    ldk_auto_close(&mut test_params, &commit_tx[0]);
}

#[test]
#[ignore]
fn ln_dlc_ldk_auto_close_accepted_test() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::Accepted, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Accepted
    );

    let sub_channel = test_params
        .bob_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let commit_tx = if let SubChannelState::Accepted(a) = &sub_channel.state {
        a.commitment_transactions[0].clone()
    } else {
        unreachable!();
    };

    ldk_auto_close(&mut test_params, &commit_tx);
}

#[test]
#[ignore]
fn ln_dlc_ldk_auto_close_confirmed_test() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::Confirmed, true);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Accepted
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Confirmed
    );

    let sub_channel = test_params
        .bob_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let commit_tx = if let SubChannelState::Confirmed(a) = &sub_channel.state {
        a.commitment_transactions[0].clone()
    } else {
        unreachable!();
    };

    ldk_auto_close(&mut test_params, &commit_tx);
}
#[test]
#[ignore]
fn ln_dlc_ldk_auto_close_finalized_test() {
    let mut test_params = test_init();

    go_to_established_target_state(&test_params, TargetState::Finalized, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Confirmed
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Finalized
    );

    let commit_tx =
        get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo).remove(0);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    ldk_auto_close(&mut test_params, &commit_tx);
}

#[test]
#[ignore]
fn ln_dlc_ldk_auto_close_close_offered_test() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::OfferReceived, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo).remove(0);

    ldk_auto_close(&mut test_params, &commit_tx);
}

#[test]
#[ignore]
fn ln_dlc_ldk_auto_close_close_accepted_test() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::Accepted, false);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseOffered
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseAccepted
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo).remove(0);

    ldk_auto_close(&mut test_params, &commit_tx);
}

#[test]
#[ignore]
fn ln_dlc_ldk_auto_close_close_confirmed_test() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    go_to_off_chain_close_state(&test_params, TargetState::Confirmed, true);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        CloseAccepted
    );

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseConfirmed
    );

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    let commit_tx =
        get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo).remove(0);

    ldk_auto_close(&mut test_params, &commit_tx);
}

#[test]
#[ignore]
fn ln_dlc_ldk_auto_close_close_finalized_test() {
    let mut test_params = test_init();

    make_ln_payment(&test_params.alice_node, &test_params.bob_node, 900000);

    open_sub_channel(&test_params);

    mocks::mock_time::set_time(EVENT_MATURITY as u64);

    go_to_off_chain_close_state(&test_params, TargetState::Finalized, true);

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        CloseConfirmed
    );

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id;
        OffChainClosed
    );

    let commit_tx =
        get_commit_tx_from_node(&test_params.bob_node, &test_params.funding_txo).remove(0);

    ldk_auto_close(&mut test_params, &commit_tx);
}

fn test_init() -> LnDlcTestParams {
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

    let generate_blocks = |nb_blocks: u64| generate_blocks(nb_blocks, &electrs, &sink_rpc);

    generate_blocks(6);

    refresh_wallet(&alice_node.wallet, 200000);

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    let mut alice_descriptor = MockSocketDescriptor::new(0, bob_node.peer_manager.clone());
    let mut bob_descriptor = MockSocketDescriptor::new(1, alice_node.peer_manager.clone());

    alice_descriptor.counter_descriptor = Some(Box::new(bob_descriptor.clone()));
    bob_descriptor.counter_descriptor = Some(Box::new(alice_descriptor.clone()));

    ln_channel_setup(
        &mut alice_node,
        &mut bob_node,
        &alice_descriptor,
        &mut bob_descriptor,
        &generate_blocks,
    );

    std::thread::sleep(std::time::Duration::from_secs(2));

    let channel_details = alice_node.channel_manager.list_channels().remove(0);
    let funding_txo = channel_details.funding_txo.expect("to have a funding txo");
    let channel_id = channel_details.channel_id;
    let alice_node_id = alice_node.channel_manager.get_our_node_id();
    let bob_node_id = bob_node.channel_manager.get_our_node_id();

    LnDlcTestParams {
        alice_node,
        bob_node,
        alice_node_id,
        bob_node_id,
        alice_descriptor,
        bob_descriptor,
        electrs,
        sink_rpc,
        funding_txo,
        channel_id,
        test_params,
    }
}

fn generate_blocks(nb_blocks: u64, electrs: &Arc<ElectrsBlockchainProvider>, sink_rpc: &Client) {
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
}

fn ln_channel_setup<F>(
    alice_node: &mut LnDlcParty,
    bob_node: &mut LnDlcParty,
    alice_descriptor: &MockSocketDescriptor,
    bob_descriptor: &mut MockSocketDescriptor,
    generate_blocks: &F,
) where
    F: Fn(u64),
{
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
        .read_event(bob_descriptor, &initial_send)
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

    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();

    alice_node.process_events();
    bob_node.process_events();

    generate_blocks(6);

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    alice_node.process_events();
    bob_node.process_events();

    assert_eq!(1, alice_node.channel_manager.list_channels().len());

    while alice_node.channel_manager.list_usable_channels().len() != 1 {
        generate_blocks(1);
        alice_node.update_to_chain_tip();
        bob_node.update_to_chain_tip();
        alice_node.peer_manager.process_events();
        bob_node.peer_manager.process_events();
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    assert_eq!(1, alice_node.channel_manager.list_usable_channels().len());

    make_ln_payment(alice_node, bob_node, 90000000);
}

fn make_ln_payment(alice_node: &LnDlcParty, bob_node: &LnDlcParty, final_value_msat: u64) {
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
        payment_params,
        final_value_msat,
        max_total_routing_fee_msat: None,
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
        &(),
        &random_seed_bytes,
    )
    .unwrap();

    let mut payment_id_val = [0u8; 32];

    payment_id_val[31] += PAYMENT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let payment_id = PaymentId(payment_id_val);

    alice_node
        .channel_manager
        .send_spontaneous_payment(
            &route,
            Some(payment_preimage),
            RecipientOnionFields::spontaneous_empty(),
            payment_id,
        )
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
}

fn get_commit_tx_from_node(
    node: &LnDlcParty,
    funding_txo: &lightning::chain::transaction::OutPoint,
) -> Vec<Transaction> {
    node.chain_monitor
        .get_latest_holder_commitment_txn(funding_txo)
        .expect("to be able to get latest holder commitment transaction")
}

fn settle(test_params: &LnDlcTestParams, channel_id: &DlcChannelId) {
    let (settle_offer, bob_key) = test_params
        .alice_node
        .dlc_manager
        .settle_offer(
            channel_id,
            test_params.test_params.contract_input.accept_collateral,
        )
        .unwrap();

    test_params
        .bob_node
        .dlc_manager
        .on_dlc_message(
            &Message::Channel(ChannelMessage::SettleOffer(settle_offer)),
            test_params.alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    let (settle_accept, alice_key) = test_params
        .bob_node
        .dlc_manager
        .accept_settle_offer(channel_id)
        .unwrap();

    let msg = test_params
        .alice_node
        .dlc_manager
        .on_dlc_message(
            &Message::Channel(ChannelMessage::SettleAccept(settle_accept)),
            bob_key,
        )
        .unwrap()
        .unwrap();

    let msg = test_params
        .bob_node
        .dlc_manager
        .on_dlc_message(&msg, alice_key)
        .unwrap()
        .unwrap();

    test_params
        .alice_node
        .dlc_manager
        .on_dlc_message(&msg, bob_key)
        .unwrap();
}

fn renew(test_params: &LnDlcTestParams, dlc_channel_id: &DlcChannelId) {
    let (renew_offer, _) = test_params
        .alice_node
        .dlc_manager
        .renew_offer(
            dlc_channel_id,
            test_params.test_params.contract_input.accept_collateral,
            &test_params.test_params.contract_input,
        )
        .unwrap();

    test_params
        .bob_node
        .dlc_manager
        .on_dlc_message(
            &Message::Channel(ChannelMessage::RenewOffer(renew_offer)),
            test_params.alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    let (accept, _) = test_params
        .bob_node
        .dlc_manager
        .accept_renew_offer(dlc_channel_id)
        .unwrap();

    let msg = test_params
        .alice_node
        .dlc_manager
        .on_dlc_message(
            &Message::Channel(ChannelMessage::RenewAccept(accept)),
            test_params.bob_node_id,
        )
        .unwrap()
        .unwrap();

    let msg = test_params
        .bob_node
        .dlc_manager
        .on_dlc_message(&msg, test_params.alice_node_id)
        .unwrap()
        .unwrap();

    let msg = test_params
        .alice_node
        .dlc_manager
        .on_dlc_message(&msg, test_params.bob_node_id)
        .unwrap()
        .unwrap();

    test_params
        .bob_node
        .dlc_manager
        .on_dlc_message(&msg, test_params.alice_node_id)
        .unwrap();
}

fn cheat_with_revoked_tx(cheat_tx: &Transaction, test_params: &mut LnDlcTestParams) {
    test_params.electrs.broadcast_transactions(&[cheat_tx]);

    // wait for cheat tx to be confirmed
    test_params.generate_blocks(6);

    test_params.bob_node.update_to_chain_tip();

    test_params.bob_node.process_events();

    // LDK should have reacted, this should include a punish tx
    test_params.generate_blocks(1);

    test_params.bob_node.update_to_chain_tip();

    test_params.bob_node.process_events();

    std::thread::sleep(std::time::Duration::from_secs(1));

    let vout = cheat_tx
        .output
        .iter()
        .position(|x| x.script_pubkey.is_v0_p2wsh())
        .expect("to have a p2wsh output");

    let outspends = test_params.electrs.get_outspends(&cheat_tx.txid()).unwrap();

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

    let spend_tx = test_params
        .electrs
        .get_transaction(&outspend_info[vout].txid)
        .unwrap();

    test_params.generate_blocks(6);

    test_params.bob_node.update_to_chain_tip();

    test_params.bob_node.process_events();

    let mut outspend_info = vec![];
    while outspend_info.is_empty() {
        let outspends = test_params.electrs.get_outspends(&spend_tx.txid()).unwrap();
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

    let claim_tx = test_params
        .electrs
        .get_transaction(&outspend_info[0].txid)
        .unwrap();

    let receive_addr =
        Address::from_script(&claim_tx.output[0].script_pubkey, Network::Regtest).unwrap();

    assert!(test_params
        .bob_node
        .dlc_manager
        .get_store()
        .get_addresses()
        .unwrap()
        .iter()
        .any(|x| *x == receive_addr));
}

fn generate_offer(
    test_params: &TestParams,
    offerer: &LnDlcParty,
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

    let offer = offerer
        .sub_channel_manager
        .offer_sub_channel(
            *channel_id,
            &test_params.contract_input,
            &[oracle_announcements],
        )
        .unwrap();

    assert_sub_channel_state!(offerer.sub_channel_manager, channel_id, Offered);

    offer
}

fn open_sub_channel(test_params: &LnDlcTestParams) {
    offer_sub_channel_internal(test_params, false);
}

fn offer_sub_channel_with_reconnect(test_params: &LnDlcTestParams) {
    offer_sub_channel_internal(test_params, true);
}

fn offer_sub_channel_internal(test_params: &LnDlcTestParams, do_reconnect: bool) {
    let offer = generate_offer(
        &test_params.test_params,
        &test_params.alice_node,
        &test_params.channel_id,
    );

    if do_reconnect {
        reconnect(test_params);
        // Alice should resend the offer message to bob as he has not received it yet.
        let mut msgs = test_params.alice_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::Offer(o), p) = msgs.pop().unwrap() {
            assert_eq!(p, test_params.bob_node.channel_manager.get_our_node_id());
            assert_eq!(o, offer);
        } else {
            panic!("Expected an offer message");
        }

        assert_eq!(
            0,
            test_params
                .bob_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
    }

    test_params
        .bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Offer(offer),
            &test_params.alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    if do_reconnect {
        reconnect(test_params);
        assert_eq!(
            0,
            test_params
                .alice_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
        assert_eq!(
            0,
            test_params
                .bob_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
    }

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    let (_, mut accept) = test_params
        .bob_node
        .sub_channel_manager
        .accept_sub_channel(&test_params.channel_id)
        .unwrap();

    if do_reconnect {
        reconnect(test_params);

        assert_sub_channel_state!(
            test_params.alice_node.sub_channel_manager,
            &test_params.channel_id,
            Offered
        );
        assert_sub_channel_state!(
            test_params.bob_node.sub_channel_manager,
            &test_params.channel_id,
            Offered
        );

        test_params
            .alice_node
            .sub_channel_manager
            .on_sub_channel_message(
                &SubChannelMessage::Accept(accept.clone()),
                &test_params.bob_node.channel_manager.get_our_node_id(),
            )
            .expect_err("Should not accept a stale accept message");

        // Bob should re-send the accept message
        let mut msgs = test_params.bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::Accept(a), p) = msgs.pop().unwrap() {
            assert_eq!(p, test_params.alice_node.channel_manager.get_our_node_id());
            assert_eq_accept(&a, &accept);
            accept = a;
        } else {
            panic!("Expected an accept message");
        }

        assert_eq!(
            0,
            test_params
                .alice_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
    }

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Accepted
    );

    let mut confirm = test_params
        .alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Accept(accept),
            &test_params.bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    if do_reconnect {
        reconnect(test_params);

        assert_sub_channel_state!(
            test_params.alice_node.sub_channel_manager,
            &test_params.channel_id,
            Offered
        );
        assert_sub_channel_state!(
            test_params.bob_node.sub_channel_manager,
            &test_params.channel_id,
            Offered
        );

        // Bob should re-send the accept message
        let mut msgs = test_params.bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        assert_eq!(
            0,
            test_params
                .alice_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
        if let (SubChannelMessage::Accept(a), p) = msgs.pop().unwrap() {
            assert_eq!(p, test_params.alice_node.channel_manager.get_our_node_id());
            confirm = test_params
                .alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &SubChannelMessage::Accept(a),
                    &test_params.bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap()
                .unwrap();
        } else {
            panic!("Expected an accept message");
        }
    }

    test_params.alice_node.process_events();
    let mut finalize = test_params
        .bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &confirm,
            &test_params.alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Finalized
    );

    test_params.bob_node.process_events();
    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Confirmed
    );

    if do_reconnect {
        reconnect(test_params);

        assert_sub_channel_state!(
            test_params.alice_node.sub_channel_manager,
            &test_params.channel_id,
            Offered
        );
        assert_sub_channel_state!(
            test_params.bob_node.sub_channel_manager,
            &test_params.channel_id,
            Offered
        );

        // Bob should re-send the accept message
        let mut msgs = test_params.bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        assert_eq!(
            0,
            test_params
                .alice_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
        if let (SubChannelMessage::Accept(a), p) = msgs.pop().unwrap() {
            assert_eq!(p, test_params.alice_node.channel_manager.get_our_node_id());
            let _ = test_params
                .alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &SubChannelMessage::Accept(a),
                    &test_params.bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap()
                .unwrap();
            reconnect(test_params);
            assert_sub_channel_state!(
                test_params.alice_node.sub_channel_manager,
                &test_params.channel_id,
                Offered
            );
            assert_sub_channel_state!(
                test_params.bob_node.sub_channel_manager,
                &test_params.channel_id,
                Offered
            );
            let mut msgs = test_params.bob_node.sub_channel_manager.periodic_check();
            assert_eq!(1, msgs.len());
            assert_eq!(
                0,
                test_params
                    .alice_node
                    .sub_channel_manager
                    .periodic_check()
                    .len()
            );
            if let (SubChannelMessage::Accept(a), p) = msgs.pop().unwrap() {
                assert_eq!(p, test_params.alice_node.channel_manager.get_our_node_id());
                let confirm = test_params
                    .alice_node
                    .sub_channel_manager
                    .on_sub_channel_message(
                        &SubChannelMessage::Accept(a),
                        &test_params.bob_node.channel_manager.get_our_node_id(),
                    )
                    .unwrap()
                    .unwrap();
                finalize = test_params
                    .bob_node
                    .sub_channel_manager
                    .on_sub_channel_message(
                        &confirm,
                        &test_params.alice_node.channel_manager.get_our_node_id(),
                    )
                    .unwrap()
                    .unwrap();
            } else {
                panic!();
            }
        } else {
            panic!("Expected an accept message");
        }
    }

    let revoke = test_params
        .alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &finalize,
            &test_params.bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();
    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Signed
    );
    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Finalized
    );

    if do_reconnect {
        reconnect(test_params);

        assert_sub_channel_state!(
            test_params.alice_node.sub_channel_manager,
            &test_params.channel_id,
            Signed
        );
        assert_sub_channel_state!(
            test_params.bob_node.sub_channel_manager,
            &test_params.channel_id,
            Finalized
        );

        assert_eq!(
            0,
            test_params
                .alice_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
        assert_eq!(
            0,
            test_params
                .bob_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
    } else {
        test_params
            .bob_node
            .sub_channel_manager
            .on_sub_channel_message(
                &revoke,
                &test_params.alice_node.channel_manager.get_our_node_id(),
            )
            .unwrap();
    }
    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &test_params.channel_id,
        Signed
    );
    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Signed
    );

    test_params.alice_node.process_events();
}

fn reconnect(test_params: &LnDlcTestParams) {
    test_params
        .alice_node
        .peer_manager
        .socket_disconnected(&test_params.alice_descriptor);

    test_params
        .bob_node
        .peer_manager
        .socket_disconnected(&test_params.bob_descriptor);

    let initial_send = test_params
        .alice_node
        .peer_manager
        .new_outbound_connection(
            test_params.bob_node.channel_manager.get_our_node_id(),
            test_params.alice_descriptor.clone(),
            None,
        )
        .unwrap();

    test_params
        .bob_node
        .peer_manager
        .new_inbound_connection(test_params.bob_descriptor.clone(), None)
        .unwrap();

    test_params
        .bob_node
        .peer_manager
        .read_event(&mut test_params.bob_descriptor.clone(), &initial_send)
        .unwrap();
    test_params.bob_node.peer_manager.process_events();
    test_params.alice_node.peer_manager.process_events();
    test_params.bob_node.peer_manager.process_events();
    test_params.bob_node.peer_manager.process_events();
    test_params.alice_node.peer_manager.process_events();
    test_params.bob_node.peer_manager.process_events();

    test_params.alice_node.process_events();
    test_params.bob_node.process_events();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();
}

fn reject_offer(test_params: &LnDlcTestParams) {
    let offer = generate_offer(
        &test_params.test_params,
        &test_params.alice_node,
        &test_params.channel_id,
    );

    test_params
        .bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Offer(offer),
            &test_params.alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    assert_sub_channel_state!(
        test_params.bob_node.sub_channel_manager,
        &test_params.channel_id,
        Offered
    );

    let (_, reject) = test_params
        .bob_node
        .sub_channel_manager
        .reject_sub_channel_offer(test_params.channel_id)
        .unwrap();

    assert_sub_channel_state!(test_params.bob_node.sub_channel_manager, &test_params.channel_id; Rejected);

    test_params
        .alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Reject(reject),
            &test_params.bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    assert_sub_channel_state!(test_params.alice_node.sub_channel_manager, &test_params.channel_id; Rejected);
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

fn off_chain_close_offer(test_params: &LnDlcTestParams, do_reconnect: bool) {
    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();

    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    assert_channel_contract_state!(
        test_params.alice_node.dlc_manager,
        dlc_channel_id,
        Confirmed
    );

    let (close_offer, _) = test_params
        .alice_node
        .sub_channel_manager
        .offer_subchannel_close(
            &test_params.channel_id,
            test_params.test_params.contract_input.accept_collateral,
        )
        .unwrap();

    if do_reconnect {
        reconnect(test_params);

        assert_sub_channel_state!(
            test_params.alice_node.sub_channel_manager,
            &test_params.channel_id,
            CloseOffered
        );
        assert_sub_channel_state!(
            test_params.bob_node.sub_channel_manager,
            &test_params.channel_id,
            Signed
        );
        let mut msgs = test_params.alice_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::CloseOffer(c), p) = msgs.pop().unwrap() {
            assert_eq!(p, test_params.bob_node_id);
            assert_eq!(c, close_offer);
        } else {
            panic!("Expected a close offer message");
        }
    }

    test_params
        .bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::CloseOffer(close_offer),
            &test_params.alice_node_id,
        )
        .unwrap();

    if do_reconnect {
        reconnect(test_params);

        assert_eq!(
            0,
            test_params
                .alice_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
        assert_eq!(
            0,
            test_params
                .bob_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
    }
}

fn off_chain_close_finalize(test_params: &LnDlcTestParams, do_reconnect: bool) {
    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();

    let dlc_channel_id = sub_channel.get_dlc_channel_id(0).unwrap();
    let contract_id = assert_channel_contract_state!(
        test_params.alice_node.dlc_manager,
        dlc_channel_id,
        Confirmed
    );
    let (mut close_accept, _) = test_params
        .bob_node
        .sub_channel_manager
        .accept_subchannel_close_offer(&test_params.channel_id)
        .unwrap();

    if do_reconnect {
        reconnect(test_params);

        assert_sub_channel_state!(
            test_params.alice_node.sub_channel_manager,
            &test_params.channel_id,
            CloseOffered
        );
        assert_sub_channel_state!(
            test_params.bob_node.sub_channel_manager,
            &test_params.channel_id,
            CloseOffered
        );

        assert_eq!(
            0,
            test_params
                .alice_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );

        test_params
            .alice_node
            .sub_channel_manager
            .on_sub_channel_message(
                &SubChannelMessage::CloseAccept(close_accept),
                &test_params.bob_node_id,
            )
            .expect_err("Should not accept a stale CloseAccept message");

        let mut msgs = test_params.bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::CloseAccept(c), p) = msgs.pop().unwrap() {
            assert_eq!(p, test_params.alice_node_id);
            close_accept = c;
        } else {
            panic!("Expected a close accept message");
        }
    }

    let mut close_confirm = test_params
        .alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::CloseAccept(close_accept),
            &test_params.bob_node_id,
        )
        .unwrap()
        .unwrap();

    if do_reconnect {
        reconnect(test_params);

        assert_sub_channel_state!(
            test_params.alice_node.sub_channel_manager,
            &test_params.channel_id,
            CloseOffered
        );
        assert_sub_channel_state!(
            test_params.bob_node.sub_channel_manager,
            &test_params.channel_id,
            CloseOffered
        );

        assert_eq!(
            0,
            test_params
                .alice_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
        let mut msgs = test_params.bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::CloseAccept(c), _) = msgs.pop().unwrap() {
            let close_confirm2 = test_params
                .alice_node
                .sub_channel_manager
                .on_sub_channel_message(
                    &SubChannelMessage::CloseAccept(c),
                    &test_params.bob_node.channel_manager.get_our_node_id(),
                )
                .unwrap()
                .unwrap();
            close_confirm = close_confirm2;
        } else {
            panic!("Expected a close accept message");
        }
    }

    let mut close_finalize = test_params
        .bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &close_confirm,
            &test_params.alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    if do_reconnect {
        reconnect(test_params);

        assert_eq!(
            0,
            test_params
                .alice_node
                .sub_channel_manager
                .periodic_check()
                .len()
        );
        let mut msgs = test_params.bob_node.sub_channel_manager.periodic_check();
        assert_eq!(1, msgs.len());
        if let (SubChannelMessage::CloseFinalize(c), _) = msgs.pop().unwrap() {
            close_finalize = SubChannelMessage::CloseFinalize(c);
        } else {
            panic!("Expected a close finalize message");
        }
    }

    test_params
        .alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &close_finalize,
            &test_params.bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    assert_contract_state_unlocked!(test_params.alice_node.dlc_manager, contract_id, Closed);
    assert_contract_state_unlocked!(test_params.bob_node.dlc_manager, contract_id, Closed);

    assert_channel_state_unlocked!(
        test_params.alice_node.dlc_manager,
        dlc_channel_id,
        CollaborativelyClosed
    );
    assert_channel_state_unlocked!(
        test_params.bob_node.dlc_manager,
        dlc_channel_id,
        CollaborativelyClosed
    );

    assert_sub_channel_state!(test_params.alice_node.sub_channel_manager, &test_params.channel_id; OffChainClosed);
    assert_sub_channel_state!(test_params.bob_node.sub_channel_manager, &test_params.channel_id; OffChainClosed);
}

fn off_chain_close(test_params: &LnDlcTestParams) {
    off_chain_close_internal(test_params, false);
}

fn off_chain_close_with_reconnect(test_params: &LnDlcTestParams) {
    off_chain_close_internal(test_params, true);
}

fn off_chain_close_internal(test_params: &LnDlcTestParams, do_reconnect: bool) {
    off_chain_close_offer(test_params, do_reconnect);
    off_chain_close_finalize(test_params, do_reconnect);
}

fn force_close_stable(test_params: &mut LnDlcTestParams) {
    let commit_tx =
        get_commit_tx_from_node(&test_params.alice_node, &test_params.funding_txo).remove(0);
    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();

    let dlc_channel_id_alice = sub_channel.get_dlc_channel_id(0).unwrap();

    let channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_channel(&dlc_channel_id_alice)
        .unwrap()
        .unwrap();

    let contract_id = channel.get_contract_id();

    let sub_channel = test_params
        .bob_node
        .dlc_manager
        .get_store()
        .get_sub_channel(sub_channel.channel_id)
        .unwrap()
        .unwrap();
    let dlc_channel_id_bob = sub_channel.get_dlc_channel_id(0);

    let channel_id = sub_channel.channel_id;

    test_params
        .alice_node
        .sub_channel_manager
        .force_close_sub_channel(&channel_id)
        .expect("To be able to force close offered channel");

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &channel_id,
        Closing
    );

    test_params.generate_blocks(1);

    assert_sub_channel_state!(
        test_params.alice_node.sub_channel_manager,
        &channel_id,
        Closing
    );

    test_params.generate_blocks(500);

    test_params.alice_node.update_to_chain_tip();
    test_params.alice_node.process_events();
    test_params.bob_node.update_to_chain_tip();
    test_params.bob_node.process_events();

    assert_sub_channel_state!(test_params.alice_node.sub_channel_manager, &channel_id; OnChainClosed);
    assert_sub_channel_state!(test_params.bob_node.sub_channel_manager, &channel_id; CounterOnChainClosed);

    if let Some(contract_id) = contract_id {
        assert_channel_state_unlocked!(
            test_params.alice_node.dlc_manager,
            dlc_channel_id_alice,
            Signed,
            Closing
        );
        assert_channel_state_unlocked!(
            test_params.bob_node.dlc_manager,
            dlc_channel_id_alice,
            Signed,
            Closing
        );

        test_params.generate_blocks(dlc_manager::manager::CET_NSEQUENCE as u64);

        test_params.generate_blocks(1);
        test_params.alice_node.update_to_chain_tip();
        test_params.bob_node.update_to_chain_tip();

        assert_channel_state_unlocked!(
            test_params.alice_node.dlc_manager,
            dlc_channel_id_alice,
            Closed
        );
        assert_channel_state_unlocked!(
            test_params.bob_node.dlc_manager,
            dlc_channel_id_alice,
            CounterClosed
        );

        assert_contract_state_unlocked!(test_params.alice_node.dlc_manager, contract_id, PreClosed);
        assert_contract_state_unlocked!(test_params.bob_node.dlc_manager, contract_id, PreClosed);

        test_params.generate_blocks(6);

        test_params.alice_node.update_to_chain_tip();
        test_params.bob_node.update_to_chain_tip();

        assert_contract_state_unlocked!(test_params.alice_node.dlc_manager, contract_id, Closed);
        assert_contract_state_unlocked!(test_params.bob_node.dlc_manager, contract_id, Closed);
    } else {
        assert_channel_state_unlocked!(
            test_params.alice_node.dlc_manager,
            dlc_channel_id_alice,
            Closed
        );
        if let Some(dlc_channel_id_bob) = dlc_channel_id_bob {
            assert_channel_state_unlocked!(
                test_params.bob_node.dlc_manager,
                dlc_channel_id_bob,
                CounterClosed
            );
        }
    }

    test_params.generate_blocks(500);

    test_params.alice_node.update_to_chain_tip();
    test_params.alice_node.process_events();
    test_params.bob_node.update_to_chain_tip();
    test_params.bob_node.process_events();

    test_params.generate_blocks(2);

    test_params.alice_node.update_to_chain_tip();
    test_params.alice_node.process_events();
    test_params.bob_node.update_to_chain_tip();
    test_params.bob_node.process_events();

    assert!(test_params
        .alice_node
        .dlc_manager
        .get_chain_monitor()
        .lock()
        .unwrap()
        .is_empty());
    assert!(test_params
        .bob_node
        .dlc_manager
        .get_chain_monitor()
        .lock()
        .unwrap()
        .is_empty());

    let all_spent = test_params
        .electrs
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

fn force_close_mid_protocol(
    test_params: &mut LnDlcTestParams,
    revert_closer: bool,
    commit_tx: &Transaction,
) {
    let electrs = &test_params.electrs;
    let sink_rpc = &test_params.sink_rpc;

    let generate_blocks = |nb_blocks: u64| generate_blocks(nb_blocks, electrs, sink_rpc);

    let (closer, closee) = if !revert_closer {
        (&mut test_params.alice_node, &mut test_params.bob_node)
    } else {
        (&mut test_params.bob_node, &mut test_params.alice_node)
    };

    let sub_channel = closer
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
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

fn go_to_established_target_state(
    test_params: &LnDlcTestParams,
    target_state: TargetState,
    reverse_offerer: bool,
) {
    let (offerer, accepter) = if !reverse_offerer {
        (&test_params.alice_node, &test_params.bob_node)
    } else {
        (&test_params.bob_node, &test_params.alice_node)
    };

    let offer = generate_offer(&test_params.test_params, offerer, &test_params.channel_id);

    accepter
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Offer(offer),
            &offerer.channel_manager.get_our_node_id(),
        )
        .unwrap();

    if target_state == TargetState::OfferReceived {
        return;
    }

    let (_, accept) = accepter
        .sub_channel_manager
        .accept_sub_channel(&test_params.channel_id)
        .unwrap();

    if target_state == TargetState::Accepted {
        return;
    }

    let confirm = offerer
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Accept(accept),
            &accepter.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    if target_state == TargetState::Confirmed {
        return;
    }

    accepter
        .sub_channel_manager
        .on_sub_channel_message(&confirm, &offerer.channel_manager.get_our_node_id())
        .unwrap();
}

fn go_to_off_chain_close_state(
    test_params: &LnDlcTestParams,
    target_state: TargetState,
    reverse_closer: bool,
) {
    let (closer, closee) = if reverse_closer {
        (&test_params.bob_node, &test_params.alice_node)
    } else {
        (&test_params.alice_node, &test_params.bob_node)
    };
    let (close_offer, _) = closer
        .sub_channel_manager
        .offer_subchannel_close(
            &test_params.channel_id,
            test_params.test_params.contract_input.accept_collateral,
        )
        .unwrap();

    if target_state == TargetState::OfferSent {
        return;
    }

    closee
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::CloseOffer(close_offer),
            &closer.channel_manager.get_our_node_id(),
        )
        .unwrap();

    if target_state == TargetState::OfferReceived {
        return;
    }

    let (accept, _) = closee
        .sub_channel_manager
        .accept_subchannel_close_offer(&test_params.channel_id)
        .unwrap();

    if target_state == TargetState::Accepted {
        return;
    }

    let confirm = closer
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::CloseAccept(accept),
            &closee.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();

    if target_state == TargetState::Confirmed {
        return;
    }

    closee
        .sub_channel_manager
        .on_sub_channel_message(&confirm, &closer.channel_manager.get_our_node_id())
        .unwrap();
}

fn ldk_auto_close(test_params: &mut LnDlcTestParams, commit_tx: &Transaction) {
    let sub_channel = test_params
        .alice_node
        .dlc_manager
        .get_store()
        .get_sub_channel(test_params.channel_id)
        .unwrap()
        .unwrap();
    let dlc_channel_id_alice = sub_channel.get_dlc_channel_id(0);

    let sub_channel = test_params
        .bob_node
        .dlc_manager
        .get_store()
        .get_sub_channel(sub_channel.channel_id)
        .unwrap()
        .unwrap();
    let dlc_channel_id_bob = sub_channel.get_dlc_channel_id(0);

    let channel_id = sub_channel.channel_id;

    test_params
        .bob_node
        .channel_manager
        .force_close_broadcasting_latest_txn(&test_params.channel_id, &test_params.alice_node_id)
        .unwrap();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();
    test_params.alice_node.process_events();
    test_params.bob_node.process_events();

    test_params.generate_blocks(500);
    test_params.bob_node.update_to_chain_tip();
    test_params.bob_node.process_events();

    assert_sub_channel_state!(test_params.bob_node.sub_channel_manager, &channel_id; OnChainClosed);

    test_params.generate_blocks(3);

    test_params.bob_node.update_to_chain_tip();
    test_params.alice_node.update_to_chain_tip();
    test_params.alice_node.process_events();

    assert_sub_channel_state!(test_params.alice_node.sub_channel_manager, &channel_id; CounterOnChainClosed);

    test_params.generate_blocks(500);

    test_params.bob_node.update_to_chain_tip();
    test_params.bob_node.process_events();
    test_params.alice_node.update_to_chain_tip();
    test_params.alice_node.process_events();

    test_params.generate_blocks(2);

    test_params.bob_node.update_to_chain_tip();
    test_params.bob_node.process_events();
    test_params.alice_node.update_to_chain_tip();
    test_params.alice_node.process_events();

    if let Some(dlc_channel_id_alice) = dlc_channel_id_alice {
        assert_channel_state_unlocked!(
            test_params.alice_node.dlc_manager,
            dlc_channel_id_alice,
            CounterClosed
        );
    }
    if let Some(dlc_channel_id_bob) = dlc_channel_id_bob {
        assert_channel_state_unlocked!(
            test_params.bob_node.dlc_manager,
            dlc_channel_id_bob,
            Closed
        );
    }

    assert!(test_params
        .bob_node
        .dlc_manager
        .get_chain_monitor()
        .lock()
        .unwrap()
        .is_empty());
    assert!(test_params
        .alice_node
        .dlc_manager
        .get_chain_monitor()
        .lock()
        .unwrap()
        .is_empty());

    let all_spent = test_params
        .electrs
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
