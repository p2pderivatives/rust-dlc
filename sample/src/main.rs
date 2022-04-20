mod cli;
mod disk;
mod hex_utils;

use disk::FilesystemLogger;

use bitcoin::secp256k1::rand::{thread_rng, RngCore};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin_rpc_provider::BitcoinCoreProvider;
use dlc_manager::{Oracle, SystemTimeProvider};
use dlc_messages::message_handler::MessageHandler as DlcMessageHandler;
use lightning::ln::peer_handler::{
    ErroringMessageHandler, IgnoringMessageHandler, MessageHandler, PeerManager as LdkPeerManager,
};
use lightning_net_tokio::SocketDescriptor;
use p2pd_oracle_client::P2PDOracleClient;
use std::collections::hash_map::HashMap;
use std::env;
use std::fs;
use std::sync::{Arc, Mutex};

pub(crate) type PeerManager = LdkPeerManager<
    SocketDescriptor,
    Arc<ErroringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<FilesystemLogger>,
    Arc<DlcMessageHandler>,
>;

pub(crate) type DlcManager = dlc_manager::manager::Manager<
    Arc<BitcoinCoreProvider>,
    Arc<BitcoinCoreProvider>,
    Box<dlc_sled_storage_provider::SledStorageProvider>,
    Box<P2PDOracleClient>,
    Arc<SystemTimeProvider>,
>;

#[tokio::main]
async fn main() {
    let mut args = env::args();
    if args.len() != 2 {
        println!("This application requires a single argument corresponding to the path to a configuration file.");
        return;
    }

    // Parse application configuration
    let config = cli::parse_config(&args.nth(1).unwrap()).expect("Error parsing arguments");
    fs::create_dir_all(&config.storage_dir_path).expect("Error creating storage directory.");
    let offers_path = format!("{}/{}", config.storage_dir_path, "offers");
    fs::create_dir_all(&offers_path).expect("Error creating offered contract directory");

    // Instantiate a bitcoind provider instance.
    let bitcoind_provider = Arc::new(
        bitcoin_rpc_provider::BitcoinCoreProvider::new(
            config.bitcoin_info.rpc_host,
            config.bitcoin_info.rpc_port,
            config.bitcoin_info.wallet,
            config.bitcoin_info.rpc_username,
            config.bitcoin_info.rpc_password,
        )
        .expect("Error creating BitcoinCoreProvider"),
    );

    // Instantiate an oracle client. At the moment the implementation of the oracle
    // client uses reqwest in blocking mode to satisfy the non async oracle interface
    // so we need to use `spawn_blocking`.
    let oracle_host = config.oracle_config.host;
    let oracle = tokio::task::spawn_blocking(move || {
        P2PDOracleClient::new(&oracle_host).expect("Error creating oracle client")
    })
    .await
    .unwrap();
    let mut oracles = HashMap::new();
    oracles.insert(oracle.get_public_key(), Box::new(oracle));

    // Instantiate a DlcManager.
    let dlc_manager = Arc::new(Mutex::new(dlc_manager::manager::Manager::new(
        bitcoind_provider.clone(),
        bitcoind_provider.clone(),
        Box::new(
            dlc_sled_storage_provider::SledStorageProvider::new(&config.storage_dir_path)
                .expect("Error creating storage."),
        ),
        oracles,
        Arc::new(dlc_manager::SystemTimeProvider {}),
    )));

    let dlc_data_dir = format!("{}/.dlc", config.storage_dir_path);
    let logger = Arc::new(FilesystemLogger::new(dlc_data_dir.clone()));

    let mut ephemeral_bytes = [0; 32];
    thread_rng().fill_bytes(&mut ephemeral_bytes);
    let sk_path = format!("{}/secret_key", dlc_data_dir);

    // We store the private key in plaintext as this is an example, should be
    // avoided in a real application.
    let sk = if fs::metadata(&sk_path).is_ok() {
        let sk_str = fs::read_to_string(sk_path).expect("Error reading secret key file");
        sk_str.parse().expect("Error parsing secret key file")
    } else {
        let sk = SecretKey::new(&mut thread_rng());
        let sk_str = sk.to_string();
        fs::write(sk_path, sk_str).expect("Error writing secret key file.");
        sk
    };

    // Setup a handler for the DLC messages that will be sent/received through LDK.
    let dlc_message_handler = Arc::new(DlcMessageHandler::new());
    println!(
        "Node public key: {}",
        PublicKey::from_secret_key(&Secp256k1::new(), &sk)
    );

    // The peer manager helps us establish connections and communicate with our peers.
    let peer_manager: Arc<PeerManager> = Arc::new(PeerManager::new(
        MessageHandler {
            chan_handler: Arc::new(ErroringMessageHandler::new()),
            route_handler: Arc::new(IgnoringMessageHandler {}),
        },
        sk,
        &ephemeral_bytes,
        logger.clone(),
        dlc_message_handler.clone(),
    ));

    let peer_manager_connection_handler = peer_manager.clone();
    let listening_port = config.network_configuration.peer_listening_port;
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", listening_port))
            .await
            .expect("Failed to bind to listen port - is something else already listening on it?");
        loop {
            let peer_mgr = peer_manager_connection_handler.clone();
            let tcp_stream = listener.accept().await.unwrap().0;
            tokio::spawn(async move {
                lightning_net_tokio::setup_inbound(
                    peer_mgr.clone(),
                    tcp_stream.into_std().unwrap(),
                )
                .await;
            });
        }
    });

    // Start the CLI.
    cli::poll_for_user_input(
        peer_manager.clone(),
        dlc_message_handler.clone(),
        dlc_manager.clone(),
        &offers_path,
    )
    .await;
}
