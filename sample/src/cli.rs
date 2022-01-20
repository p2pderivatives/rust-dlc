// This code is mainly copied and adapted from the LdkSample (https://github.com/lightningdevkit/ldk-sample)
use crate::hex_utils;
use crate::DlcManager;
use crate::DlcMessageHandler;
use crate::PeerManager;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::key::PublicKey;
use dlc_manager::channel::signed_channel::SignedChannelState;
use dlc_manager::channel::signed_channel::SignedChannelStateType;
use dlc_manager::contract::contract_input::ContractInput;
use dlc_manager::contract::{ClosedContract, Contract};
use dlc_manager::Storage;
use dlc_messages::Message as DlcMessage;
use hex_utils::{hex_str, to_slice};
use lightning::ln::msgs::NetAddress;
use serde::Deserialize;
use serde_json::Value;
use std::convert::TryInto;
use std::fs;
use std::io;
use std::io::{BufRead, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::str::SplitWhitespace;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitcoindInfo {
    pub rpc_username: String,
    pub rpc_password: String,
    pub rpc_port: u16,
    pub rpc_host: String,
    pub wallet: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleConfig {
    pub host: String,
}

#[derive(Debug)]
pub struct NetworkConfig {
    pub peer_listening_port: u16,
    pub announced_listen_addr: Option<NetAddress>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub bitcoin_info: BitcoindInfo,
    pub storage_dir_path: String,
    #[serde(deserialize_with = "deserialize_network_configuration")]
    pub network_configuration: NetworkConfig,
    #[serde(default)]
    pub announced_node_name: [u8; 32],
    pub network: Network,
    pub oracle_config: OracleConfig,
}

fn deserialize_network_configuration<'de, D>(deserializer: D) -> Result<NetworkConfig, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let val = Value::deserialize(deserializer)?;

    let peer_listening_port: u16 = val["peerListeningPort"]
        .as_u64()
        .expect("Could not parse peerListeningPort")
        .try_into()
        .expect("Could not fit port in u16");

    let announced_listen_addr = if let Some(announced_listen_addr) = val.get("announcedListenAddr")
    {
        let buf = announced_listen_addr
            .as_str()
            .expect("Error parsing announcedListeAddr");
        match IpAddr::from_str(buf) {
            Ok(IpAddr::V4(a)) => Some(NetAddress::IPv4 {
                addr: a.octets(),
                port: peer_listening_port,
            }),
            Ok(IpAddr::V6(a)) => Some(NetAddress::IPv6 {
                addr: a.octets(),
                port: peer_listening_port,
            }),
            Err(_) => panic!("Failed to parse announced-listen-addr into an IP address"),
        }
    } else {
        None
    };

    Ok(NetworkConfig {
        peer_listening_port,
        announced_listen_addr,
    })
}

pub(crate) fn parse_config(config_path: &str) -> Result<Configuration, String> {
    let config_file = fs::read_to_string(config_path).map_err(|e| e.to_string())?;

    serde_yaml::from_str(&config_file).map_err(|e| e.to_string())
}

macro_rules! read_id_or_continue {
    ($words: ident, $err_cmd: expr, $err_arg: expr) => {
        match read_id(&mut $words, $err_cmd, $err_arg) {
            Ok(res) => res,
            Err(()) => continue,
        }
    };
}

pub(crate) async fn poll_for_user_input(
    peer_manager: Arc<PeerManager>,
    dlc_message_handler: Arc<DlcMessageHandler>,
    dlc_manager: Arc<Mutex<DlcManager>>,
    offers_path: &str,
) {
    println!("DLC node startup successful. To view available commands: \"help\".");
    println!("DLC logs are available at <your-supplied-ldk-data-dir-path>/.dlc/logs");
    let stdin = io::stdin();
    print!("> ");
    io::stdout().flush().unwrap(); // Without flushing, the `>` doesn't print
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let mut words = line.split_whitespace();
        if let Some(word) = words.next() {
            process_incoming_messages(&peer_manager, &dlc_manager, &dlc_message_handler);
            match word {
                "help" => help(),
                "connectpeer" => {
                    let peer_pubkey_and_ip_addr = words.next();
                    if peer_pubkey_and_ip_addr.is_none() {
                        println!("ERROR: connectpeer requires peer connection info: `connectpeer pubkey@host:port`");
                        print!("> ");
                        io::stdout().flush().unwrap();
                        continue;
                    }
                    let (pubkey, peer_addr) =
                        match parse_peer_info(peer_pubkey_and_ip_addr.unwrap().to_string()) {
                            Ok(info) => info,
                            Err(e) => {
                                println!("{:?}", e.into_inner().unwrap());
                                print!("> ");
                                io::stdout().flush().unwrap();
                                continue;
                            }
                        };
                    if connect_peer_if_necessary(pubkey, peer_addr, peer_manager.clone())
                        .await
                        .is_ok()
                    {
                        println!("SUCCESS: connected to peer {}", pubkey);
                    }
                }
                "listpeers" => list_peers(peer_manager.clone()),
                o @ "offercontract" | o @ "offerchannel" => {
                    let (peer_pubkey_and_ip_addr, contract_path) = match (
                        words.next(),
                        words.next(),
                    ) {
                        (Some(pp), Some(cp)) => (pp, cp),
                        _ => {
                            println!("ERROR: offercontract requires peer connection info and contract path: `offercontract pubkey@host:port contract_path`");
                            print!("> ");
                            io::stdout().flush().unwrap();
                            continue;
                        }
                    };
                    let (pubkey, peer_addr) =
                        match parse_peer_info(peer_pubkey_and_ip_addr.to_string()) {
                            Ok(info) => info,
                            Err(e) => {
                                println!("{:?}", e.into_inner().unwrap());
                                print!("> ");
                                io::stdout().flush().unwrap();
                                continue;
                            }
                        };
                    if connect_peer_if_necessary(pubkey, peer_addr, peer_manager.clone())
                        .await
                        .is_ok()
                    {
                        println!("SUCCESS: connected to peer {}", pubkey);
                    }
                    let contract_input_str = fs::read_to_string(&contract_path)
                        .expect("Error reading contract input file.");
                    let contract_input: ContractInput = serde_json::from_str(&contract_input_str)
                        .expect("Error deserializing contract input.");
                    let manager_clone = dlc_manager.clone();
                    let is_contract = o == "offercontract";
                    let offer = tokio::task::spawn_blocking(move || {
                        if is_contract {
                            DlcMessage::Offer(
                                manager_clone
                                    .lock()
                                    .unwrap()
                                    .send_offer(&contract_input, pubkey)
                                    .expect("Error sending offer"),
                            )
                        } else {
                            DlcMessage::OfferChannel(
                                manager_clone
                                    .lock()
                                    .unwrap()
                                    .send_offer_channel(&contract_input, pubkey)
                                    .expect("Error sending offer channel"),
                            )
                        }
                    })
                    .await
                    .unwrap();
                    dlc_message_handler.send_message(pubkey, offer);
                    peer_manager.process_events();
                }
                "listoffers" => {
                    let locked_manager = dlc_manager.lock().unwrap();
                    for offer in locked_manager
                        .get_store()
                        .get_contract_offers()
                        .unwrap()
                        .iter()
                        .filter(|x| !x.is_offer_party)
                    {
                        let offer_id = hex_str(&offer.id);
                        let offer_json_path = format!("{}/{}.json", offers_path, offer_id);
                        if fs::metadata(&offer_json_path).is_err() {
                            let offer_str = serde_json::to_string_pretty(&offer)
                                .expect("Error serializing offered contract");
                            fs::write(&offer_json_path, offer_str)
                                .expect("Error saving offer json");
                        }
                        println!("Offer {:?} from {}", offer_id, offer.counter_party);
                    }
                }
                a @ "acceptoffer" => {
                    let contract_id = read_id_or_continue!(words, a, "contract id");

                    let (_, node_id, msg) = dlc_manager
                        .lock()
                        .unwrap()
                        .accept_contract_offer(&contract_id)
                        .expect("Error accepting contract.");
                    dlc_message_handler.send_message(node_id, DlcMessage::Accept(msg));
                    peer_manager.process_events();
                }
                "listcontracts" => {
                    let manager_clone = dlc_manager.clone();
                    // Because the oracle client is currently blocking we need to use `spawn_blocking` here.
                    tokio::task::spawn_blocking(move || {
                        manager_clone
                            .lock()
                            .unwrap()
                            .periodic_check()
                            .expect("Error doing periodic check.");
                        let contracts = manager_clone
                            .lock()
                            .unwrap()
                            .get_store()
                            .get_contracts()
                            .expect("Error retrieving contract list.");
                        for contract in contracts {
                            let id = hex_str(&contract.get_id());
                            match contract {
                                Contract::Offered(_) => {
                                    println!("Offered contract: {}", id);
                                }
                                Contract::Accepted(_) => {
                                    println!("Accepted contract: {}", id);
                                }
                                Contract::Confirmed(_) => {
                                    println!("Confirmed contract: {}", id);
                                }
                                Contract::Signed(_) => {
                                    println!("Signed contract: {}", id);
                                }
                                Contract::Closed(closed) => {
                                    println!("Closed contract: {}", id);
                                    println!(
                                        "Outcomes: {:?}",
                                        closed
                                            .attestations
                                            .iter()
                                            .map(|x| x.outcomes.clone())
                                            .collect::<Vec<_>>()
                                    );
                                    println!("PnL: {} sats", compute_pnl(&closed))
                                }
                                Contract::Refunded(_) => {
                                    println!("Refunded contract: {}", id);
                                }
                                _ => {
                                    println!("Rejected contract: {}", id);
                                }
                            }
                        }
                    })
                    .await
                    .expect("Error listing contract info");
                }
                "listchanneloffers" => {
                    let locked_manager = dlc_manager.lock().unwrap();
                    for offer in locked_manager
                        .get_store()
                        .get_offered_channels()
                        .unwrap()
                        .iter()
                        .filter(|x| !x.is_offer_party)
                    {
                        let channel_id = hex_str(&offer.temporary_channel_id);
                        let channel_offer_json_path =
                            format!("{}/{}.json", offers_path, channel_id);
                        if fs::metadata(&channel_offer_json_path).is_err() {
                            let offer_str = serde_json::to_string_pretty(&offer)
                                .expect("Error serializing offered channel");
                            fs::write(&channel_offer_json_path, offer_str)
                                .expect("Error saving offer channel json");
                        }
                        println!(
                            "Offer channel {:?} from {}",
                            channel_id, offer.counter_party
                        );
                    }
                }
                a @ "acceptchannel" => {
                    let channel_id = read_id_or_continue!(words, a, "channel id");

                    let (msg, _, _, node_id) = dlc_manager
                        .lock()
                        .unwrap()
                        .accept_channel(&channel_id)
                        .expect("Error accepting channel.");
                    dlc_message_handler.send_message(node_id, DlcMessage::AcceptChannel(msg));
                    peer_manager.process_events();
                }
                s @ "offersettlechannel" => {
                    let channel_id = read_id_or_continue!(words, s, "channel id");
                    let counter_payout: u64 = match words.next().map(|w| w.parse().ok()) {
                        Some(Some(p)) => p,
                        _ => {
                            println!("Missing or invalid counter payout parameter");
                            continue;
                        }
                    };

                    let (msg, node_id) = dlc_manager
                        .lock()
                        .unwrap()
                        .settle_offer(&channel_id, counter_payout)
                        .expect("Error getting settle offer message.");
                    dlc_message_handler.send_message(node_id, DlcMessage::SettleOffer(msg));
                    peer_manager.process_events();
                }
                l @ "acceptsettlechanneloffer" => {
                    let channel_id = read_id_or_continue!(words, l, "channel id");
                    let (msg, node_id) = dlc_manager
                        .lock()
                        .unwrap()
                        .accept_settle_offer(&channel_id)
                        .expect("Error accepting channel.");
                    dlc_message_handler.send_message(node_id, DlcMessage::SettleAccept(msg));
                    peer_manager.process_events();
                }
                "listsettlechanneloffers" => {
                    let locked_manager = dlc_manager.lock().unwrap();
                    for channel in locked_manager
                        .get_store()
                        .get_signed_channels(Some(SignedChannelStateType::SettledReceived))
                        .unwrap()
                        .iter()
                    {
                        let channel_id = hex_str(&channel.channel_id);
                        let own_payout = match channel.state {
                            SignedChannelState::SettledReceived { own_payout, .. } => own_payout,
                            _ => continue,
                        };
                        println!(
                            "Settle offer channel {:?} from {} with own payout: {}",
                            channel_id, channel.counter_party, own_payout
                        );
                    }
                }
                o @ "offerchannelrenew" => {
                    let channel_id = read_id_or_continue!(words, o, "channel id");
                    let (counter_payout, contract_path) =
                        match (words.next().map(|x| x.parse()), words.next()) {
                            (Some(Ok(payout)), Some(s)) => (payout, s),
                            _ => continue,
                        };
                    let contract_input_str = fs::read_to_string(&contract_path)
                        .expect("Error reading contract input file.");
                    let contract_input: ContractInput = serde_json::from_str(&contract_input_str)
                        .expect("Error deserializing contract input.");
                    let manager_clone = dlc_manager.clone();
                    let (renew_offer, node_id) = tokio::task::spawn_blocking(move || {
                        manager_clone
                            .lock()
                            .unwrap()
                            .send_renew_channel_offer(&channel_id, counter_payout, &contract_input)
                            .expect("Error sending offer")
                    })
                    .await
                    .unwrap();
                    dlc_message_handler
                        .send_message(node_id, DlcMessage::RenewChannelOffer(renew_offer));
                    peer_manager.process_events();
                }
                "listrenewchanneloffers" => {
                    let locked_manager = dlc_manager.lock().unwrap();
                    for channel in locked_manager
                        .get_store()
                        .get_signed_channels(Some(SignedChannelStateType::RenewOffered))
                        .unwrap()
                        .iter()
                    {
                        let channel_id = hex_str(&channel.channel_id);
                        let own_payout = match channel.state {
                            SignedChannelState::RenewOffered {
                                counter_payout,
                                is_offer,
                                ..
                            } => {
                                if is_offer {
                                    continue;
                                } else {
                                    counter_payout
                                }
                            }

                            _ => continue,
                        };
                        println!(
                            "Settle offer channel {:?} from {} with own payout: {}",
                            channel_id, channel.counter_party, own_payout
                        );
                    }
                }
                l @ "acceptchannelrenew" => {
                    let channel_id = read_id_or_continue!(words, l, "channel id");
                    let (msg, node_id) = dlc_manager
                        .lock()
                        .unwrap()
                        .accept_channel_renew(&channel_id)
                        .expect("Error accepting channel.");
                    dlc_message_handler.send_message(node_id, DlcMessage::RenewChannelAccept(msg));
                    peer_manager.process_events();
                }
                "listsignedchannels" => {
                    let locked_manager = dlc_manager.lock().unwrap();
                    for channel in locked_manager
                        .get_store()
                        .get_signed_channels(None)
                        .unwrap()
                        .iter()
                    {
                        let channel_id = hex_str(&channel.channel_id);
                        println!(
                            "Signed channel {:?} with {}",
                            channel_id, channel.counter_party
                        );
                    }
                }
                _ => println!("Unknown command. See `\"help\" for available commands."),
            }
        }
        print!("> ");
        io::stdout().flush().unwrap();
    }
}

fn read_id(words: &mut SplitWhitespace, err_cmd: &str, err_arg: &str) -> Result<[u8; 32], ()> {
    match words.next() {
        None => {
            println!("ERROR: {} expects the {} as parameter.", err_cmd, err_arg);
            Err(())
        }
        Some(s) => {
            let mut res = [0u8; 32];
            match to_slice(s, &mut res) {
                Err(_) => {
                    println!("ERROR: invalid {}.", err_arg);
                    Err(())
                }
                Ok(_) => Ok(res),
            }
        }
    }
}

fn help() {
    println!("connectpeer <pubkey@host:port>");
    println!("listpeers");
    println!("offercontract <pubkey@host:port> <path_to_contract_input_json>");
    println!("listoffers");
    println!("acceptoffer <contract_id>");
    println!("listcontracts");
    println!("offerchannel <pubkey@host:port> <path_to_contract_input_json>");
    println!("listchanneloffers");
    println!("acceptchannel <channel_id>");
    println!("offer settlechannel <channel_id> <counter_payout>");
    println!("listsettlechanneloffers");
    println!("acceptsettlechanneloffer <channel_id>");
    println!("offerchannelrenew <channel_id> <path_to_contract_input_json>");
    println!("listrenewchanneloffers");
    println!("acceptchannelrenew <channel_id>");
}

fn list_peers(peer_manager: Arc<PeerManager>) {
    println!("\t{{");
    for pubkey in peer_manager.get_peer_node_ids() {
        println!("\t\t pubkey: {}", pubkey);
    }
    println!("\t}},");
}

pub(crate) async fn connect_peer_if_necessary(
    pubkey: PublicKey,
    peer_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), ()> {
    for node_pubkey in peer_manager.get_peer_node_ids() {
        if node_pubkey == pubkey {
            return Ok(());
        }
    }
    match lightning_net_tokio::connect_outbound(Arc::clone(&peer_manager), pubkey, peer_addr).await
    {
        Some(connection_closed_future) => {
            let mut connection_closed_future = Box::pin(connection_closed_future);
            loop {
                match futures::poll!(&mut connection_closed_future) {
                    std::task::Poll::Ready(_) => {
                        println!("ERROR: Peer disconnected before we finished the handshake");
                        return Err(());
                    }
                    std::task::Poll::Pending => {}
                }
                // Avoid blocking the tokio context by sleeping a bit
                match peer_manager
                    .get_peer_node_ids()
                    .iter()
                    .find(|id| **id == pubkey)
                {
                    Some(_) => break,
                    None => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        }
        None => {
            println!("ERROR: failed to connect to peer");
            return Err(());
        }
    }
    Ok(())
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, SocketAddr), std::io::Error> {
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split('@');
    let pubkey = pubkey_and_addr.next();
    let peer_addr_str = pubkey_and_addr.next();
    if peer_addr_str.is_none() || peer_addr_str.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ERROR: incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`",
        ));
    }

    let peer_addr = peer_addr_str
        .unwrap()
        .to_socket_addrs()
        .map(|mut r| r.next());
    if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ERROR: couldn't parse pubkey@host:port into a socket address",
        ));
    }

    let pubkey = hex_utils::to_compressed_pubkey(pubkey.unwrap());
    if pubkey.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ERROR: unable to parse given pubkey for node",
        ));
    }

    Ok((pubkey.unwrap(), peer_addr.unwrap().unwrap()))
}

fn compute_pnl(contract: &ClosedContract) -> i64 {
    let offer = &contract.signed_contract.accepted_contract.offered_contract;
    let accepted_contract = &contract.signed_contract.accepted_contract;
    let party_params = if offer.is_offer_party {
        &offer.offer_params
    } else {
        &accepted_contract.accept_params
    };
    let collateral = party_params.collateral as i64;
    let cet = &contract.signed_cet;
    let v0_witness_payout_script = &party_params.payout_script_pubkey;
    let final_payout = cet
        .output
        .iter()
        .find_map(|x| {
            if &x.script_pubkey == v0_witness_payout_script {
                Some(x.value)
            } else {
                None
            }
        })
        .unwrap_or(0) as i64;
    final_payout - collateral
}

fn process_incoming_messages(
    peer_manager: &Arc<PeerManager>,
    dlc_manager: &Arc<Mutex<DlcManager>>,
    dlc_message_handler: &Arc<DlcMessageHandler>,
) {
    println!("Checking for messages");
    let messages = dlc_message_handler.get_and_clear_received_messages();

    for (node_id, message) in messages {
        println!("Processing message from {}", node_id);
        let resp = dlc_manager
            .lock()
            .unwrap()
            .on_dlc_message(&message, node_id)
            .expect("Error processing message");
        if let Some(msg) = resp {
            println!("Sending message to {}", node_id);
            dlc_message_handler.send_message(node_id, msg);
        }
    }

    if dlc_message_handler.has_pending_messages() {
        peer_manager.process_events();
    }
}
