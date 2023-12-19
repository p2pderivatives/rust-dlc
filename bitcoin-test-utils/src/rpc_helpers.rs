use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::env;

pub const OFFER_PARTY: &str = "alice";
pub const ACCEPT_PARTY: &str = "bob";
pub const SINK: &str = "sink";

fn rpc_base() -> String {
    let host = env::var("BITCOIND_HOST").unwrap_or_else(|_| "localhost".to_owned());
    format!("http://{}:18443", host)
}

pub fn get_new_wallet_rpc(
    default_rpc: &Client,
    wallet_name: &str,
    auth: Auth,
) -> Result<Client, bitcoincore_rpc::Error> {
    let wallet_list = {
        let mut retry_count = 20;
        loop {
            if let Ok(wallets) = default_rpc.list_wallets() {
                break wallets;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            if retry_count == 0 {
                panic!("Could not get wallet list.");
            }
            retry_count -= 1;
        }
    };
    if !wallet_list.contains(&wallet_name.to_owned()) {
        default_rpc.create_wallet(wallet_name, Some(false), None, None, None)?;
    }
    let rpc_url = format!("{}/wallet/{}", rpc_base(), wallet_name);
    Client::new(&rpc_url, auth)
}

pub fn init_clients() -> (Client, Client, Client) {
    let auth = Auth::UserPass(
        "testuser".to_string(),
        "lq6zequb-gYTdF2_ZEUtr8ywTXzLYtknzWU4nV8uVoo=".to_string(),
    );
    let rpc = Client::new(&rpc_base(), auth.clone()).unwrap();

    // Deals with wallet loading error.
    let mut retry_count = 0;
    std::thread::sleep(std::time::Duration::from_millis(100));
    let offer_rpc = loop {
        match get_new_wallet_rpc(&rpc, OFFER_PARTY, auth.clone()) {
            Ok(rpc) => break rpc,
            Err(e) => {
                if retry_count < 20 {
                    retry_count += 1;
                    std::thread::sleep(std::time::Duration::from_millis(100));
                } else {
                    panic!("{}", e);
                }
            }
        };
    };

    let accept_rpc = get_new_wallet_rpc(&rpc, ACCEPT_PARTY, auth.clone()).unwrap();
    let sink_rpc = get_new_wallet_rpc(&rpc, SINK, auth).unwrap();

    let offer_address = offer_rpc
        .call("getnewaddress", &["".into(), "bech32m".into()])
        .unwrap();
    let accept_address = accept_rpc
        .call("getnewaddress", &["".into(), "bech32m".into()])
        .unwrap();
    let sink_address = sink_rpc
        .call("getnewaddress", &["".into(), "bech32m".into()])
        .unwrap();

    sink_rpc.generate_to_address(1, &offer_address).unwrap();
    sink_rpc.generate_to_address(1, &accept_address).unwrap();
    sink_rpc.generate_to_address(101, &sink_address).unwrap();

    (offer_rpc, accept_rpc, sink_rpc)
}
