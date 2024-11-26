use std::{process::Command, thread::sleep, time::Duration};

use assert_cmd::cargo::cargo_bin;
use ddk_manager::contract::contract_input::ContractInput;
use rexpect::session::{spawn_command, PtySession};

#[test]
#[ignore]
fn sample_cli_test() {
    let contract_str = include_str!("../examples/contracts/numerical_contract_input.json");
    let mut contract: ContractInput = serde_json::from_str(&contract_str).unwrap();
    let time_now = std::time::SystemTime::now();
    let unix_time = (time_now
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        + Duration::new(300, 0))
    .as_secs();
    contract.contract_infos[0].oracles.event_id = format!("btcusd{}", unix_time);

    let alice_config_str = include_str!("../examples/configurations/alice.yml");
    let bob_config_str = include_str!("../examples/configurations/bob.yml");
    std::fs::write(
        "./numerical_contract_input.json",
        serde_json::to_string(&contract).unwrap(),
    )
    .unwrap();
    std::fs::write("./alice.yml", alice_config_str).unwrap();
    std::fs::write("./bob.yml", bob_config_str).unwrap();

    let bin_path = cargo_bin("sample");
    let mut command = Command::new(bin_path.to_str().unwrap());
    command.arg("./alice.yml");
    let mut alice_cli = spawn_command(command, Some(5000)).unwrap();

    alice_cli.exp_regex("[a-f0-9]{66}").unwrap();
    alice_cli.exp_regex("> $").unwrap();

    let mut command = Command::new(bin_path.to_str().unwrap());
    command.arg("./bob.yml");
    let mut bob_cli = spawn_command(command, Some(5000)).unwrap();

    let (_, bob_ip) = bob_cli.exp_regex("[a-f0-9]{66}").unwrap();
    bob_cli.exp_regex("> $").unwrap();

    alice_cli
        .send_line(&format!(
            "offercontract {}@127.0.0.1:9001 ./numerical_contract_input.json",
            bob_ip
        ))
        .unwrap();

    alice_cli.exp_char('>').unwrap();

    std::thread::sleep(std::time::Duration::from_secs(5));

    try_send_until(&mut bob_cli, "listoffers", "Offer");

    let (_, offer_id) = bob_cli.exp_regex("[a-f0-9]{64}").unwrap();

    bob_cli
        .send_line(&format!("acceptoffer {}", offer_id))
        .unwrap();
    bob_cli.exp_char('>').unwrap();

    try_send_until(&mut alice_cli, "listcontracts", "Signed contract");
    alice_cli.exp_char('>').unwrap();

    try_send_until(&mut bob_cli, "listcontracts", "Signed contract");
    bob_cli.exp_char('>').unwrap();
}

fn try_send_until(session: &mut PtySession, to_send: &str, expected: &str) {
    const RETRY: u8 = 5;

    for _ in 0..RETRY {
        session.send_line(to_send).unwrap();
        if let Ok(_) = session.exp_string(expected) {
            return;
        }
        sleep(Duration::from_secs(1));
    }

    panic!("Did not receive expected output after {} tries", RETRY);
}
