use bitcoin::blockdata::transaction::{TxOut, TxIn, Transaction};
use bitcoin::blockdata::script::{Script, Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::util::address::Address;
use secp256k1::key::{PublicKey};
use bitcoin::hashes::{Hash, sha256d};

use secp256k1::*;

const DUST_LIMIT: u64 = 5000;
const TX_VERSION: u32 = 2;
const MATURITY_TIME_MIN: u32 = 500000000;

pub fn combine_keys(pub_keys: &[PublicKey]) -> PublicKey {
    pub_keys.iter().fold(pub_keys[0], |keys, key| keys.combine(key).unwrap())
}

pub fn get_secp_committed_key(oracle_pub_key: PublicKey,
                              oracle_r_point: PublicKey,
                              message: String) -> PublicKey {
    let s = Secp256k1::signing_only();
    let msg = Message::from_slice(message.as_bytes()).unwrap();
    PublicKey::schnorrsig_sig_pubkey(&s, &oracle_r_point, &msg, &oracle_pub_key)
}

pub fn get_committed_key(oracle_pub_key: PublicKey,
                         oracle_r_points: &[PublicKey],
                         messages: &[String]) -> PublicKey {
    let mut pubkey_list = Vec::new();
    for (r_point, msg) in oracle_r_points.iter().zip(messages.iter()) {
        let secp_commitment_key = get_secp_committed_key(
            oracle_pub_key, *r_point, msg.to_string()
        );

        pubkey_list.push(secp_commitment_key);
    }
    combine_keys(&pubkey_list)
}

pub fn create_cet_transaction(cet_script: &[u8],
                  remote_final_address: Address,
                  local_payout: u64,
                  remote_payout: u64,
                  fund_txin: TxIn,
                  maturity_time: u32) -> Option<Transaction>
{
    if maturity_time < MATURITY_TIME_MIN {
        return None
    }

    let lock_script = create_p2wsh_locking_script(cet_script);

    let tx_out_local = TxOut {
        value: local_payout,
        script_pubkey: lock_script
    };

    let tx_out_remote = TxOut {
        value: remote_payout,
        script_pubkey: remote_final_address.script_pubkey()
    };

    let cet = Transaction {
        version: TX_VERSION,
        lock_time: maturity_time,
        input: vec![fund_txin],
        output: vec![tx_out_local, tx_out_remote]
    };

    Some(cet)
}

//TODO is fund_tx_id sufficient, or should fund_vout be an argument as well
pub fn create_cet(local_fund_pubkey: PublicKey,
                  local_sweep_pubkey: PublicKey,
                  remote_sweep_pubkey: PublicKey,
                  remote_final_address: Address,
                  oracle_pubkey: PublicKey,
                  oracle_r_points: &[PublicKey],
                  messages: &[String],
                  delay: i64,
                  local_payout: u64,
                  remote_payout: u64,
                  maturity_time: u32,
                  fund_tx_id: TxIn
) -> Option<Transaction> {

    let cet_script = create_cet_redeem_script(
        local_fund_pubkey,
        local_sweep_pubkey,
        remote_sweep_pubkey,
        oracle_pubkey,
        oracle_r_points,
        messages, 
        delay
    );

    create_cet_transaction(
        cet_script.as_bytes(),
        remote_final_address,
        local_payout,
        remote_payout,
        fund_tx_id,
        maturity_time)
}

pub fn create_cet_redeem_script(local_fund_pubkey: PublicKey,
                                local_sweep_pubkey: PublicKey,
                                remote_sweep_pubkey: PublicKey,
                                oracle_pubkey: PublicKey,
                                oracle_r_points: &[PublicKey],
                                messages: &[String],
                                delay: i64) -> Script {

    let s = Secp256k1::signing_only();
    let local_sweep_hash = sha256d::Hash::hash(local_sweep_pubkey.to_string().as_bytes());
    let sk_local_sweep = SecretKey::from_slice(&local_sweep_hash).unwrap();
    let pk_local_sweep = PublicKey::from_secret_key(&s, &sk_local_sweep);

    let combine_pubkey = get_committed_key(oracle_pubkey, oracle_r_points, messages)
        .combine(&local_fund_pubkey).unwrap()
        .combine(&pk_local_sweep).unwrap();

    Builder::new()
        .push_opcode(opcodes::all::OP_IF)
        .push_slice(combine_pubkey.to_string().as_bytes())
        .push_opcode(opcodes::all::OP_ELSE)
        .push_int(delay)
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(remote_sweep_pubkey.to_string().as_bytes())
        .push_opcode(opcodes::all::OP_ENDIF)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

pub fn create_funding_transaction(local_fund_pubkey: PublicKey,
                                  remote_fund_pubkey: PublicKey,
                                  output_amount: u64,
                                  local_inputs: Vec<TxIn>,
                                  remote_inputs: Vec<TxIn>,
                                  local_change_output: Vec<TxOut>,
                                  remote_change_output: Vec<TxOut>) -> Transaction {

    let script = make_funding_redeemscript(&local_fund_pubkey, &remote_fund_pubkey);

    let mut tx_out_vec = Vec::new();
    let tx_out = TxOut {
        value: output_amount,
        script_pubkey: script
    };
    tx_out_vec.push(tx_out);

    let inputs = [&local_inputs[..], &remote_inputs[..]].concat();
    let outputs = [
        &local_change_output[..],
        &remote_change_output[..],
        &tx_out_vec[..]
    ].concat();

    let result: Vec<TxOut> = outputs.into_iter().filter( |o| o.value > DUST_LIMIT).collect();

    let funding_transaction = Transaction {
        version: TX_VERSION,
        lock_time: 0,
        input: inputs,
        output: result
    };

    return funding_transaction
}

pub fn create_mutual_closing_transaction(local_output: TxOut,
                                         remote_output: TxOut,
                                         funding_input: TxIn) -> Transaction {
    Transaction {
        version: TX_VERSION,
        lock_time: 0,
        input: vec![funding_input],
        output: vec![local_output, remote_output]
    }
}

pub fn create_refund_transaction(local_output: TxOut,
                                 remote_output: TxOut,
                                 funding_input: TxIn,
                                 locktime: u32) -> Transaction {
    Transaction {
        version: TX_VERSION,
        lock_time: locktime,
        input: vec![funding_input],
        output: vec![local_output, remote_output]
    }
}

pub fn create_p2wsh_locking_script(script: &[u8]) -> Script {
    Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0)
        .push_slice(script)
        .into_script()
}

/// Gets the redeemscript for a funding output from the two funding public keys.
/// Note that the order of funding public keys does not matter.
pub fn make_funding_redeemscript(a: &PublicKey, b: &PublicKey) -> Script {
    let our_funding_key = a.serialize();
    let their_funding_key = b.serialize();

    let builder = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2);
    if our_funding_key[..] < their_funding_key[..] {
        builder.push_slice(&our_funding_key)
            .push_slice(&their_funding_key)
    } else {
        builder.push_slice(&their_funding_key)
            .push_slice(&our_funding_key)
    }.push_opcode(opcodes::all::OP_PUSHNUM_2).push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use secp256k1::{Secp256k1, SecretKey, PublicKey};
    use bitcoin::blockdata::script::Script;
    use bitcoin::blockdata::transaction::OutPoint;

    fn create_txout_vec(values: Vec<u64>) -> Vec<TxOut> {
        let mut outputs = Vec::new();
        for value in values {
            let txout = TxOut {
                value: value,
                script_pubkey: Script::new()
            };
            outputs.push(txout);
        }
        return outputs
    }

    fn create_txin_vec(sequence: u32) -> Vec<TxIn> {
        let mut inputs = Vec::new();
        let txin = TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: sequence,
            witness: Vec::new(),
        };
        inputs.push(txin);
        inputs
    }

    fn create_multi_party_pub_keys() -> (PublicKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let pk = PublicKey::from_secret_key(&secp, &secret_key);
        let pk1 = pk;

        (pk, pk1)
    }

    fn create_test_tx_io() -> (TxOut, TxOut, TxIn) {
        let local = TxOut {
            value: 1,
            script_pubkey: Script::new()
        };

        let remote = TxOut {
            value: 2,
            script_pubkey: Script::new()
        };

        let funding = TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: 3,
            witness: Vec::new(),
        };

        (local, remote, funding)
    }

    #[test]
    fn create_refund_transaction_test() {
        let (local, remote, funding) = create_test_tx_io();

        let refund_transaction = create_refund_transaction(local, remote, funding, 0);
        assert_eq!(2, refund_transaction.version);
        assert_eq!(0, refund_transaction.lock_time);
        assert_eq!(1, refund_transaction.output[0].value);
        assert_eq!(2, refund_transaction.output[1].value);
        assert_eq!(3, refund_transaction.input[0].sequence);
    }

    #[test]
    fn create_funding_transaction_test() {
        let (pk, pk1) = create_multi_party_pub_keys();

        let local_inputs = create_txin_vec(0);
        let remote_inputs = create_txin_vec(1);

        let local_change_output = create_txout_vec(vec![5001, 5002]); 
        let remote_change_output = create_txout_vec(vec![5003]);

        let transaction = create_funding_transaction(
            pk,
            pk1,
            31415,
            local_inputs,
            remote_inputs,
            local_change_output,
            remote_change_output
        );

        let transaction_inputs = transaction.input;
        let transaction_outputs = transaction.output;

        assert_eq!(transaction_inputs[0].sequence, 0);
        assert_eq!(transaction_inputs[1].sequence, 1);

        assert_eq!(transaction_outputs[0].value, 5001);
        assert_eq!(transaction_outputs[1].value, 5002);
        assert_eq!(transaction_outputs[2].value, 5003);
        assert_eq!(transaction_outputs[3].value, 31415);
    }

    #[test]
    fn create_funding_transaction_with_outputs_less_than_dust_limit_test() {
        let (pk, pk1) = create_multi_party_pub_keys();

        let local_inputs = create_txin_vec(0);
        let remote_inputs = create_txin_vec(1);

        let local_change_output = create_txout_vec(vec![4999,5000,5001]); 
        let remote_change_output = create_txout_vec(vec![5002]);

        let transaction = create_funding_transaction(
            pk,
            pk1,
            31415,
            local_inputs,
            remote_inputs,
            local_change_output,
            remote_change_output
        );

        let transaction_outputs = transaction.output;

        assert_eq!(transaction_outputs[0].value, 5001);
        assert_eq!(transaction_outputs[1].value, 5002);
        assert_eq!(transaction_outputs[2].value, 31415);
    }

    #[test]
    fn create_mutual_closing_transaction_test() {
        let (local, remote, funding) = create_test_tx_io();

        let refund_transaction = create_mutual_closing_transaction(local, remote, funding);
        assert_eq!(2, refund_transaction.version);
        assert_eq!(0, refund_transaction.lock_time);
        assert_eq!(1, refund_transaction.output[0].value);
        assert_eq!(2, refund_transaction.output[1].value);
        assert_eq!(3, refund_transaction.input[0].sequence);
    }
    #[test]
    fn create_cet_transaction_test() {
        let addr = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap();

        let maturity_time = 500000001;
        let cet_script = vec![0u8, 1, 2, 3];

        let txin = TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: 0,
            witness: Vec::new(),
        };

        let cet = create_cet_transaction(&cet_script, addr, 1, 2, txin, maturity_time).unwrap();

        assert_eq!(maturity_time, cet.lock_time);
        assert_eq!(2, cet.version);
        assert_eq!(0, cet.input[0].sequence);
        assert_eq!(2, cet.output[1].value);
        assert_eq!(1, cet.output[0].value);
    }

    #[test]
    fn create_cet_with_maturity_time_less_than_min_test() {
        let addr = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap();

        let maturity_time = 1;
        let cet_script = vec![0u8, 1, 2, 3];

        let txin = TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: 0,
            witness: Vec::new(),
        };

        let cet = create_cet_transaction(&cet_script, addr, 1, 2, txin, maturity_time);
        assert_eq!(None, cet);
    }
}
