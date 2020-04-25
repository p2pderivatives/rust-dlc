use bitcoin::blockdata::transaction::{TxOut, TxIn, Transaction};
use secp256k1::PublicKey;

use lightning::ln::chan_utils::*;

const DUST_LIMIT: u64 = 5000;
const TX_VERSION: u32 = 2;

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
