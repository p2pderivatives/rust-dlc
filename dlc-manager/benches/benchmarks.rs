#![cfg_attr(all(test, feature = "unstable"), feature(test))]

#[cfg(all(test, feature = "unstable"))]
extern crate test;

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use dlc_manager::contract::accepted_contract::AcceptedContract;
    use dlc_manager::contract::offered_contract::OfferedContract;
    use dlc_manager::contract::signed_contract::SignedContract;
    use lightning::util::ser::Readable;
    use secp256k1_zkp::bitcoin_hashes::sha256;
    use secp256k1_zkp::global::SECP256K1;
    use secp256k1_zkp::PublicKey;
    use secp256k1_zkp::SecretKey;
    use secp256k1_zkp::{EcdsaAdaptorSignature, Message};
    use test::{black_box, Bencher};

    fn accept_seckey() -> SecretKey {
        "c0296e3059b34c9707f05dc54ec008de90c0ce52841ff54b98e51487de031e6d"
            .parse()
            .unwrap()
    }

    fn offer_seckey() -> SecretKey {
        "c3b1634c6a13019f372722db0ec0435df11fb2dd6b0b5c647503ef6b5e4656ec"
            .parse()
            .unwrap()
    }

    fn offered_contract() -> OfferedContract {
        let ser = include_bytes!("./bench_files/offered");
        let mut cur = std::io::Cursor::new(&ser);
        Readable::read(&mut cur).unwrap()
    }

    fn accepted_contract() -> AcceptedContract {
        let ser = include_bytes!("./bench_files/accepted");
        let mut cur = std::io::Cursor::new(&ser);
        Readable::read(&mut cur).unwrap()
    }

    fn signed_contract() -> SignedContract {
        let ser = include_bytes!("./bench_files/signed");
        let mut cur = std::io::Cursor::new(&ser);
        Readable::read(&mut cur).unwrap()
    }

    #[bench]
    fn single_oracle_sign_bench(b: &mut Bencher) {
        let accepted = accepted_contract();
        let offered = accepted.offered_contract;
        let dlc_transactions = accepted.dlc_transactions;
        let fund_output_value = dlc_transactions.get_fund_output().value;

        let cet_input = dlc_transactions.cets[0].input[0].clone();
        let seckey = accept_seckey();
        b.iter(|| {
            black_box(
                offered.contract_info[0]
                    .get_adaptor_info(
                        &SECP256K1,
                        offered.total_collateral,
                        &seckey,
                        &dlc_transactions.funding_script_pubkey,
                        fund_output_value,
                        &dlc_transactions.cets,
                        0,
                    )
                    .unwrap(),
            )
        });
    }

    #[bench]
    fn single_oracle_verify_bench(b: &mut Bencher) {
        let signed = signed_contract();
        let accepted = signed.accepted_contract;
        let offered = accepted.offered_contract;
        let dlc_transactions = accepted.dlc_transactions;
        let fund_output_value = dlc_transactions.get_fund_output().value;
        let offer_params = &offered.offer_params;

        let cet_input = dlc_transactions.cets[0].input[0].clone();
        let seckey = accept_seckey();
        let adaptor_signatures = &signed.adaptor_signatures.unwrap();
        b.iter(|| {
            black_box(
                offered.contract_info[0]
                    .verify_and_get_adaptor_info(
                        &SECP256K1,
                        offered.total_collateral,
                        &offer_params.fund_pubkey,
                        &dlc_transactions.funding_script_pubkey,
                        fund_output_value,
                        &dlc_transactions.cets,
                        adaptor_signatures,
                        0,
                    )
                    .unwrap(),
            )
        });
    }
}
