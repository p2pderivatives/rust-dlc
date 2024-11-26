#![cfg_attr(all(test, feature = "unstable"), feature(test))]

extern crate bitcoin;
extern crate bitcoin_test_utils;
extern crate ddk_dlc;
extern crate rayon;
extern crate secp256k1_zkp;
#[cfg(all(test, feature = "unstable"))]
extern crate test;

#[cfg(all(test, feature = "unstable"))]
mod benches {

    use bitcoin::{ScriptBuf, Transaction};
    use bitcoin_test_utils::tx_from_string;
    use ddk_dlc::*;
    use rayon::prelude::*;
    use secp256k1_zkp::{
        global::SECP256K1, rand::thread_rng, rand::RngCore, Keypair, Message, PublicKey, SecretKey,
    };

    use test::{black_box, Bencher};

    const SINGLE_NB_ORACLES: usize = 1;
    const SINGLE_NB_NONCES: usize = 10;
    const ALL_NB_ORACLES: usize = 1;
    const ALL_NB_NONCES: usize = 10;
    const ALL_BASE: usize = 2;

    fn generate_oracle_info(nb_nonces: usize) -> OracleInfo {
        let public_key = Keypair::new(SECP256K1, &mut thread_rng())
            .x_only_public_key()
            .0;

        let mut nonces = Vec::with_capacity(nb_nonces);
        for _ in 0..nb_nonces {
            nonces.push(
                Keypair::new(SECP256K1, &mut thread_rng())
                    .x_only_public_key()
                    .0,
            );
        }

        OracleInfo { public_key, nonces }
    }

    fn generate_oracle_infos(nb_oracles: usize, nb_nonces: usize) -> Vec<OracleInfo> {
        (0..nb_oracles)
            .map(|_| generate_oracle_info(nb_nonces))
            .collect()
    }

    fn generate_single_outcome_messages(nb_oracles: usize, nb_nonces: usize) -> Vec<Vec<Message>> {
        (0..nb_oracles)
            .map(|_| {
                (0..nb_nonces)
                    .map(|_| {
                        let mut buf = [0u8; 32];
                        thread_rng().fill_bytes(&mut buf);
                        Message::from_digest_slice(&buf).unwrap()
                    })
                    .collect()
            })
            .collect()
    }

    fn generate_all_messages_recur(
        nb_oracles: usize,
        nb_nonces: usize,
        base: usize,
        cur: &mut Vec<usize>,
        result: &mut Vec<Vec<Vec<Message>>>,
    ) {
        if nb_nonces == 0 {
            let mut tmp = Vec::new();
            for _ in 0..nb_oracles {
                tmp.push(
                    cur.iter()
                        .map(|x| Message::from_digest_slice(&[(*x) as u8]).unwrap())
                        .collect(),
                );
            }
            result.push(tmp);
            return;
        }
        for i in 0..base {
            cur.push(i);
            generate_all_messages_recur(nb_oracles, nb_nonces - 1, base, cur, result);
            cur.pop();
        }
    }

    fn generate_all_messages(
        nb_oracles: usize,
        nb_nonces: usize,
        base: usize,
    ) -> Vec<Vec<Vec<Message>>> {
        let mut result = Vec::new();
        let mut cur = Vec::new();

        generate_all_messages_recur(nb_oracles, nb_nonces, base, &mut cur, &mut result);

        result
    }

    fn generate_messages_for_precompute(nb_nonces: usize, base: usize) -> Vec<Vec<Message>> {
        (0..base)
            .map(|i| {
                (0..nb_nonces)
                    .map(|_| Message::from_digest_slice(&[i as u8]).unwrap())
                    .collect()
            })
            .collect()
    }

    fn cet() -> Transaction {
        tx_from_string("02000000019246862ea34db0833bd4bd9e657d61e2e5447d0438f6f6181d1cd329e8cf71c30000000000ffffffff02603bea0b000000001600145dedfbf9ea599dd4e3ca6a80b333c472fd0b3f69a0860100000000001600149652d86bedf43ad264362e6e6eba6eb76450812700000000")
    }

    fn funding_script_pubkey() -> ScriptBuf {
        let seckey = SecretKey::new(&mut thread_rng());
        make_funding_redeemscript(
            &PublicKey::from_secret_key(SECP256K1, &seckey),
            &PublicKey::from_secret_key(SECP256K1, &seckey),
        )
    }

    /// Create a single adaptor signature including both the signature itself and the
    /// aggregated anticipation point (base case).
    #[bench]
    fn bench_create_single_adaptor_sig_including_aggregated_point(b: &mut Bencher) {
        let oracle_infos = generate_oracle_infos(SINGLE_NB_ORACLES, SINGLE_NB_NONCES);
        let seckey = SecretKey::new(&mut thread_rng());
        let cet = cet();

        b.iter(|| {
            black_box(
                create_cet_adaptor_sig_from_oracle_info(
                    SECP256K1,
                    &cet,
                    &oracle_infos,
                    &seckey,
                    &funding_script_pubkey(),
                    cet.output[0].value.to_sat(),
                    &generate_single_outcome_messages(SINGLE_NB_ORACLES, SINGLE_NB_NONCES),
                )
                .unwrap(),
            );
        })
    }

    /// Create an adaptor signature directly from the aggregated anticipation point.
    #[bench]
    fn bench_create_single_adaptor_sig_from_aggregated_point(b: &mut Bencher) {
        let seckey = SecretKey::new(&mut thread_rng());
        let cet = cet();
        let adaptor_point = &PublicKey::from_secret_key(SECP256K1, &seckey);

        b.iter(|| {
            black_box(
                create_cet_adaptor_sig_from_point(
                    SECP256K1,
                    &cet,
                    adaptor_point,
                    &seckey,
                    &funding_script_pubkey(),
                    cet.output[0].value.to_sat(),
                )
                .unwrap(),
            )
        })
    }

    /// Create only the aggregated anticipation point.
    #[bench]
    fn bench_compute_aggregated_point(b: &mut Bencher) {
        let oracle_infos = generate_oracle_infos(SINGLE_NB_ORACLES, SINGLE_NB_NONCES);
        let msgs = generate_single_outcome_messages(SINGLE_NB_ORACLES, SINGLE_NB_NONCES);

        b.iter(|| get_adaptor_point_from_oracle_info(SECP256K1, &oracle_infos, &msgs).unwrap())
    }

    /// Create all possible aggregated anticipation points without any optimization (base case).
    #[bench]
    fn bench_create_all_aggregated_point_base(b: &mut Bencher) {
        let oracle_infos = generate_oracle_infos(ALL_NB_ORACLES, ALL_NB_NONCES);
        let all_msgs = generate_all_messages(ALL_NB_ORACLES, ALL_NB_NONCES, ALL_BASE);

        b.iter(|| {
            compute_all_aggregated_points_base(&all_msgs, &oracle_infos);
        });
    }

    /// Create all possible aggregated anticipation points, pre-computing the anticipation points
    /// for each digits (pre-computation optimization).
    #[bench]
    fn bench_create_all_aggregated_point_pre_compute(b: &mut Bencher) {
        let oracle_infos = generate_oracle_infos(ALL_NB_ORACLES, ALL_NB_NONCES);
        let msgs: Vec<Vec<Message>> = generate_messages_for_precompute(ALL_NB_NONCES, ALL_BASE);

        b.iter(|| compute_all_aggregated_points_precompute(&oracle_infos, &msgs));
    }

    #[bench]
    fn bench_create_all_aggregated_point_pre_compute_parallelize(b: &mut Bencher) {
        let oracle_infos = generate_oracle_infos(ALL_NB_ORACLES, ALL_NB_NONCES);
        let msgs: Vec<Vec<Message>> = generate_messages_for_precompute(ALL_NB_NONCES, ALL_BASE);

        b.iter(|| compute_all_aggregated_points_precompute_parallelize(&oracle_infos, &msgs));
    }

    /// Create all possible aggregated anticipation points, using pre-computation as well as memoization.
    #[bench]
    fn bench_create_all_aggregated_point_pre_compute_memoize(b: &mut Bencher) {
        let oracle_infos = generate_oracle_infos(ALL_NB_ORACLES, ALL_NB_NONCES);
        let msgs: Vec<Vec<Message>> = generate_messages_for_precompute(ALL_NB_NONCES, ALL_BASE);

        b.iter(|| compute_all_aggregated_points_precompute_memoize(&oracle_infos, &msgs));
    }

    /// Create all possible aggregated anticipation points, using pre-computation and memoization.
    /// This differs from the above one in that it performs memoization on the aggregation of the anticipation
    /// points for each digit across all oracles.
    #[bench]
    fn bench_create_all_aggregated_point_pre_compute_memoize2(b: &mut Bencher) {
        let oracle_infos = generate_oracle_infos(ALL_NB_ORACLES, ALL_NB_NONCES);
        let msgs: Vec<Vec<Message>> = generate_messages_for_precompute(ALL_NB_NONCES, ALL_BASE);

        b.iter(|| compute_all_aggregated_points_precompute_memoize2(&oracle_infos, &msgs));
    }

    /// Verify that optimized and base case yield the same result.
    #[test]
    fn test_all_equal_result() {
        let oracle_infos = generate_oracle_infos(ALL_NB_ORACLES, ALL_NB_NONCES);
        let all_msgs: Vec<Vec<Vec<Message>>> =
            generate_all_messages(ALL_NB_ORACLES, ALL_NB_NONCES, ALL_BASE);
        let precomp_msgs: Vec<Vec<Message>> =
            generate_messages_for_precompute(ALL_NB_NONCES, ALL_BASE);

        let base = compute_all_aggregated_points_base(&all_msgs, &oracle_infos);
        let precompute = compute_all_aggregated_points_precompute(&oracle_infos, &precomp_msgs);
        let memoize_precompute =
            compute_all_aggregated_points_precompute_memoize(&oracle_infos, &precomp_msgs);
        let memoize_precompute2 =
            compute_all_aggregated_points_precompute_memoize2(&oracle_infos, &precomp_msgs);
        assert_eq!(base, precompute);
        assert_eq!(precompute, memoize_precompute);
        assert_eq!(precompute, memoize_precompute2);
    }

    fn compute_all_aggregated_points_base(
        msgs: &[Vec<Vec<Message>>],
        oracle_infos: &[OracleInfo],
    ) -> Vec<PublicKey> {
        msgs.iter()
            .map(|m| get_adaptor_point_from_oracle_info(SECP256K1, oracle_infos, m).unwrap())
            .collect::<Vec<PublicKey>>()
    }

    fn compute_all_aggregated_points_precompute(
        oracle_infos: &[OracleInfo],
        msgs: &[Vec<Message>],
    ) -> Vec<PublicKey> {
        let precomputed_points = get_precomputed_points(oracle_infos, msgs);
        let mut all_adaptor_points: Vec<PublicKey> = Vec::new();
        let nb_outcomes = ALL_BASE.pow(ALL_NB_NONCES as u32);
        for i in 0..nb_outcomes {
            let mut to_combine = Vec::with_capacity(ALL_NB_NONCES * ALL_NB_ORACLES);
            for precomputed in &precomputed_points {
                for j in 0..ALL_NB_NONCES {
                    let x = i / (ALL_BASE.pow((ALL_NB_NONCES - j - 1) as u32)) % ALL_BASE;
                    to_combine.push(&precomputed[x][j]);
                }
            }
            all_adaptor_points.push(PublicKey::combine_keys(&to_combine).unwrap());
        }
        all_adaptor_points
    }

    fn compute_all_aggregated_points_precompute_parallelize(
        oracle_infos: &[OracleInfo],
        msgs: &[Vec<Message>],
    ) -> Vec<PublicKey> {
        let precomputed_points = get_precomputed_points(oracle_infos, msgs);
        let nb_outcomes = ALL_BASE.pow(ALL_NB_NONCES as u32);
        (0..nb_outcomes)
            .into_par_iter()
            .map(|i| {
                let mut to_combine = Vec::with_capacity(ALL_NB_NONCES * ALL_NB_ORACLES);
                for precomputed in &precomputed_points {
                    for j in 0..ALL_NB_NONCES {
                        let x = i / (ALL_BASE.pow((ALL_NB_NONCES - j - 1) as u32)) % ALL_BASE;
                        to_combine.push(&precomputed[x][j]);
                    }
                }
                PublicKey::combine_keys(&to_combine).unwrap()
            })
            .collect()
    }

    fn compute_all_aggregated_points_precompute_memoize(
        oracle_infos: &[OracleInfo],
        msgs: &[Vec<Message>],
    ) -> Vec<PublicKey> {
        let mut all_adaptor_points: Vec<PublicKey> = Vec::new();
        let pre_computed_points = get_precomputed_points(oracle_infos, msgs);
        let mut all_outcomes_per_oracle: Vec<Vec<PublicKey>> = Vec::with_capacity(ALL_NB_ORACLES);
        all_outcomes_per_oracle.resize(ALL_NB_ORACLES, Vec::new());
        for i in 0..oracle_infos.len() {
            memoize_recursive(
                0,
                None,
                &pre_computed_points[i],
                &mut all_outcomes_per_oracle[i],
            );
        }

        for i in 0..ALL_BASE.pow(ALL_NB_NONCES as u32) {
            let mut to_add = Vec::new();
            for v in &all_outcomes_per_oracle {
                to_add.push(v[i]);
            }
            if to_add.len() == 1 {
                all_adaptor_points.push(to_add[0]);
            } else {
                all_adaptor_points
                    .push(PublicKey::combine_keys(&to_add.iter().collect::<Vec<_>>()).unwrap());
            }
        }
        all_adaptor_points
    }

    fn compute_all_aggregated_points_precompute_memoize2(
        oracle_infos: &[OracleInfo],
        msgs: &[Vec<Message>],
    ) -> Vec<PublicKey> {
        let mut all_adaptor_points: Vec<PublicKey> = Vec::new();
        let pre_computed_points = get_precomputed_points(oracle_infos, msgs);
        memoize_recursive2(0, None, &pre_computed_points, &mut all_adaptor_points);
        all_adaptor_points
    }

    fn get_precomputed_points(
        oracle_infos: &[OracleInfo],
        msgs: &[Vec<Message>],
    ) -> Vec<Vec<Vec<PublicKey>>> {
        oracle_infos
            .iter()
            .map(|info| {
                msgs.iter()
                    .map(|msg| {
                        msg.iter()
                            .zip(info.nonces.iter())
                            .map(|(m, n)| {
                                secp_utils::schnorrsig_compute_sig_point(
                                    SECP256K1,
                                    &info.public_key,
                                    n,
                                    m,
                                )
                                .unwrap()
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect()
    }

    fn memoize_recursive(
        index: usize,
        prev: Option<PublicKey>,
        nonces_sig_points: &[Vec<PublicKey>],
        res: &mut Vec<PublicKey>,
    ) {
        assert!(index < nonces_sig_points[0].len());
        for i in 0..nonces_sig_points.len() {
            let next = match prev {
                Some(prev) => prev.combine(&nonces_sig_points[i][index]).unwrap(),
                None => nonces_sig_points[i][index],
            };
            if index < nonces_sig_points[0].len() - 1 {
                memoize_recursive(index + 1, Some(next), nonces_sig_points, res);
            } else {
                res.push(next);
            }
        }
    }

    fn memoize_recursive2(
        index: usize,
        prev: Option<PublicKey>,
        nonces_sig_points: &[Vec<Vec<PublicKey>>],
        res: &mut Vec<PublicKey>,
    ) {
        assert!(index < nonces_sig_points[0][0].len());
        for i in 0..nonces_sig_points[0].len() {
            let mut to_combine = Vec::new();
            for o in nonces_sig_points {
                to_combine.push(o[i][index]);
            }
            let next = match prev {
                Some(prev) => {
                    to_combine.push(prev);
                    PublicKey::combine_keys(&to_combine.iter().collect::<Vec<_>>()).unwrap()
                }
                None => PublicKey::combine_keys(&to_combine.iter().collect::<Vec<_>>()).unwrap(),
            };
            if index < nonces_sig_points[0][0].len() - 1 {
                memoize_recursive2(index + 1, Some(next), nonces_sig_points, res);
            } else {
                res.push(next);
            }
        }
    }
}
