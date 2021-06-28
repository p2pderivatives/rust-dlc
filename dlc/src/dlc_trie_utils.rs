//! Utility functions when working with DLC trie

use super::OracleInfo;
use bitcoin::hashes::*;
use secp256k1::{Message, PublicKey, Secp256k1, Signing};

/// Creates an adaptor point using the provided oracle infos and paths. The paths
/// are converted to strings and hashed to be used as messages in adaptor signature
/// creation.
pub(crate) fn get_adaptor_point_from_paths<C: Signing>(
    secp: &Secp256k1<C>,
    oracle_infos: &[OracleInfo],
    paths: &[Vec<usize>],
) -> Result<PublicKey, super::Error> {
    debug_assert!(oracle_infos.len() == paths.len());

    let paths_msg: Vec<Vec<Message>> = paths
        .iter()
        .map(|x| {
            x.iter()
                .map(|y| Message::from_hashed_data::<sha256::Hash>(y.to_string().as_bytes()))
                .collect()
        })
        .collect();
    super::get_adaptor_point_from_oracle_info(&secp, oracle_infos, &paths_msg)
}

/// Creates an adaptor point using the provided oracle infos and paths, selecting
/// the oracle info at the provided indexes only. The paths are converted to
/// strings and hashed to be used as messages in adaptor signature creation.
pub(crate) fn get_adaptor_point_for_indexed_paths<C: Signing>(
    secp: &Secp256k1<C>,
    oracle_infos: &[OracleInfo],
    indexes: &Vec<usize>,
    paths: &Vec<Vec<usize>>,
) -> Result<PublicKey, super::Error> {
    debug_assert!(indexes.len() == paths.len());
    debug_assert!(oracle_infos.len() >= indexes.len());

    let filtered_oracle_infos: Vec<OracleInfo> = oracle_infos
        .iter()
        .enumerate()
        .filter_map(|(i, x)| {
            if indexes.contains(&i) {
                Some(x.clone())
            } else {
                None
            }
        })
        .collect();

    get_adaptor_point_from_paths(&secp, &filtered_oracle_infos, paths)
}
