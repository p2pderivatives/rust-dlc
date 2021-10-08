//! Utility functions when working with DLC trie

use secp256k1_zkp::PublicKey;

/// Creates an adaptor point using the provided oracle infos and paths, selecting
/// the oracle info at the provided indexes only. The paths are converted to
/// strings and hashed to be used as messages in adaptor signature creation.
pub(crate) fn get_adaptor_point_for_indexed_paths(
    indexes: &Vec<usize>,
    paths: &Vec<Vec<usize>>,
    precomputed_points: &Vec<Vec<Vec<PublicKey>>>,
) -> Result<PublicKey, super::Error> {
    debug_assert!(indexes.len() == paths.len());
    debug_assert!(precomputed_points.len() >= indexes.len());
    if indexes.len() < 1 {
        return Err(super::Error::InvalidArgument);
    }

    let mut keys = Vec::new();

    for (i, j) in indexes.iter().enumerate() {
        let path = &paths[i];
        let k: Vec<&PublicKey> = precomputed_points[*j]
            .iter()
            .zip(path.iter())
            .map(|(y, p)| &y[*p])
            .collect();
        keys.extend(k);
    }

    Ok(PublicKey::combine_keys(&keys)?)
}
