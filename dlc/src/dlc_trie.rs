//! # DlcTrie
//! Common trait and functions for trie data structures that store adaptor
//! signature information.

use crate::{Error, OracleInfo, RangeInfo, RangePayout};
use bitcoin::{Script, Transaction};
use secp256k1::{
    ecdsa_adaptor::{AdaptorProof, AdaptorSignature},
    All, PublicKey, Secp256k1, SecretKey, Signing,
};

/// A common trait for trie data structures that store DLC adaptor signature
/// information.
pub trait DlcTrie {
    /// Generate the trie using the provided outcomes and oracle information,
    /// calling the provided callback with the CET index and adaptor point for
    /// each adaptor signature.
    fn generate<C: Signing, F>(
        &mut self,
        secp: &Secp256k1<C>,
        outcomes: &[RangePayout],
        oracle_infos: &[OracleInfo],
        callback: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(usize, &PublicKey) -> Result<usize, Error>;

    /// Iterate through the trie calling the provided callback for each adaptor
    /// signature passing the corresponding adaptor point and RangeInfo.
    fn iter<F>(
        &self,
        secp: &Secp256k1<All>,
        oracle_infos: &[OracleInfo],
        callback: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(&PublicKey, &RangeInfo) -> Result<(), Error>;

    /// Generate the trie while verifying the provided adaptor signatures.
    fn generate_verify(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        outcomes: &Vec<RangePayout>,
        cets: &[Transaction],
        oracle_infos: &[OracleInfo],
        adaptor_pairs: &[(AdaptorSignature, AdaptorProof)],
        adaptor_index_start: usize,
    ) -> Result<usize, Error> {
        let mut adaptor_sig_index = adaptor_index_start;
        let mut verify_callback =
            |cet_index: usize, adaptor_point: &PublicKey| -> Result<usize, crate::Error> {
                let adaptor_pair = adaptor_pairs[adaptor_sig_index];
                let cet = &cets[cet_index];
                adaptor_sig_index += 1;
                super::verify_cet_adaptor_sig_from_point(
                    secp,
                    &adaptor_pair.0,
                    &adaptor_pair.1,
                    cet,
                    &adaptor_point,
                    &fund_pubkey,
                    &funding_script_pubkey,
                    fund_output_value,
                )?;
                Ok(adaptor_sig_index - 1)
            };
        self.generate(secp, outcomes, oracle_infos, &mut verify_callback)?;
        Ok(adaptor_sig_index)
    }

    /// Generate the trie while creating the set of adaptor signatures.
    fn generate_sign<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        outcomes: &Vec<RangePayout>,
        cets: &[Transaction],
        oracle_infos: &[OracleInfo],
        adaptor_index_start: usize,
    ) -> Result<Vec<(AdaptorSignature, AdaptorProof)>, Error> {
        let mut adaptor_pairs = Vec::new();
        let mut adaptor_index = adaptor_index_start;
        let mut sign_callback =
            |cet_index: usize, adaptor_point: &PublicKey| -> Result<usize, crate::Error> {
                let adaptor_pair = crate::create_cet_adaptor_sig_from_point(
                    &secp,
                    &cets[cet_index],
                    &adaptor_point,
                    fund_privkey,
                    &funding_script_pubkey,
                    fund_output_value,
                )?;
                adaptor_pairs.push(adaptor_pair);
                adaptor_index += 1;
                Ok(adaptor_index - 1)
            };
        self.generate(secp, outcomes, oracle_infos, &mut sign_callback)?;
        Ok(adaptor_pairs)
    }

    /// Verify that the provided signatures are valid with respect to the
    /// information stored in the trie.
    fn verify(
        &self,
        secp: &Secp256k1<All>,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        adaptor_pairs: &[(AdaptorSignature, AdaptorProof)],
        cets: &[Transaction],
        oracle_infos: &[OracleInfo],
    ) -> Result<usize, Error> {
        let mut max_adaptor_index = 0;
        let mut callback =
            |adaptor_point: &PublicKey, range_info: &RangeInfo| -> Result<(), Error> {
                let adaptor_pair = adaptor_pairs[range_info.adaptor_index];
                let cet = &cets[range_info.cet_index];
                if range_info.adaptor_index > max_adaptor_index {
                    max_adaptor_index = range_info.adaptor_index;
                }
                super::verify_cet_adaptor_sig_from_point(
                    secp,
                    &adaptor_pair.0,
                    &adaptor_pair.1,
                    cet,
                    &adaptor_point,
                    &fund_pubkey,
                    &funding_script_pubkey,
                    fund_output_value,
                )
            };

        self.iter(secp, oracle_infos, &mut callback)?;
        Ok(max_adaptor_index + 1)
    }

    /// Produce the set of adaptor signatures for the trie.
    fn sign(
        &self,
        secp: &Secp256k1<All>,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        oracle_infos: &[OracleInfo],
    ) -> Result<Vec<(AdaptorSignature, AdaptorProof)>, Error>;
}
