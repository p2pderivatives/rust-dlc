//! # optcat utils

use std::convert::TryInto as _;

use bitcoin::{
    absolute::LockTime,
    consensus::Encodable,
    hashes::{sha256, Hash, HashEngine},
    hex::{Case, DisplayHex},
    opcodes::all::*,
    script::Builder,
    sighash::{Annex, Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Amount, OutPoint, Script, ScriptBuf, Sequence, TapLeafHash, TapSighash, TapSighashType,
    Transaction, TxIn, TxOut, XOnlyPublicKey,
};
use lazy_static::lazy_static;
use log::debug;
use secp256k1_zkp::{
    constants::GENERATOR_X, All, Keypair, Message, PublicKey, Secp256k1, SECP256K1,
};

use crate::{get_payout_outputs, Error, Payout};

lazy_static! {
    pub(crate) static ref G_X: [u8; 32] = GENERATOR_X;
    pub(crate) static ref TAPSIGHASH_TAG: [u8; 10] = {
        let mut tag = [0u8; 10];
        let val = "TapSighash".as_bytes();
        tag.copy_from_slice(val);
        tag
    };
    pub(crate) static ref BIP0340_CHALLENGE_TAG: [u8; 17] = {
        let mut tag = [0u8; 17];
        let val = "BIP0340/challenge".as_bytes();
        tag.copy_from_slice(val);
        tag
    };
    pub(crate) static ref DUST_AMOUNT: [u8; 8] = {
        let mut dust = [0u8; 8];
        let mut buffer = Vec::new();
        let amount = Amount::from_sat(546);
        amount.consensus_encode(&mut buffer).unwrap();
        dust.copy_from_slice(&buffer);
        dust
    };
}

#[derive()]
pub(crate) struct TxCommitmentSpec {
    pub(crate) epoch: bool,
    pub(crate) control: bool,
    pub(crate) version: bool,
    pub(crate) lock_time: bool,
    pub(crate) prevouts: bool,
    pub(crate) prev_amounts: bool,
    pub(crate) prev_sciptpubkeys: bool,
    pub(crate) sequences: bool,
    pub(crate) input_index: bool,
    pub(crate) outputs: bool,
    pub(crate) spend_type: bool,
    pub(crate) annex: bool,
    pub(crate) single_output: bool,
    pub(crate) scriptpath: bool,
}

impl Default for TxCommitmentSpec {
    fn default() -> Self {
        Self {
            epoch: true,
            control: true,
            version: true,
            lock_time: true,
            prevouts: true,
            prev_amounts: true,
            prev_sciptpubkeys: true,
            sequences: true,
            input_index: true,
            outputs: true,
            spend_type: true,
            annex: true,
            single_output: true,
            scriptpath: true,
        }
    }
}

/// Create the dlc tx
pub fn create_dlc_tx(
    outpoint: OutPoint,
    prev_output: TxOut,
    offer_spk: &Script,
    accept_spk: &Script,
    agg_key: &Keypair,
    payout: Payout,
    taproot_spend_info: &TaprootSpendInfo,
) -> Result<Transaction, Error> {
    let mut collateral_txin = TxIn {
        previous_output: outpoint,
        ..Default::default()
    };

    let outputs = get_payout_outputs(&payout, offer_spk, accept_spk);

    let txn = Transaction {
        lock_time: LockTime::ZERO,
        version: Version(2),
        input: vec![collateral_txin.clone()],
        output: outputs.clone(),
    };

    let tx_commitment_spec = TxCommitmentSpec {
        outputs: false,
        ..Default::default()
    };

    let pubkey = agg_key.x_only_public_key();

    let enforce_payout_spk = vault_dlc_withdrawal(&outputs, pubkey.0);

    let leaf_hash = TapLeafHash::from_script(&enforce_payout_spk, LeafVersion::TapScript);
    let contract_components = grind_transaction(
        txn,
        GrindField::LockTime,
        std::slice::from_ref(&prev_output),
        leaf_hash,
    )?;

    let mut txn = contract_components.transaction;
    let witness_components = get_sigmsg_components(
        &tx_commitment_spec,
        &txn,
        0,
        std::slice::from_ref(&prev_output),
        None,
        leaf_hash,
        TapSighashType::Default,
    )?;

    for component in witness_components.iter() {
        log::debug!(
            "pushing component <0x{}> into the witness",
            hex::encode(component)
        );
        collateral_txin.witness.push(component.as_slice());
    }
    let computed_signature =
        compute_signature_from_components(&contract_components.signature_components)?;

    let mangled_signature: [u8; 63] = computed_signature[0..63].try_into().unwrap(); // chop off the last byte, so we can provide the 0x00 and 0x01 bytes on the stack
    collateral_txin.witness.push(mangled_signature);

    let prevouts = Prevouts::All(&[prev_output]);
    let mut cache = SighashCache::new(&txn);
    let sighash_type = TapSighashType::Default;
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0, // input index
            &prevouts,
            leaf_hash,
            sighash_type,
        )
        .unwrap();

    let digest = sighash.as_byte_array();
    let msg = Message::from_digest_slice(digest)?;
    let sig = SECP256K1.sign_schnorr(&msg, agg_key);
    collateral_txin.witness.push(sig.serialize());

    // Build the taproot tree of outcomes
    // let spend_info = build_cat_taproot_leafs(
    //     outcomes,
    //     output.script_pubkey.clone(),
    //     create_nums_key(),
    //     oracle_infos,
    // ); // todo use this later, for now no DLC part

    // let secp = Secp256k1::new();
    // let spend_info = TaprootBuilder::new()
    //     .add_leaf(0, enforce_payout_spk.clone())
    //     .unwrap()
    //     .finalize(&secp, create_nums_key())
    //     .unwrap();

    // vault_txin
    //     .witness
    //     .push(vault_trigger_withdrawal(self.x_only_public_key()).to_bytes());
    // vault_txin.witness.push(
    //     self.taproot_spend_info()?
    //         .control_block(&(
    //             vault_trigger_withdrawal(self.x_only_public_key()).clone(),
    //             LeafVersion::TapScript,
    //         ))
    //         .expect("control block should work")
    //         .serialize(),
    // );

    collateral_txin
        .witness
        .push(enforce_payout_spk.clone().to_bytes());
    let cb = taproot_spend_info
        .control_block(&(enforce_payout_spk.clone(), LeafVersion::TapScript))
        .expect("control block should work");

    let ok = cb.verify_taproot_commitment(
        SECP256K1,
        taproot_spend_info.output_key().to_inner(),
        &enforce_payout_spk,
    );

    assert!(ok, "control block does not match taptree/output key");

    collateral_txin.witness.push(cb.serialize());
    txn.input.first_mut().unwrap().witness = collateral_txin.witness.clone();

    Ok(txn)
}

/// Doc
pub fn vault_dlc_withdrawal(outputs: &[TxOut], pubkey: XOnlyPublicKey) -> ScriptBuf {
    let mut builder = Script::builder();
    // The witness program needs to have the signature components except the outputs and the pre_scriptpubkeys and pre_amounts,
    // followed by the output amount, then the script pubkey,
    // followed by the fee amount, then the fee-paying scriptpubkey
    // and finally the mangled signature

    let mut buffer = Vec::new();
    for o in outputs {
        o.consensus_encode(&mut buffer).unwrap();
    }
    let output_hash_bytes = bitcoin::hashes::sha256::Hash::hash(&buffer);

    builder = builder
        .push_slice(pubkey.serialize())
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_opcode(OP_TOALTSTACK) // move pre-computed signature minus last byte to alt stack
        // start with encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // input index
        .push_opcode(OP_CAT) // spend type
        .push_slice(output_hash_bytes.to_byte_array())
        .push_opcode(OP_SWAP) // move the hashed encoded outputs below our working sigmsg
        .push_opcode(OP_CAT) // outputs
        .push_opcode(OP_CAT) // prev sequences
        .push_opcode(OP_CAT) // prev scriptpubkeys
        .push_opcode(OP_CAT) // prev amounts
        .push_opcode(OP_CAT) // prevouts
        .push_opcode(OP_CAT) // lock time
        .push_opcode(OP_CAT) // version
        .push_opcode(OP_CAT) // control
        .push_opcode(OP_CAT); // epoch
    builder = add_signature_construction_and_check(builder);
    builder.into_script()
}

/// Assumes that the builder has the sigmsg on the stack, and the pre-computed mangled signature on top of the alt stack.
/// will construct the tagged hash and the signature and do the verification
/// Call this after you've CAT'd the epoch onto the sigmsg
pub(crate) fn add_signature_construction_and_check(builder: Builder) -> Builder {
    builder
        .push_slice(*TAPSIGHASH_TAG) // push tag
        .push_opcode(OP_SHA256) // hash tag
        .push_opcode(OP_DUP) // dup hash
        .push_opcode(OP_ROT) // move the sighash to the top of the stack
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_SHA256) // tagged hash of the sighash
        .push_slice(*BIP0340_CHALLENGE_TAG) // push tag
        .push_opcode(OP_SHA256)
        .push_opcode(OP_DUP)
        .push_opcode(OP_ROT) // bring challenge to the top of the stack
        .push_slice(*G_X) // G is used for the pubkey and K
        .push_opcode(OP_DUP)
        .push_opcode(OP_DUP)
        .push_opcode(OP_TOALTSTACK) // we'll need a copy of G later to be our R value in the signature
        .push_opcode(OP_ROT) // bring the challenge to the top of the stack
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT) // cat the two tags, R, P, and M values together
        .push_opcode(OP_SHA256) // hash the whole thing to get the s value for the signature
        .push_opcode(OP_FROMALTSTACK) // bring G back from the alt stack to use as the R value in the signature
        .push_opcode(OP_SWAP)
        .push_opcode(OP_CAT) // cat the R value with the s value for a complete signature
        .push_opcode(OP_FROMALTSTACK) // grab the pre-computed signature minus the last byte from the alt stack
        .push_opcode(OP_DUP) // we'll need a second copy later to do the actual signature verification
        .push_slice([0x00u8]) // add the last byte of the signature, which should match what we computed. NOTE ⚠️: push_int(0) will not work here because it will push OP_FALSE, but we want an actual 0 byte
        .push_opcode(OP_CAT)
        .push_opcode(OP_ROT) // bring the script-computed signature to the top of the stack
        .push_opcode(OP_EQUALVERIFY) // check that the script-computed and pre-computed signatures match
        .push_int(0x01) // we need the last byte of the signature to be 0x01 because our k value is 1 (because K is G)
        .push_opcode(OP_CAT)
        .push_slice(*G_X) // push G again. TODO: DUP this from before and stick it in the alt stack or something
        .push_opcode(OP_CHECKSIG)
}

/// Grind a tx
pub fn grind_transaction<S>(
    initial_tx: Transaction,
    grind_field: GrindField,
    prevouts: &[TxOut],
    leaf_hash: S,
) -> Result<ContractComponents, Error>
where
    S: Into<TapLeafHash> + Clone,
{
    let signature_components: Vec<Vec<u8>>;
    let mut counter = 0;

    let mut spend_tx = initial_tx.clone();

    loop {
        match grind_field {
            GrindField::LockTime => spend_tx.lock_time = LockTime::from_height(counter).unwrap(),
            GrindField::Sequence => {
                // make sure counter has the 31st bit set, so that it's not used as a relative timelock
                // (BIP68 tells us that bit disables the consensus meaning of sequence numbers for RTL)
                counter |= 1 << 31;
                // set the sequence number of the last input to the counter, we'll use that to pay fees if there is more than one input
                spend_tx.input.last_mut().unwrap().sequence = Sequence::from_consensus(counter);
            }
        }
        debug!("grinding counter {}", counter);

        let components_for_signature = get_sigmsg_components(
            &TxCommitmentSpec::default(),
            &spend_tx,
            0,
            prevouts,
            None,
            leaf_hash.clone(),
            TapSighashType::Default,
        )?;
        let sigmsg = compute_sigmsg_from_components(&components_for_signature)?;
        let challenge = compute_challenge(&sigmsg);

        if challenge[31] == 0 {
            debug!("Found a challenge with a {} at the end!", challenge[31]);
            debug!("{:?} is {}", grind_field, counter);
            debug!("Here's the challenge: {}", hex::encode(challenge));
            signature_components = components_for_signature;
            break;
        }
        counter += 1;
    }
    Ok(ContractComponents {
        transaction: spend_tx,
        signature_components,
    })
}

/// Components
pub struct ContractComponents {
    pub(crate) transaction: Transaction,
    pub(crate) signature_components: Vec<Vec<u8>>,
}

#[derive(Debug)]
/// Type of grinding
pub enum GrindField {
    /// Locktime grinding
    LockTime,
    /// Sequence grinding
    Sequence,
}

pub(crate) fn compute_sigmsg_from_components(components: &[Vec<u8>]) -> Result<[u8; 32], Error> {
    debug!("creating sigmsg from components",);
    let mut hashed_tag = sha256::Hash::engine();
    hashed_tag.input("TapSighash".as_bytes());
    let hashed_tag = sha256::Hash::from_engine(hashed_tag);

    let mut serialized_tx = sha256::Hash::engine();
    serialized_tx.input(hashed_tag.as_ref());
    serialized_tx.input(hashed_tag.as_ref());

    {
        let tapsighash_engine = TapSighash::engine();
        assert_eq!(tapsighash_engine.midstate(), serialized_tx.midstate());
    }

    for component in components.iter() {
        serialized_tx.input(component.as_slice());
    }

    let tagged_hash = sha256::Hash::from_engine(serialized_tx);
    Ok(tagged_hash.to_byte_array())
}

pub(crate) fn compute_challenge(sigmsg: &[u8; 32]) -> [u8; 32] {
    let mut buffer = Vec::new();
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut sigmsg.to_vec());
    make_tagged_hash("BIP0340/challenge".as_bytes(), buffer.as_slice())
}

fn make_tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    // make a hashed_tag which is sha256(tag)
    let mut hashed_tag = sha256::Hash::engine();
    hashed_tag.input(tag);
    let hashed_tag = sha256::Hash::from_engine(hashed_tag);

    // compute the message to be hashed. It is prefixed with the hashed_tag twice
    // for example, hashed_tag || hashed_tag || data
    let mut message = sha256::Hash::engine();
    message.input(hashed_tag.as_ref());
    message.input(hashed_tag.as_ref());
    message.input(data);
    let message = sha256::Hash::from_engine(message);
    message.to_byte_array()
}

pub(crate) fn get_sigmsg_components<S: Into<TapLeafHash>>(
    spec: &TxCommitmentSpec,
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    annex: Option<Annex>,
    leaf_hash: S,
    sighash_type: TapSighashType,
) -> Result<Vec<Vec<u8>>, Error> {
    // all this serialization code was lifted from bitcoin-0.31.1/src/crypto/sighash.rs:597 and
    // then very violently hacked up.

    let mut components = Vec::new();

    let leaf_hash_code_separator = Some((leaf_hash.into(), 0xFFFFFFFFu32));

    let (sighash, anyone_can_pay) = match sighash_type {
        TapSighashType::Default => (bitcoin::TapSighashType::Default, false),
        TapSighashType::All => (bitcoin::TapSighashType::All, false),
        TapSighashType::None => (bitcoin::TapSighashType::None, false),
        TapSighashType::Single => (bitcoin::TapSighashType::Single, false),
        TapSighashType::AllPlusAnyoneCanPay => (TapSighashType::All, true),
        TapSighashType::NonePlusAnyoneCanPay => (bitcoin::TapSighashType::None, true),
        TapSighashType::SinglePlusAnyoneCanPay => (TapSighashType::Single, true),
    };

    if spec.epoch {
        let mut epoch = Vec::new();
        0u8.consensus_encode(&mut epoch).unwrap();
        debug!("epoch: {:?}", epoch.to_hex_string(Case::Lower));
        components.push(epoch);
    }

    if spec.control {
        let mut control = Vec::new();
        (sighash_type as u8).consensus_encode(&mut control).unwrap();
        debug!("control: {:?}", control.to_hex_string(Case::Lower));
        components.push(control);
    }

    if spec.version {
        let mut version = Vec::new();
        tx.version.consensus_encode(&mut version).unwrap();
        debug!("version: {:?}", version.to_hex_string(Case::Lower));
        components.push(version);
    }

    if spec.lock_time {
        let mut lock_time = Vec::new();
        tx.lock_time.consensus_encode(&mut lock_time).unwrap();
        debug!("lock_time: {:?}", lock_time.to_hex_string(Case::Lower));
        components.push(lock_time);
    }

    if !anyone_can_pay {
        if spec.prevouts {
            let mut prevouts = Vec::new();
            let mut buffer = Vec::new();
            for prevout in tx.input.iter() {
                prevout
                    .previous_output
                    .consensus_encode(&mut buffer)
                    .unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut prevouts).unwrap();
            debug!("prevouts: {:?}", prevouts.to_hex_string(Case::Lower));
            components.push(prevouts);
        }

        if spec.prev_amounts {
            let mut prev_amounts = Vec::new();
            let mut buffer = Vec::new();
            for p in prevouts {
                p.value.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut prev_amounts).unwrap();
            debug!(
                "prev_amounts: {:?}",
                prev_amounts.to_hex_string(Case::Lower)
            );
            components.push(prev_amounts);
        }
        if spec.prev_sciptpubkeys {
            let mut prev_sciptpubkeys = Vec::new();
            let mut buffer = Vec::new();
            for p in prevouts {
                p.script_pubkey.consensus_encode(&mut buffer).unwrap();
            }
            debug!(
                "prev_sciptpubkeys buffer: {:?}",
                buffer.to_hex_string(Case::Lower)
            );

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut prev_sciptpubkeys).unwrap();
            debug!(
                "prev_sciptpubkeys: {:?}",
                prev_sciptpubkeys.to_hex_string(Case::Lower)
            );
            components.push(prev_sciptpubkeys);
        }
        if spec.sequences {
            let mut sequences = Vec::new();
            let mut buffer = Vec::new();
            for i in tx.input.iter() {
                i.sequence.consensus_encode(&mut buffer).unwrap();
            }

            let hash = sha256::Hash::hash(&buffer);
            hash.consensus_encode(&mut sequences).unwrap();
            debug!("sequences: {:?}", sequences.to_hex_string(Case::Lower));
            components.push(sequences);
        }
    }

    if spec.outputs && sighash != TapSighashType::None && sighash != TapSighashType::Single {
        let mut outputs = Vec::new();
        let mut buffer = Vec::new();
        for o in tx.output.iter() {
            o.consensus_encode(&mut buffer).unwrap();
        }
        let hash = sha256::Hash::hash(&buffer);
        hash.consensus_encode(&mut outputs).unwrap();
        debug!("outputs: {:?}", outputs.to_hex_string(Case::Lower));
        components.push(outputs);
    }

    if spec.spend_type {
        let mut encoded_spend_type = Vec::new();
        let mut spend_type = 0u8;
        if annex.is_some() {
            spend_type |= 1u8;
        }
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2u8;
        }
        spend_type
            .consensus_encode(&mut encoded_spend_type)
            .unwrap();
        debug!(
            "spend_type: {:?}",
            encoded_spend_type.to_hex_string(Case::Lower)
        );
        components.push(encoded_spend_type);
    }

    // TODO: wrap these fields in spec checks. right now we dont use ANYONECANPAY so it doesnt matter. But some other applications might want to use it.

    // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
    //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
    //      amount (8): value of the previous output spent by this input.
    //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
    //      nSequence (4): nSequence of this input.
    if anyone_can_pay {
        let txin = &tx.input.get(input_index).unwrap();
        let previous_output = prevouts.get(input_index).unwrap();
        let mut prevout = Vec::new();
        txin.previous_output.consensus_encode(&mut prevout).unwrap();
        debug!("input prevout: {:?}", prevout.to_hex_string(Case::Lower));
        components.push(prevout);
        let mut amount = Vec::new();
        previous_output.value.consensus_encode(&mut amount).unwrap();
        debug!("input amount: {:?}", amount.to_hex_string(Case::Lower));
        components.push(amount);
        let mut script_pubkey = Vec::new();
        previous_output
            .script_pubkey
            .consensus_encode(&mut script_pubkey)
            .unwrap();
        debug!(
            "input script_pubkey: {:?}",
            script_pubkey.to_hex_string(Case::Lower)
        );
        components.push(script_pubkey);
        let mut sequence = Vec::new();
        txin.sequence.consensus_encode(&mut sequence).unwrap();
        debug!("input sequence: {:?}", sequence.to_hex_string(Case::Lower));
        components.push(sequence);
    } else if spec.input_index {
        let mut input_idx = Vec::new();
        (input_index as u32)
            .consensus_encode(&mut input_idx)
            .unwrap();
        debug!("input index: {:?}", input_idx.to_hex_string(Case::Lower));
        components.push(input_idx);
    }

    // If an annex is present (the lowest bit of spend_type is set):
    //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
    //      includes the mandatory 0x50 prefix.
    if spec.annex {
        if let Some(annex) = annex {
            let mut encoded_annex = Vec::new();
            let mut enc = sha256::Hash::engine();
            annex.consensus_encode(&mut enc).unwrap();
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut encoded_annex).unwrap();
            debug!("annex: {:?}", encoded_annex.to_hex_string(Case::Lower));
            components.push(encoded_annex);
        }
    }

    // * Data about this output:
    // If hash_type & 3 equals SIGHASH_SINGLE:
    //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
    if spec.single_output && sighash == TapSighashType::Single {
        let mut encoded_single_output = Vec::new();
        let mut enc = sha256::Hash::engine();
        tx.output
            .get(input_index)
            .unwrap()
            .consensus_encode(&mut enc)
            .unwrap();
        let hash = sha256::Hash::from_engine(enc);
        hash.consensus_encode(&mut encoded_single_output).unwrap();
        debug!(
            "single_output: {:?}",
            encoded_single_output.to_hex_string(Case::Lower)
        );
        components.push(encoded_single_output);
    }

    //     if (scriptpath):
    //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
    //         ss += bytes([0])
    //         ss += struct.pack("<i", codeseparator_pos)

    if spec.scriptpath {
        #[allow(non_snake_case)]
        let KEY_VERSION_0 = 0u8;

        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            let mut encoded_leaf_hash = Vec::new();
            hash.as_byte_array()
                .consensus_encode(&mut encoded_leaf_hash)
                .unwrap();
            debug!(
                "leaf_hash: {:?}",
                encoded_leaf_hash.to_hex_string(Case::Lower)
            );
            components.push(encoded_leaf_hash);
            let mut encoded_leaf_hash = Vec::new();
            KEY_VERSION_0
                .consensus_encode(&mut encoded_leaf_hash)
                .unwrap();
            debug!(
                "leaf_ver: {:?}",
                encoded_leaf_hash.to_hex_string(Case::Lower)
            );
            components.push(encoded_leaf_hash);
            let mut encoded_leaf_hash = Vec::new();
            code_separator_pos
                .consensus_encode(&mut encoded_leaf_hash)
                .unwrap();
            debug!(
                "code_separator_pos: {:?}",
                encoded_leaf_hash.to_hex_string(Case::Lower)
            );
            components.push(encoded_leaf_hash);
        }
    }

    Ok(components)
}

pub(crate) fn compute_signature_from_components(components: &[Vec<u8>]) -> Result<[u8; 64], Error> {
    let sigmsg = compute_sigmsg_from_components(components)?;
    let mut buffer = Vec::new();
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut sigmsg.to_vec());
    let challenge = make_tagged_hash("BIP0340/challenge".as_bytes(), buffer.as_slice());
    Ok(make_signature(&challenge))
}

fn make_signature(challenge: &[u8; 32]) -> [u8; 64] {
    let mut signature: [u8; 64] = [0; 64];
    signature[0..32].copy_from_slice(&G_X[..]);
    signature[32..64].copy_from_slice(challenge);
    signature
}

/// Construct taproot spend info from a list of scripts
pub fn taproot_spend_info(
    secp: &Secp256k1<All>,
    scripts: &[ScriptBuf],
) -> Result<TaprootSpendInfo, Error> {
    // hash G into a NUMS point
    let mut g_uncompressed = [0u8; 65];
    g_uncompressed[0] = 0x04;
    g_uncompressed[1..33].copy_from_slice(&secp256k1_zkp::constants::GENERATOR_X);
    g_uncompressed[33..65].copy_from_slice(&secp256k1_zkp::constants::GENERATOR_Y);
    let hash = sha256::Hash::hash(&g_uncompressed);
    let x_bytes = hash.to_byte_array(); // [u8; 32]
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // even-Y tag for BIP340 points
    compressed[1..].copy_from_slice(&x_bytes);
    let nums_full_pk = PublicKey::from_slice(&compressed).expect("Invalid NUMS");

    let (nums_key, _parity) = nums_full_pk.x_only_public_key();

    // let builder = TaprootBuilder::new()
    //     .add_leaf(1, scripts[0].clone())
    //     .unwrap()
    //     .add_leaf(1, scripts[1].clone())
    //     .unwrap();

    let builder = TaprootBuilder::with_huffman_tree(scripts.iter().cloned().map(|x| (1, x)))
        .expect("To be able to build the tree");
    Ok(builder.finalize(secp, nums_key).unwrap())
}
