//!
use std::sync::{Arc, Mutex};

use bitcoin::{Script, Transaction, TxOut};
use lightning::{
    chain::keysinterface::{
        BaseSign, ExtraSign, InMemorySigner, KeyMaterial, KeysInterface, KeysManager, Recipient,
        Sign, SpendableOutputDescriptor,
    },
    ln::{chan_utils::ChannelPublicKeys, msgs::DecodeError, script::ShutdownScript},
    util::ser::Writeable,
};
use secp256k1_zkp::{ecdsa::RecoverableSignature, Secp256k1, SecretKey, Signing};

///
pub struct CustomSigner {
    in_memory_signer: Arc<Mutex<InMemorySigner>>,
    // TODO(tibo): this might not be safe.
    channel_public_keys: ChannelPublicKeys,
}

impl CustomSigner {
    ///
    pub fn new(in_memory_signer: InMemorySigner) -> Self {
        Self {
            channel_public_keys: in_memory_signer.pubkeys().clone(),
            in_memory_signer: Arc::new(Mutex::new(in_memory_signer)),
        }
    }
}

impl Clone for CustomSigner {
    fn clone(&self) -> Self {
        Self {
            in_memory_signer: self.in_memory_signer.clone(),
            channel_public_keys: self.channel_public_keys.clone(),
        }
    }
}

impl BaseSign for CustomSigner {
    fn get_per_commitment_point(
        &self,
        idx: u64,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> secp256k1_zkp::PublicKey {
        self.in_memory_signer
            .lock()
            .unwrap()
            .get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
        self.in_memory_signer
            .lock()
            .unwrap()
            .release_commitment_secret(idx)
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction,
        preimages: Vec<lightning::ln::PaymentPreimage>,
    ) -> Result<(), ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .validate_holder_commitment(holder_tx, preimages)
    }

    fn pubkeys(&self) -> &lightning::ln::chan_utils::ChannelPublicKeys {
        &self.channel_public_keys
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.in_memory_signer.lock().unwrap().channel_keys_id()
    }

    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &lightning::ln::chan_utils::CommitmentTransaction,
        preimages: Vec<lightning::ln::PaymentPreimage>,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<
        (
            secp256k1_zkp::ecdsa::Signature,
            Vec<secp256k1_zkp::ecdsa::Signature>,
        ),
        (),
    > {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_counterparty_commitment(commitment_tx, preimages, secp_ctx)
    }

    fn validate_counterparty_revocation(
        &self,
        idx: u64,
        secret: &secp256k1_zkp::SecretKey,
    ) -> Result<(), ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .validate_counterparty_revocation(idx, secret)
    }

    fn sign_holder_commitment_and_htlcs(
        &self,
        commitment_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<
        (
            secp256k1_zkp::ecdsa::Signature,
            Vec<secp256k1_zkp::ecdsa::Signature>,
        ),
        (),
    > {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_holder_commitment_and_htlcs(commitment_tx, secp_ctx)
    }

    fn sign_justice_revoked_output(
        &self,
        justice_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &secp256k1_zkp::SecretKey,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<secp256k1_zkp::ecdsa::Signature, ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_justice_revoked_output(justice_tx, input, amount, per_commitment_key, secp_ctx)
    }

    fn sign_justice_revoked_htlc(
        &self,
        justice_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &secp256k1_zkp::SecretKey,
        htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<secp256k1_zkp::ecdsa::Signature, ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_justice_revoked_htlc(
                justice_tx,
                input,
                amount,
                per_commitment_key,
                htlc,
                secp_ctx,
            )
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        htlc_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &secp256k1_zkp::PublicKey,
        htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<secp256k1_zkp::ecdsa::Signature, ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_counterparty_htlc_transaction(
                htlc_tx,
                input,
                amount,
                per_commitment_point,
                htlc,
                secp_ctx,
            )
    }

    fn sign_closing_transaction(
        &self,
        closing_tx: &lightning::ln::chan_utils::ClosingTransaction,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<secp256k1_zkp::ecdsa::Signature, ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_closing_transaction(closing_tx, secp_ctx)
    }

    fn sign_channel_announcement(
        &self,
        msg: &lightning::ln::msgs::UnsignedChannelAnnouncement,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<
        (
            secp256k1_zkp::ecdsa::Signature,
            secp256k1_zkp::ecdsa::Signature,
        ),
        (),
    > {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_channel_announcement(msg, secp_ctx)
    }

    fn ready_channel(
        &mut self,
        channel_parameters: &lightning::ln::chan_utils::ChannelTransactionParameters,
    ) {
        self.in_memory_signer
            .lock()
            .unwrap()
            .ready_channel(channel_parameters)
    }

    fn sign_holder_anchor_input(
        &self,
        anchor_tx: &Transaction,
        input: usize,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<secp256k1_zkp::ecdsa::Signature, ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_holder_anchor_input(anchor_tx, input, secp_ctx)
    }
}

impl ExtraSign for CustomSigner {
    fn sign_with_fund_key_callback<F>(&self, cb: &mut F)
    where
        F: FnMut(&secp256k1_zkp::SecretKey),
    {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_with_fund_key_callback(cb)
    }

    fn set_channel_value_satoshis(&mut self, value: u64) {
        self.in_memory_signer
            .lock()
            .unwrap()
            .set_channel_value_satoshis(value)
    }
}

impl Writeable for CustomSigner {
    fn write<W: lightning::util::ser::Writer>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.in_memory_signer.lock().unwrap().write(writer)
    }
}

impl Sign for CustomSigner {}

///
pub struct CustomKeysManager {
    keys_manager: KeysManager,
}

///
impl CustomKeysManager {
    ///
    pub fn new(keys_manager: KeysManager) -> Self {
        Self { keys_manager }
    }
}

impl CustomKeysManager {
    #[allow(clippy::result_unit_err)]
    ///
    pub fn spend_spendable_outputs<C: Signing>(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: Script,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<C>,
    ) -> Result<Transaction, ()> {
        self.keys_manager.spend_spendable_outputs(
            descriptors,
            outputs,
            change_destination_script,
            feerate_sat_per_1000_weight,
            secp_ctx,
        )
    }
}

impl KeysInterface for CustomKeysManager {
    type Signer = CustomSigner;

    fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
        self.keys_manager.get_node_secret(recipient)
    }

    fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.keys_manager.get_inbound_payment_key_material()
    }

    fn get_destination_script(&self) -> Script {
        self.keys_manager.get_destination_script()
    }

    fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
        self.keys_manager.get_shutdown_scriptpubkey()
    }

    fn get_channel_signer(&self, inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
        let in_memory = self
            .keys_manager
            .get_channel_signer(inbound, channel_value_satoshis);
        CustomSigner::new(in_memory)
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.keys_manager.get_secure_random_bytes()
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        let in_memory = self.keys_manager.read_chan_signer(reader)?;
        Ok(CustomSigner::new(in_memory))
    }

    fn sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[bitcoin::bech32::u5],
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        self.keys_manager
            .sign_invoice(hrp_bytes, invoice_data, recipient)
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &secp256k1_zkp::PublicKey,
        tweak: Option<&secp256k1_zkp::Scalar>,
    ) -> Result<secp256k1_zkp::ecdh::SharedSecret, ()> {
        self.keys_manager.ecdh(recipient, other_key, tweak)
    }
}
