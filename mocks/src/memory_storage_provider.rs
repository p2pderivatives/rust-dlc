use bitcoin::{Address, OutPoint, Txid};
use dlc_manager::chain_monitor::ChainMonitor;
use dlc_manager::channel::{
    offered_channel::OfferedChannel,
    signed_channel::{SignedChannel, SignedChannelStateType},
    Channel,
};
use dlc_manager::contract::{
    offered_contract::OfferedContract, signed_contract::SignedContract, Contract, PreClosedContract,
};
use dlc_manager::sub_channel_manager::Action;
use dlc_manager::subchannel::{SubChannel, SubChannelState};
use dlc_manager::Storage;
use dlc_manager::{error::Error as DaemonError, ChannelId, ContractId, Utxo};
use secp256k1_zkp::{PublicKey, SecretKey};
use simple_wallet::WalletStorage;
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

pub struct MemoryStorage {
    contracts: RwLock<HashMap<ContractId, Contract>>,
    channels: RwLock<HashMap<ChannelId, Channel>>,
    sub_channels: RwLock<HashMap<ChannelId, SubChannel>>,
    contracts_saved: Mutex<Option<HashMap<ContractId, Contract>>>,
    channels_saved: Mutex<Option<HashMap<ChannelId, Channel>>>,
    sub_channels_saved: Mutex<Option<HashMap<ChannelId, SubChannel>>>,
    addresses: RwLock<HashMap<Address, SecretKey>>,
    utxos: RwLock<HashMap<OutPoint, Utxo>>,
    key_pairs: RwLock<HashMap<PublicKey, SecretKey>>,
    actions: RwLock<Vec<Action>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        MemoryStorage {
            contracts: RwLock::new(HashMap::new()),
            channels: RwLock::new(HashMap::new()),
            sub_channels: RwLock::new(HashMap::new()),
            contracts_saved: Mutex::new(None),
            channels_saved: Mutex::new(None),
            sub_channels_saved: Mutex::new(None),
            addresses: RwLock::new(HashMap::new()),
            utxos: RwLock::new(HashMap::new()),
            key_pairs: RwLock::new(HashMap::new()),
            actions: RwLock::new(Vec::new()),
        }
    }

    pub fn save(&self) {
        let mut contracts_saved = self.contracts_saved.lock().unwrap();

        *contracts_saved = Some(
            self.contracts
                .read()
                .expect("Could not get read lock")
                .clone(),
        );
        let mut channels_saved = self.channels_saved.lock().unwrap();
        *channels_saved = Some(
            self.channels
                .read()
                .expect("Could not get read lock")
                .clone(),
        );

        let mut sub_channels_saved = self.sub_channels_saved.lock().unwrap();
        *sub_channels_saved = Some(
            self.sub_channels
                .read()
                .expect("Could not get read lock")
                .clone(),
        );
    }

    pub fn rollback(&self) {
        let mut contracts = self.contracts.write().unwrap();
        let mut contracts_saved = self.contracts_saved.lock().unwrap();
        let mut tmp = None;
        std::mem::swap(&mut tmp, &mut *contracts_saved);
        std::mem::swap(&mut *contracts, &mut tmp.unwrap());

        let mut channels = self.channels.write().unwrap();
        let mut channels_saved = self.channels_saved.lock().unwrap();
        let mut tmp = None;
        std::mem::swap(&mut tmp, &mut *channels_saved);
        std::mem::swap(&mut *channels, &mut tmp.unwrap());

        let mut sub_channels = self.sub_channels.write().unwrap();
        let mut sub_channels_saved = self.sub_channels_saved.lock().unwrap();
        let mut tmp = None;
        std::mem::swap(&mut tmp, &mut *sub_channels_saved);
        std::mem::swap(&mut *sub_channels, &mut tmp.unwrap());
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for MemoryStorage {
    fn get_contract(&self, id: &ContractId) -> Result<Option<Contract>, DaemonError> {
        let map = self.contracts.read().expect("Could not get read lock");
        Ok(map.get(id).cloned())
    }

    fn get_contracts(&self) -> Result<Vec<Contract>, DaemonError> {
        Ok(self
            .contracts
            .read()
            .expect("Could not get read lock")
            .values()
            .cloned()
            .collect())
    }

    fn create_contract(&self, contract: &OfferedContract) -> Result<(), DaemonError> {
        let mut map = self.contracts.write().expect("Could not get write lock");
        let res = map.insert(contract.id, Contract::Offered(contract.clone()));
        match res {
            None => Ok(()),
            Some(_) => Err(DaemonError::StorageError(
                "Contract already exists".to_string(),
            )),
        }
    }

    fn delete_contract(&self, id: &ContractId) -> Result<(), DaemonError> {
        let mut map = self.contracts.write().expect("Could not get write lock");
        map.remove(id);
        Ok(())
    }

    fn update_contract(&self, contract: &Contract) -> Result<(), DaemonError> {
        let mut map = self.contracts.write().expect("Could not get write lock");
        match contract {
            a @ Contract::Accepted(_) | a @ Contract::Signed(_) => {
                map.remove(&a.get_temporary_id());
            }
            _ => {}
        };
        map.insert(contract.get_id(), contract.clone());
        Ok(())
    }

    fn get_signed_contracts(&self) -> Result<Vec<SignedContract>, DaemonError> {
        let map = self.contracts.read().expect("Could not get read lock");

        let mut res: Vec<SignedContract> = Vec::new();

        for (_, val) in map.iter() {
            if let Contract::Signed(c) = val {
                res.push(c.clone());
            }
        }

        Ok(res)
    }

    fn get_confirmed_contracts(&self) -> Result<Vec<SignedContract>, DaemonError> {
        let map = self.contracts.read().expect("Could not get read lock");

        let mut res: Vec<SignedContract> = Vec::new();

        for (_, val) in map.iter() {
            if let Contract::Confirmed(c) = val {
                res.push(c.clone());
            }
        }

        Ok(res)
    }

    fn get_contract_offers(&self) -> Result<Vec<OfferedContract>, DaemonError> {
        let map = self.contracts.read().expect("Could not get read lock");

        let mut res: Vec<OfferedContract> = Vec::new();

        for (_, val) in map.iter() {
            if let Contract::Offered(c) = val {
                res.push(c.clone());
            }
        }

        Ok(res)
    }

    fn get_preclosed_contracts(&self) -> Result<Vec<PreClosedContract>, DaemonError> {
        let map = self.contracts.read().expect("Could not get read lock");

        let mut res: Vec<PreClosedContract> = Vec::new();

        for (_, val) in map.iter() {
            if let Contract::PreClosed(c) = val {
                res.push(c.clone());
            }
        }
        Ok(res)
    }
    fn upsert_channel(
        &self,
        channel: Channel,
        contract: Option<Contract>,
    ) -> Result<(), DaemonError> {
        {
            let mut map = self.channels.write().expect("Could not get write lock");
            match &channel {
                a @ Channel::Accepted(_) | a @ Channel::Signed(_) => {
                    map.remove(&a.get_temporary_id());
                }
                _ => {}
            };
            map.insert(channel.get_id(), channel);
        }
        if let Some(c) = contract {
            self.update_contract(&c)?;
        }
        Ok(())
    }

    fn delete_channel(&self, channel_id: &ChannelId) -> Result<(), DaemonError> {
        let mut map = self.channels.write().expect("Could not get write lock");
        map.remove(channel_id);
        Ok(())
    }

    fn get_channel(&self, channel_id: &ChannelId) -> Result<Option<Channel>, DaemonError> {
        let map = self.channels.read().expect("could not get read lock");
        Ok(map.get(channel_id).cloned())
    }

    fn get_signed_channels(
        &self,
        channel_state: Option<SignedChannelStateType>,
    ) -> Result<Vec<SignedChannel>, DaemonError> {
        let map = self.channels.read().expect("Could not get read lock");

        let mut res: Vec<SignedChannel> = Vec::new();

        for (_, val) in map.iter() {
            if let Channel::Signed(c) = val {
                match channel_state {
                    Some(ref state) => {
                        if c.state.is_of_type(state) {
                            res.push(c.clone())
                        }
                    }
                    None => res.push(c.clone()),
                };
            }
        }

        Ok(res)
    }

    fn get_offered_channels(&self) -> Result<Vec<OfferedChannel>, DaemonError> {
        let map = self.channels.read().expect("Could not get read lock");

        let mut res: Vec<OfferedChannel> = Vec::new();

        for (_, val) in map.iter() {
            if let Channel::Offered(c) = val {
                res.push(c.clone())
            }
        }

        Ok(res)
    }

    fn persist_chain_monitor(&self, _: &ChainMonitor) -> Result<(), DaemonError> {
        // No need to persist for mocks
        Ok(())
    }

    fn get_chain_monitor(&self) -> Result<Option<ChainMonitor>, DaemonError> {
        Ok(None)
    }

    fn upsert_sub_channel(&self, subchannel: &SubChannel) -> Result<(), DaemonError> {
        let mut map = self.sub_channels.write().expect("Could not get write lock");
        map.insert(subchannel.channel_id, subchannel.clone());
        Ok(())
    }

    fn get_sub_channel(
        &self,
        channel_id: dlc_manager::ChannelId,
    ) -> Result<Option<SubChannel>, DaemonError> {
        let res = self
            .sub_channels
            .read()
            .expect("could not get read lock")
            .get(&channel_id)
            .cloned();
        Ok(res)
    }

    fn get_sub_channels(&self) -> Result<Vec<SubChannel>, DaemonError> {
        Ok(self
            .sub_channels
            .read()
            .expect("Could not get read lock")
            .values()
            .cloned()
            .collect())
    }

    fn get_offered_sub_channels(&self) -> Result<Vec<SubChannel>, DaemonError> {
        let map = self.sub_channels.read().expect("Could not get read lock");

        let mut res: Vec<SubChannel> = Vec::new();

        for (_, val) in map.iter() {
            if let SubChannelState::Offered(_) = &val.state {
                res.push(val.clone())
            }
        }

        Ok(res)
    }

    fn save_sub_channel_actions(&self, actions: &[Action]) -> Result<(), DaemonError> {
        let mut vec = self.actions.write().expect("Could not get write lock");
        vec.append(&mut actions.to_vec());
        Ok(())
    }

    fn get_sub_channel_actions(&self) -> Result<Vec<Action>, DaemonError> {
        Ok(self
            .actions
            .read()
            .expect("Could not get read lock")
            .clone())
    }
}

impl WalletStorage for MemoryStorage {
    fn upsert_address(
        &self,
        address: &Address,
        privkey: &secp256k1_zkp::SecretKey,
    ) -> Result<(), DaemonError> {
        self.addresses
            .write()
            .expect("Could not get write lock")
            .insert(address.clone(), *privkey);
        Ok(())
    }

    fn delete_address(&self, address: &Address) -> Result<(), DaemonError> {
        self.addresses
            .write()
            .expect("Could not get write lock")
            .remove(address);
        Ok(())
    }

    fn get_addresses(&self) -> Result<Vec<Address>, DaemonError> {
        Ok(self
            .addresses
            .read()
            .expect("Could not get read lock")
            .keys()
            .cloned()
            .collect())
    }

    fn get_priv_key_for_address(
        &self,
        address: &Address,
    ) -> Result<Option<secp256k1_zkp::SecretKey>, DaemonError> {
        Ok(self
            .addresses
            .read()
            .expect("Could not get read lock")
            .get(address)
            .cloned())
    }

    fn upsert_key_pair(
        &self,
        public_key: &secp256k1_zkp::PublicKey,
        privkey: &secp256k1_zkp::SecretKey,
    ) -> Result<(), DaemonError> {
        self.key_pairs
            .write()
            .expect("Could not get write lock")
            .insert(*public_key, *privkey);

        Ok(())
    }

    fn get_priv_key_for_pubkey(
        &self,
        public_key: &secp256k1_zkp::PublicKey,
    ) -> Result<Option<secp256k1_zkp::SecretKey>, DaemonError> {
        Ok(self
            .key_pairs
            .read()
            .expect("Could not get read lock")
            .get(public_key)
            .cloned())
    }

    fn upsert_utxo(&self, utxo: &Utxo) -> Result<(), DaemonError> {
        self.utxos
            .write()
            .expect("Could not get write lock")
            .insert(utxo.outpoint, utxo.clone());
        Ok(())
    }

    fn has_utxo(&self, utxo: &Utxo) -> Result<bool, DaemonError> {
        Ok(self
            .utxos
            .read()
            .expect("Could not get read lock")
            .contains_key(&utxo.outpoint))
    }

    fn delete_utxo(&self, utxo: &Utxo) -> Result<(), DaemonError> {
        self.utxos
            .write()
            .expect("Could not get write lock")
            .remove(&utxo.outpoint);
        Ok(())
    }

    fn get_utxos(&self) -> Result<Vec<Utxo>, DaemonError> {
        Ok(self
            .utxos
            .read()
            .expect("Could not get read lock")
            .values()
            .cloned()
            .collect())
    }

    fn unreserve_utxo(&self, txid: &Txid, vout: u32) -> Result<(), DaemonError> {
        let outpoint = OutPoint { txid: *txid, vout };
        self.utxos
            .write()
            .expect("Could not get write lock")
            .get_mut(&outpoint)
            .expect("Could not get value")
            .reserved = false;
        Ok(())
    }
}
