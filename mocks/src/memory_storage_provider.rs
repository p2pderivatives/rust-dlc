use dlc_manager::chain_monitor::ChainMonitor;
use dlc_manager::channel::{
    offered_channel::OfferedChannel,
    signed_channel::{SignedChannel, SignedChannelStateType},
    Channel,
};
use dlc_manager::contract::{
    offered_contract::OfferedContract, signed_contract::SignedContract, Contract,
};
use dlc_manager::Storage;
use dlc_manager::{error::Error as DaemonError, ChannelId, ContractId};
use std::collections::HashMap;
use std::sync::RwLock;

pub struct MemoryStorage {
    contracts: RwLock<HashMap<ContractId, Contract>>,
    channels: RwLock<HashMap<ChannelId, Channel>>,
    contracts_saved: Option<HashMap<ContractId, Contract>>,
    channels_saved: Option<HashMap<ChannelId, Channel>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        MemoryStorage {
            contracts: RwLock::new(HashMap::new()),
            channels: RwLock::new(HashMap::new()),
            contracts_saved: None,
            channels_saved: None,
        }
    }

    pub fn save(&mut self) {
        self.contracts_saved = Some(
            self.contracts
                .read()
                .expect("Could not get read lock")
                .clone(),
        );
        self.channels_saved = Some(
            self.channels
                .read()
                .expect("Could not get read lock")
                .clone(),
        );
    }

    pub fn rollback(&mut self) {
        self.contracts = RwLock::new(std::mem::replace(&mut self.contracts_saved, None).unwrap());
        self.channels = RwLock::new(std::mem::replace(&mut self.channels_saved, None).unwrap());
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

    fn create_contract(&mut self, contract: &OfferedContract) -> Result<(), DaemonError> {
        let mut map = self.contracts.write().expect("Could not get write lock");
        let res = map.insert(contract.id, Contract::Offered(contract.clone()));
        match res {
            None => Ok(()),
            Some(_) => Err(DaemonError::StorageError(
                "Contract already exists".to_string(),
            )),
        }
    }

    fn delete_contract(&mut self, id: &ContractId) -> Result<(), DaemonError> {
        let mut map = self.contracts.write().expect("Could not get write lock");
        map.remove(id);
        Ok(())
    }

    fn update_contract(&mut self, contract: &Contract) -> Result<(), DaemonError> {
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

    fn upsert_channel(
        &mut self,
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
            map.insert(channel.get_id(), channel.clone());
        }
        if let Some(c) = contract {
            self.update_contract(&c)?;
        }
        Ok(())
    }

    fn delete_channel(&mut self, channel_id: &ChannelId) -> Result<(), DaemonError> {
        let mut map = self.channels.write().expect("Could not get write lock");
        map.remove(channel_id);
        Ok(())
    }

    fn get_channel(&self, channel_id: &ChannelId) -> Result<Option<Channel>, DaemonError> {
        let map = self.channels.read().expect("Could not get read lock");
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

    fn persist_chain_monitor(&mut self, _: &ChainMonitor) -> Result<(), DaemonError> {
        // No need to persist for mocks
        Ok(())
    }

    fn get_chain_monitor(&self) -> Result<Option<ChainMonitor>, DaemonError> {
        Ok(None)
    }
}
