extern crate dlc_manager;

use dlc_manager::contract::{
    offered_contract::OfferedContract, signed_contract::SignedContract, Contract,
};
use dlc_manager::Storage;
use dlc_manager::{error::Error as DaemonError, ContractId};
use std::collections::HashMap;
use std::sync::RwLock;

pub struct MemoryStorage {
    contracts: RwLock<HashMap<ContractId, Contract>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        MemoryStorage {
            contracts: RwLock::new(HashMap::new()),
        }
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
}
