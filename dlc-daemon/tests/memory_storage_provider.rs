extern crate dlc_daemon;

use dlc_daemon::contract::{Contract, OfferedContract, SignedContract};
use dlc_daemon::daemon::{ContractId, DlcStorage, Error as DaemonError};
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

impl DlcStorage for MemoryStorage {
    fn get_contract(&self, id: &ContractId) -> Result<Contract, DaemonError> {
        let map = self.contracts.read().expect("Could not get read lock");
        let c = map.get(id).ok_or(DaemonError::StorageError)?;
        println!("{:?}", c);
        Ok(c.clone())
    }

    fn create_contract(&mut self, contract: &OfferedContract) -> Result<(), DaemonError> {
        let mut map = self.contracts.write().expect("Could not get write lock");
        let res = map.insert(contract.id, Contract::Offered(contract.clone()));
        match res {
            None => Ok(()),
            Some(_) => Err(DaemonError::StorageError),
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
            println!("{:?}", val);
            match val {
                Contract::Signed(c) => res.push(c.clone()),
                _ => {}
            };
        }

        Ok(res)
    }

    fn get_confirmed_contracts(&self) -> Result<Vec<SignedContract>, DaemonError> {
        let map = self.contracts.read().expect("Could not get read lock");

        let mut res: Vec<SignedContract> = Vec::new();

        for (_, val) in map.iter() {
            match val {
                Contract::Confirmed(c) => {
                    res.push(c.clone());
                }
                _ => {}
            };
        }

        Ok(res)
    }
}
