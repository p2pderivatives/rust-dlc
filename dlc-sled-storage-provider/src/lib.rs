//! # dlc-sled-storage-provider
//! Storage provider for dlc-manager using sled as underlying storage.

#![crate_name = "dlc_sled_storage_provider"]
// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

extern crate dlc_manager;
extern crate sled;

#[cfg(feature = "wallet")]
use bitcoin::{address::NetworkUnchecked, Address, Txid};
use dlc_manager::contract::accepted_contract::AcceptedContract;
use dlc_manager::contract::offered_contract::OfferedContract;
use dlc_manager::contract::ser::Serializable;
use dlc_manager::contract::signed_contract::SignedContract;
use dlc_manager::contract::{
    ClosedContract, Contract, FailedAcceptContract, FailedSignContract, PreClosedContract,
};
#[cfg(feature = "wallet")]
use dlc_manager::Utxo;
use dlc_manager::{error::Error, ContractId, Storage};
use lightning::io::{Cursor, Read};
#[cfg(feature = "wallet")]
use lightning::util::ser::{Readable, Writeable};
#[cfg(feature = "wallet")]
use secp256k1_zkp::SecretKey;
#[cfg(feature = "wallet")]
use simple_wallet::WalletStorage;
use sled::transaction::UnabortableTransactionError;
use sled::{Db, Tree};
use std::convert::TryInto;

const CONTRACT_TREE: u8 = 1;
#[cfg(feature = "wallet")]
const UTXO_TREE: u8 = 6;
#[cfg(feature = "wallet")]
const KEY_PAIR_TREE: u8 = 7;
#[cfg(feature = "wallet")]
const ADDRESS_TREE: u8 = 8;

/// Implementation of Storage interface using the sled DB backend.
pub struct SledStorageProvider {
    db: Db,
}

macro_rules! convertible_enum {
    (enum $name:ident {
        $($vname:ident $(= $val:expr)?,)*;
        $($tname:ident $(= $tval:expr)?,)*
    }, $input:ident) => {
        #[derive(Debug)]
        enum $name {
            $($vname $(= $val)?,)*
            $($tname $(= $tval)?,)*
        }

        impl From<$name> for u8 {
            fn from(prefix: $name) -> u8 {
                prefix as u8
            }
        }

        impl std::convert::TryFrom<u8> for $name {
            type Error = Error;

            fn try_from(v: u8) -> Result<Self, Self::Error> {
                match v {
                    $(x if x == u8::from($name::$vname) => Ok($name::$vname),)*
                    $(x if x == u8::from($name::$tname) => Ok($name::$tname),)*
                    _ => Err(Error::StorageError("Unknown prefix".to_string())),
                }
            }
        }

        impl $name {
            fn get_prefix(input: &$input) -> u8 {
                let prefix = match input {
                    $($input::$vname(_) => $name::$vname,)*
                    $($input::$tname{..} => $name::$tname,)*
                };
                prefix.into()
            }
        }
    }
}

convertible_enum!(
    enum ContractPrefix {
        Offered = 1,
        Accepted,
        Signed,
        Confirmed,
        PreClosed,
        Closed,
        FailedAccept,
        FailedSign,
        Refunded,
        Rejected,;
    },
    Contract
);

fn to_storage_error<T>(e: T) -> Error
where
    T: std::fmt::Display,
{
    Error::StorageError(e.to_string())
}

impl SledStorageProvider {
    /// Creates a new instance of a SledStorageProvider.
    pub fn new(path: &str) -> Result<Self, sled::Error> {
        Ok(SledStorageProvider {
            db: sled::open(path)?,
        })
    }

    fn get_data_with_prefix<T: Serializable>(
        &self,
        tree: &Tree,
        prefix: &[u8],
        consume: Option<u64>,
    ) -> Result<Vec<T>, Error> {
        let iter = tree.iter();
        iter.values()
            .filter_map(|res| {
                let value = res.unwrap();
                let mut cursor = Cursor::new(&value);
                let mut pref = vec![0u8; prefix.len()];
                cursor.read_exact(&mut pref).expect("Error reading prefix");
                if pref == prefix {
                    if let Some(c) = consume {
                        cursor.set_position(cursor.position() + c);
                    }
                    Some(Ok(T::deserialize(&mut cursor).ok()?))
                } else {
                    None
                }
            })
            .collect()
    }

    fn open_tree(&self, tree_id: &[u8; 1]) -> Result<Tree, Error> {
        self.db
            .open_tree(tree_id)
            .map_err(|e| Error::StorageError(format!("Error opening contract tree: {}", e)))
    }

    fn contract_tree(&self) -> Result<Tree, Error> {
        self.open_tree(&[CONTRACT_TREE])
    }
}

#[cfg(feature = "wallet")]
impl SledStorageProvider {
    fn utxo_tree(&self) -> Result<Tree, Error> {
        self.open_tree(&[UTXO_TREE])
    }

    fn address_tree(&self) -> Result<Tree, Error> {
        self.open_tree(&[ADDRESS_TREE])
    }

    fn key_pair_tree(&self) -> Result<Tree, Error> {
        self.open_tree(&[KEY_PAIR_TREE])
    }
}

impl Storage for SledStorageProvider {
    fn get_contract(&self, contract_id: &ContractId) -> Result<Option<Contract>, Error> {
        match self
            .contract_tree()?
            .get(contract_id)
            .map_err(to_storage_error)?
        {
            Some(res) => Ok(Some(deserialize_contract(&res)?)),
            None => Ok(None),
        }
    }

    fn get_contracts(&self) -> Result<Vec<Contract>, Error> {
        self.contract_tree()?
            .iter()
            .values()
            .map(|x| deserialize_contract(&x.unwrap()))
            .collect::<Result<Vec<Contract>, Error>>()
    }

    fn create_contract(&self, contract: &OfferedContract) -> Result<(), Error> {
        let serialized = serialize_contract(&Contract::Offered(contract.clone()))?;
        self.contract_tree()?
            .insert(contract.id, serialized)
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn delete_contract(&self, contract_id: &ContractId) -> Result<(), Error> {
        self.contract_tree()?
            .remove(contract_id)
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn update_contract(&self, contract: &Contract) -> Result<(), Error> {
        let serialized = serialize_contract(contract)?;
        self.contract_tree()?
            .transaction::<_, _, UnabortableTransactionError>(|db| {
                match contract {
                    a @ Contract::Accepted(_) | a @ Contract::Signed(_) => {
                        db.remove(&a.get_temporary_id())?;
                    }
                    _ => {}
                };

                db.insert(&contract.get_id(), serialized.clone())?;
                Ok(())
            })
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn get_signed_contracts(&self) -> Result<Vec<SignedContract>, Error> {
        self.get_data_with_prefix(
            &self.contract_tree()?,
            &[ContractPrefix::Signed.into()],
            None,
        )
    }

    fn get_confirmed_contracts(&self) -> Result<Vec<SignedContract>, Error> {
        self.get_data_with_prefix(
            &self.contract_tree()?,
            &[ContractPrefix::Confirmed.into()],
            None,
        )
    }

    fn get_contract_offers(&self) -> Result<Vec<OfferedContract>, Error> {
        self.get_data_with_prefix(
            &self.contract_tree()?,
            &[ContractPrefix::Offered.into()],
            None,
        )
    }

    fn get_preclosed_contracts(&self) -> Result<Vec<PreClosedContract>, Error> {
        self.get_data_with_prefix(
            &self.contract_tree()?,
            &[ContractPrefix::PreClosed.into()],
            None,
        )
    }
}

#[cfg(feature = "wallet")]
impl WalletStorage for SledStorageProvider {
    fn upsert_address(&self, address: &Address, privkey: &SecretKey) -> Result<(), Error> {
        let db = self.address_tree()?;
        let key = get_address_key(address);
        db.insert(key, &privkey.secret_bytes())
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn delete_address(&self, address: &Address) -> Result<(), Error> {
        let db = self.address_tree()?;
        let key = get_address_key(address);
        db.remove(key).map_err(to_storage_error)?;
        Ok(())
    }

    fn get_addresses(&self) -> Result<Vec<Address>, Error> {
        self.address_tree()?
            .iter()
            .keys()
            .map(|x| {
                Ok(String::from_utf8(x.map_err(to_storage_error)?.to_vec())
                    .map_err(|e| Error::InvalidState(format!("Could not read address key {}", e)))?
                    .parse::<Address<NetworkUnchecked>>()
                    .expect("to have a valid address as key")
                    .assume_checked())
            })
            .collect::<Result<Vec<Address>, Error>>()
    }

    fn get_priv_key_for_address(&self, address: &Address) -> Result<Option<SecretKey>, Error> {
        let db = self.address_tree()?;
        let key = get_address_key(address);
        let raw_key = match db.get(key).map_err(to_storage_error)? {
            Some(res) => res,
            None => return Ok(None),
        };

        Ok(Some(
            SecretKey::from_slice(&raw_key).expect("a valid secret key"),
        ))
    }

    fn upsert_key(&self, identifier: &[u8], privkey: &SecretKey) -> Result<(), Error> {
        self.key_pair_tree()?
            .insert(identifier, &privkey.secret_bytes())
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn get_priv_key(&self, identifier: &[u8]) -> Result<Option<SecretKey>, Error> {
        let db = self.key_pair_tree()?;
        let raw_key = match db.get(identifier).map_err(to_storage_error)? {
            Some(res) => res,
            None => return Ok(None),
        };

        Ok(Some(
            SecretKey::from_slice(&raw_key).expect("a valid secret key"),
        ))
    }

    fn upsert_utxo(&self, utxo: &Utxo) -> Result<(), Error> {
        let key = get_utxo_key(&utxo.outpoint.txid, utxo.outpoint.vout);
        let db = self.utxo_tree()?;
        let mut buf = Vec::new();
        utxo.write(&mut buf)?;
        db.insert(key, buf).map_err(to_storage_error)?;
        Ok(())
    }

    fn has_utxo(&self, utxo: &Utxo) -> Result<bool, Error> {
        let key = get_utxo_key(&utxo.outpoint.txid, utxo.outpoint.vout);
        self.utxo_tree()?
            .contains_key(key)
            .map_err(to_storage_error)
    }

    fn delete_utxo(&self, utxo: &Utxo) -> Result<(), Error> {
        let key = get_utxo_key(&utxo.outpoint.txid, utxo.outpoint.vout);
        self.utxo_tree()?.remove(key).map_err(to_storage_error)?;
        Ok(())
    }

    fn get_utxos(&self) -> Result<Vec<Utxo>, Error> {
        self.utxo_tree()?
            .iter()
            .values()
            .map(|x| {
                let ivec = x.map_err(to_storage_error)?;
                let mut cursor = Cursor::new(&ivec);
                let res =
                    Utxo::read(&mut cursor).map_err(|x| Error::InvalidState(format!("{}", x)))?;
                Ok(res)
            })
            .collect::<Result<Vec<Utxo>, Error>>()
    }

    fn unreserve_utxo(&self, txid: &Txid, vout: u32) -> Result<(), Error> {
        let utxo_tree = self.utxo_tree()?;
        let key = get_utxo_key(txid, vout);
        let mut utxo = match utxo_tree.get(&key).map_err(to_storage_error)? {
            Some(res) => Utxo::read(&mut Cursor::new(&res))
                .map_err(|_| Error::InvalidState("Could not read UTXO".to_string()))?,
            None => {
                return Err(Error::InvalidState(format!(
                    "No utxo for {} {}",
                    txid, vout
                )))
            }
        };

        utxo.reserved = false;
        let mut buf = Vec::new();
        utxo.write(&mut buf)?;
        utxo_tree.insert(key, buf).map_err(to_storage_error)?;
        Ok(())
    }
}

fn serialize_contract(contract: &Contract) -> Result<Vec<u8>, lightning::io::Error> {
    let serialized = match contract {
        Contract::Offered(o) | Contract::Rejected(o) => o.serialize(),
        Contract::Accepted(o) => o.serialize(),
        Contract::Signed(o) | Contract::Confirmed(o) | Contract::Refunded(o) => o.serialize(),
        Contract::FailedAccept(c) => c.serialize(),
        Contract::FailedSign(c) => c.serialize(),
        Contract::PreClosed(c) => c.serialize(),
        Contract::Closed(c) => c.serialize(),
    };
    let mut serialized = serialized?;
    let mut res = Vec::with_capacity(serialized.len() + 1);
    res.push(ContractPrefix::get_prefix(contract));
    res.append(&mut serialized);
    Ok(res)
}

fn deserialize_contract(buff: &sled::IVec) -> Result<Contract, Error> {
    let mut cursor = lightning::io::Cursor::new(buff);
    let mut prefix = [0u8; 1];
    cursor.read_exact(&mut prefix)?;
    let contract_prefix: ContractPrefix = prefix[0].try_into()?;
    let contract = match contract_prefix {
        ContractPrefix::Offered => {
            Contract::Offered(OfferedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::Accepted => Contract::Accepted(
            AcceptedContract::deserialize(&mut cursor).map_err(to_storage_error)?,
        ),
        ContractPrefix::Signed => {
            Contract::Signed(SignedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::Confirmed => {
            Contract::Confirmed(SignedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::PreClosed => Contract::PreClosed(
            PreClosedContract::deserialize(&mut cursor).map_err(to_storage_error)?,
        ),
        ContractPrefix::Closed => {
            Contract::Closed(ClosedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::FailedAccept => Contract::FailedAccept(
            FailedAcceptContract::deserialize(&mut cursor).map_err(to_storage_error)?,
        ),
        ContractPrefix::FailedSign => Contract::FailedSign(
            FailedSignContract::deserialize(&mut cursor).map_err(to_storage_error)?,
        ),
        ContractPrefix::Refunded => {
            Contract::Refunded(SignedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::Rejected => {
            Contract::Rejected(OfferedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
    };
    Ok(contract)
}

#[cfg(feature = "wallet")]
fn get_address_key(address: &Address) -> Vec<u8> {
    address.to_string().into_bytes()
}

#[cfg(feature = "wallet")]
fn get_utxo_key(txid: &Txid, vout: u32) -> Vec<u8> {
    use bitcoin::hashes::Hash;

    let mut key = txid.to_byte_array().to_vec();
    key.extend_from_slice(&vout.to_be_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! sled_test {
        ($name: ident, $body: expr) => {
            #[test]
            fn $name() {
                let path = format!("{}{}", "test_files/sleddb/", std::stringify!($name));
                {
                    let storage = SledStorageProvider::new(&path).expect("Error opening sled DB");
                    #[allow(clippy::redundant_closure_call)]
                    $body(storage);
                }
                std::fs::remove_dir_all(path).unwrap();
            }
        };
    }

    fn deserialize_object<T>(serialized: &[u8]) -> T
    where
        T: Serializable,
    {
        let mut cursor = lightning::io::Cursor::new(serialized);
        T::deserialize(&mut cursor).unwrap()
    }

    sled_test!(
        create_contract_can_be_retrieved,
        |storage: SledStorageProvider| {
            let serialized = include_bytes!("../test_files/Offered");
            let contract = deserialize_object(serialized);

            storage
                .create_contract(&contract)
                .expect("Error creating contract");

            let retrieved = storage
                .get_contract(&contract.id)
                .expect("Error retrieving contract.");

            if let Some(Contract::Offered(retrieved_offer)) = retrieved {
                assert_eq!(serialized[..], retrieved_offer.serialize().unwrap()[..]);
            } else {
                unreachable!();
            }
        }
    );

    sled_test!(
        update_contract_is_updated,
        |storage: SledStorageProvider| {
            let serialized = include_bytes!("../test_files/Offered");
            let offered_contract = deserialize_object(serialized);
            let serialized = include_bytes!("../test_files/Accepted");
            let accepted_contract = deserialize_object(serialized);
            let accepted_contract = Contract::Accepted(accepted_contract);

            storage
                .create_contract(&offered_contract)
                .expect("Error creating contract");

            storage
                .update_contract(&accepted_contract)
                .expect("Error updating contract.");
            let retrieved = storage
                .get_contract(&accepted_contract.get_id())
                .expect("Error retrieving contract.");

            if let Some(Contract::Accepted(_)) = retrieved {
            } else {
                unreachable!();
            }
        }
    );

    sled_test!(
        delete_contract_is_deleted,
        |storage: SledStorageProvider| {
            let serialized = include_bytes!("../test_files/Offered");
            let contract = deserialize_object(serialized);
            storage
                .create_contract(&contract)
                .expect("Error creating contract");

            storage
                .delete_contract(&contract.id)
                .expect("Error deleting contract");

            assert!(storage
                .get_contract(&contract.id)
                .expect("Error querying contract")
                .is_none());
        }
    );

    fn insert_offered_signed_and_confirmed(storage: &mut SledStorageProvider) {
        let serialized = include_bytes!("../test_files/Offered");
        let offered_contract = deserialize_object(serialized);
        storage
            .create_contract(&offered_contract)
            .expect("Error creating contract");

        let serialized = include_bytes!("../test_files/Signed");
        let signed_contract = Contract::Signed(deserialize_object(serialized));
        storage
            .update_contract(&signed_contract)
            .expect("Error creating contract");
        let serialized = include_bytes!("../test_files/Signed1");
        let signed_contract = Contract::Signed(deserialize_object(serialized));
        storage
            .update_contract(&signed_contract)
            .expect("Error creating contract");

        let serialized = include_bytes!("../test_files/Confirmed");
        let confirmed_contract = Contract::Confirmed(deserialize_object(serialized));
        storage
            .update_contract(&confirmed_contract)
            .expect("Error creating contract");
        let serialized = include_bytes!("../test_files/Confirmed1");
        let confirmed_contract = Contract::Confirmed(deserialize_object(serialized));
        storage
            .update_contract(&confirmed_contract)
            .expect("Error creating contract");

        let serialized = include_bytes!("../test_files/PreClosed");
        let preclosed_contract = Contract::PreClosed(deserialize_object(serialized));
        storage
            .update_contract(&preclosed_contract)
            .expect("Error creating contract");
    }

    sled_test!(
        get_confirmed_contracts_only_confirmed,
        |mut storage: SledStorageProvider| {
            insert_offered_signed_and_confirmed(&mut storage);

            let confirmed_contracts = storage
                .get_confirmed_contracts()
                .expect("Error retrieving signed contracts");

            assert_eq!(2, confirmed_contracts.len());
        }
    );

    sled_test!(
        get_offered_contracts_only_offered,
        |mut storage: SledStorageProvider| {
            insert_offered_signed_and_confirmed(&mut storage);

            let offered_contracts = storage
                .get_contract_offers()
                .expect("Error retrieving signed contracts");

            assert_eq!(1, offered_contracts.len());
        }
    );

    sled_test!(
        get_preclosed_contracts_only_preclosed,
        |mut storage: SledStorageProvider| {
            insert_offered_signed_and_confirmed(&mut storage);

            let preclosed_contracts = storage
                .get_preclosed_contracts()
                .expect("Error retrieving preclosed contracts");

            assert_eq!(1, preclosed_contracts.len());
        }
    );
    sled_test!(
        get_contracts_all_returned,
        |mut storage: SledStorageProvider| {
            insert_offered_signed_and_confirmed(&mut storage);

            let contracts = storage.get_contracts().expect("Error retrieving contracts");

            assert_eq!(6, contracts.len());
        }
    );
}
