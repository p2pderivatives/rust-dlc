use std::fmt::{self, Display};

pub use dlc::Error as dlcError;
pub use dlc_manager::error::Error as managerError;
pub use secp256k1_zkp::Error as secpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FromDlcError {
    // #[error("{0}")]
    Dlc(dlcError),
    // #[error("{0}")]
    Secp(#[from] secpError),
    // #[error("{0}")]
    Manager(managerError),
    // #[error("{0}")]
    BitcoinEncoding(#[from] bitcoin::consensus::encode::Error),
    // #[error("{0}")]
    InvalidState(&'static str),
    // #[error("{0}")]
    EncodingError(#[from] std::io::Error),
}

impl Display for FromDlcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            FromDlcError::Dlc(err) => "DLC lib error: ".to_owned() + err.to_string().as_str(),
            FromDlcError::Secp(err) => "Secp lib error: ".to_owned() + err.to_string().as_str(),
            FromDlcError::Manager(err) => {
                "Manager lib error: ".to_owned() + err.to_string().as_str()
            }
            FromDlcError::BitcoinEncoding(err) => {
                "Encoding error: ".to_owned() + err.to_string().as_str()
            }
            FromDlcError::InvalidState(err) => {
                "State error: ".to_owned() + err.to_string().as_str()
            }
            FromDlcError::EncodingError(err) => {
                "Encoding error: ".to_owned() + err.to_string().as_str()
            }
        };

        write!(f, "{}", str)
    }
}

pub type Result<T> = std::result::Result<T, FromDlcError>;
