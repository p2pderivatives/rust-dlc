use std::fmt::{self, Display};

pub use dlc::Error as dlcError;
pub use dlc_manager::error::Error as managerError;
pub use secp256k1_zkp::Error as secpError;

#[derive(Debug)]
pub enum FromDlcError {
    // #[error("{0}")]
    Dlc(dlcError),
    // #[error("{0}")]
    Secp(secpError),
    // #[error("{0}")]
    Manager(managerError),
    // #[error("{0}")]
    BitcoinEncoding(bitcoin::consensus::encode::Error),
    // #[error("{0}")]
    InvalidState(String),
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
        };

        write!(f, "{}", str)
    }
}

pub type Result<T> = std::result::Result<T, FromDlcError>;
