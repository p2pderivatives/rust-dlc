//! #Error
use std::fmt;

/// An error code.
#[derive(Debug)]
pub enum Error {
    /// Error that occured while converting from DLC message to internal
    /// representation.
    Conversion(crate::conversion_utils::Error),
    /// An IO error.
    IOError(std::io::Error),
    /// Some invalid parameters were provided.
    InvalidParameters(String),
    /// An invalid state was encounter, likely to indicate a bug.
    InvalidState(String),
    /// An error occurred in the wallet component.
    WalletError(Box<dyn std::error::Error>),
    /// An error occurred in the blockchain component.
    BlockchainError(String),
    /// The storage component encountered an error.
    StorageError(String),
    /// The oracle component encountered an error.
    OracleError(String),
    /// An error occurred in the DLC library.
    DlcError(dlc::Error),
    /// An error occurred in the Secp library.
    SecpError(secp256k1_zkp::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Conversion(ref e) => write!(f, "Conversion error {}", e),
            Error::IOError(ref e) => write!(f, "IO error {}", e),
            Error::InvalidState(ref s) => write!(f, "Invalid state: {}", s),
            Error::InvalidParameters(ref s) => write!(f, "Invalid parameters were provided: {}", s),
            Error::WalletError(ref e) => write!(f, "Wallet error {}", e),
            Error::BlockchainError(ref s) => write!(f, "Blockchain error {}", s),
            Error::StorageError(ref s) => write!(f, "Storage error {}", s),
            Error::DlcError(ref e) => write!(f, "Dlc error {}", e),
            Error::OracleError(ref s) => write!(f, "Oracle error {}", s),
            Error::SecpError(ref s) => write!(f, "Secp error {}", s),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IOError(e)
    }
}

impl From<dlc::Error> for Error {
    fn from(e: dlc::Error) -> Error {
        Error::DlcError(e)
    }
}

impl From<crate::conversion_utils::Error> for Error {
    fn from(e: crate::conversion_utils::Error) -> Error {
        Error::Conversion(e)
    }
}

impl From<secp256k1_zkp::Error> for Error {
    fn from(e: secp256k1_zkp::Error) -> Error {
        Error::SecpError(e)
    }
}

impl From<secp256k1_zkp::UpstreamError> for Error {
    fn from(e: secp256k1_zkp::UpstreamError) -> Error {
        Error::SecpError(secp256k1_zkp::Error::Upstream(e))
    }
}
