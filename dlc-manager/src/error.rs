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
    InvalidParameters,
    /// An invalid state was encounter, likely to indicate a bug.
    InvalidState,
    /// An error occurred in the wallet component.
    WalletError(Box<dyn std::error::Error>),
    /// An error occurred in the blockchain component.
    BlockchainError,
    /// The storage component encountered an error.
    StorageError,
    /// The oracle component encountered an error.
    OracleError,
    /// An error occurred in the DLC library.
    DlcError(dlc::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Conversion(ref e) => write!(f, "Conversion error {}", e),
            Error::IOError(ref e) => write!(f, "IO error {}", e),
            Error::InvalidState => write!(f, "Invalid state"),
            Error::InvalidParameters => write!(f, "Invalid parameters were provided"),
            Error::WalletError(ref e) => write!(f, "Wallet error {}", e),
            Error::BlockchainError => write!(f, "Blockchain error"),
            Error::StorageError => write!(f, "Storage error"),
            Error::DlcError(ref e) => write!(f, "Dlc error {}", e),
            Error::OracleError => write!(f, "Oracle error"),
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
