mod package;

#[cfg(test)]
mod test;

use rsa::errors::Error as RSAError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Failed to load key file: {0}")]
    FailedToLoadKey(#[source] io::Error),
    #[error("Failed to package file: {0}")]
    FailedToPackage(#[source] io::Error),
    #[error("Key could not be parsed")]
    InvalidKey,
    #[error("Keyfile {0} not found")]
    KeyNotFound(PathBuf),
    #[error("Failed to sign package: {0}")]
    SignatureFailed(#[source] RSAError),
}

pub use package::sign_package;
use std::path::PathBuf;
