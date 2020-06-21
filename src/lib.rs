mod package;

#[cfg(test)]
mod test;

use openssl::error::ErrorStack;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Failed to load key file: {0}")]
    FailedToLoadKey(#[source] io::Error),
    #[error("Failed to package file: {0}")]
    FailedToPackage(#[source] io::Error),
    #[error("Key could not be parsed by openssl: {0}")]
    InvalidKey(#[source] ErrorStack),
    #[error("Failed to sign package: {0}")]
    SignatureFailed(#[source] ErrorStack),
}

pub use package::sign_package;
