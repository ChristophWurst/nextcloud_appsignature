use base64::encode;
use openssl::sign::Signer;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use std::fs::File;
use std::io::{copy, BufReader};
use std::path::{Path};

use super::error;
use super::keys::get_private_key;

pub fn sign_package(key_path: &Path, file_path: &Path) -> Result<String, error::SignError> {
    let package_file = File::open(file_path)?;
    let key = get_private_key(key_path)?;
    let keypair = PKey::private_key_from_pem(key.as_bytes())?;
    let mut signer = Signer::new(MessageDigest::sha512(), &keypair)?;

    let mut buf_read = BufReader::new(package_file);
    copy(&mut buf_read, &mut signer)?;

    let signature = signer.finish()?;

    Ok(encode(&signature))
}
