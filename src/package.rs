use std::fs::{read_to_string, File};
use std::io::{copy, BufReader, Read};
use std::path::Path;

use crate::Error;
use base64::encode;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

pub fn sign_package(key_path: &Path, file_path: &Path) -> Result<String, Error> {
    let package_file = File::open(file_path).map_err(Error::FailedToPackage)?;
    let key = read_to_string(key_path).map_err(Error::FailedToPackage)?;

    let buf_read = BufReader::new(package_file);
    let key_pair = PKey::private_key_from_pem(key.as_bytes()).map_err(Error::InvalidKey)?;
    sign(buf_read, &key_pair)
}

fn sign(mut package: impl Read, key: &PKey<Private>) -> Result<String, Error> {
    let mut signer = Signer::new(MessageDigest::sha512(), &key).map_err(Error::InvalidKey)?;
    copy(&mut package, &mut signer).map_err(Error::FailedToPackage)?;

    let signature = signer.sign_to_vec().map_err(Error::SignatureFailed)?;

    Ok(encode(&signature))
}

#[test]
fn test_sign() {
    use crate::test::*;
    let key = PKey::private_key_from_pem(PEM_PRIVATE_KEY).unwrap();
    assert_eq!(EXPECTED_SIGNATURE, sign(TEST_CONTENT, &key).unwrap());
}
