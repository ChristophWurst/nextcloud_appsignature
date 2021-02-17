use std::fs::{read_to_string, File};
use std::io::{copy, BufReader, Read};
use std::path::Path;

use crate::Error;
use base64::encode;
use rsa::{padding::PaddingScheme, Hash, RSAPrivateKey};
use sha2::{Digest, Sha512};

pub fn sign_package(key_path: &Path, file_path: &Path) -> Result<String, Error> {
    let package_file = File::open(file_path).map_err(Error::FailedToPackage)?;
    let raw_key = read_to_string(key_path).map_err(|_| Error::KeyNotFound(key_path.into()))?;
    let key = decode_private_key(&raw_key)?;

    let buf_read = BufReader::new(package_file);
    sign(buf_read, &key)
}

fn sign(mut package: impl Read, key: &RSAPrivateKey) -> Result<String, Error> {
    let mut hasher = Sha512::new();
    copy(&mut package, &mut hasher).map_err(Error::FailedToPackage)?;
    let signature = key
        .sign(
            PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_512)),
            &hasher.finalize(),
        )
        .map_err(Error::SignatureFailed)?;

    Ok(encode(&signature))
}

fn decode_private_key(key_data: &str) -> Result<RSAPrivateKey, Error> {
    let der_encoded = key_data
        .split('\n')
        .filter(|line| !line.starts_with("-"))
        .fold(String::with_capacity(1024), |mut data, line| {
            data.push_str(line);
            data
        });
    let der_bytes = base64::decode(&der_encoded).map_err(|_| Error::InvalidKey)?;
    RSAPrivateKey::from_pkcs8(&der_bytes).map_err(|_| Error::InvalidKey)
}

#[test]
fn test_sign() {
    use crate::test::*;
    let key = decode_private_key(PEM_PRIVATE_KEY).unwrap();
    assert_eq!(EXPECTED_SIGNATURE, sign(TEST_CONTENT, &key).unwrap());
}
