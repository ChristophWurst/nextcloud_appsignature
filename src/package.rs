use std::fs::read_to_string;
use std::io::{copy, BufReader, Read};
use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha512};

use crate::Error;

pub fn sign_package<R: Read>(key_path: &Path, content: &mut R) -> Result<String, Error> {
    let raw_key = read_to_string(key_path).map_err(|_| Error::KeyNotFound(key_path.into()))?;
    let key = decode_private_key(&raw_key)?;

    let buf_read = BufReader::new(content);
    sign(buf_read, &key)
}

fn sign(mut package: impl Read, key: &RsaPrivateKey) -> Result<String, Error> {
    let mut hasher = Sha512::new();
    copy(&mut package, &mut hasher).map_err(Error::FailedToPackage)?;
    let signature = key
        .sign(Pkcs1v15Sign::new::<Sha512>(), &hasher.finalize())
        .map_err(Error::SignatureFailed)?;

    Ok(BASE64.encode(&signature))
}

fn decode_private_key(key_data: &str) -> Result<RsaPrivateKey, Error> {
    let der_encoded = key_data
        .split('\n')
        .filter(|line| !line.starts_with('-'))
        .fold(String::with_capacity(1024), |mut data, line| {
            data.push_str(line);
            data
        });
    let der_bytes = BASE64.decode(&der_encoded).map_err(|_| Error::InvalidKey)?;
    RsaPrivateKey::from_pkcs8_der(&der_bytes)
        .or_else(|_| RsaPrivateKey::from_pkcs1_der(&der_bytes))
        .map_err(|_| Error::InvalidKey)
}

#[test]
fn test_sign() {
    use crate::test::*;
    let key = decode_private_key(PEM_PRIVATE_KEY).unwrap();
    assert_eq!(EXPECTED_SIGNATURE, sign(TEST_CONTENT, &key).unwrap());
}

#[test]
fn test_sign_rsa_key() {
    use crate::test::*;
    let key = decode_private_key(PEM_PRIVATE_KEY_RSA).unwrap();
    assert_eq!(EXPECTED_RSA_SIGNATURE, sign(TEST_CONTENT, &key).unwrap());
}
