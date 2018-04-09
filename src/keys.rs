use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use failure::Error;

pub fn get_private_key(key_path: &Path) -> Result<String, Error> {
    let mut file = File::open(key_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}
