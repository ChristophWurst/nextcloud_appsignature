extern crate base64;
extern crate futures;
extern crate hex;
extern crate openssl;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate walkdir;

pub mod error;
mod integrity;
mod keys;
mod package;

pub use package::sign_package;
pub use integrity::sign_app;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
