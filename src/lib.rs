extern crate base64;
extern crate futures;
extern crate hex;
extern crate openssl;

pub mod error;
mod keys;
mod package;

pub use package::sign_package;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
