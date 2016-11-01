//! LastPass HTTP API

#[macro_use]
extern crate log;
extern crate curl;
extern crate openssl;
extern crate base64;
extern crate libc;

mod http;
mod error;

use std::u32;
use std::str::FromStr;

pub use http::Session;
pub use error::{Result, Error};

/// Version of lpass-rs set in Cargo.toml
pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

/// Return the number of iterations for `login`
pub fn iterations(session: &Session, login: &str) -> Result<u32> {
    let login = login.to_lowercase();

    let response =
        try!(session.post("iterations.php", &[("email", &login)]));

    let s = try!(String::from_utf8(response));

    let iter = try!(u32::from_str(&s));

    Ok(iter)
}
