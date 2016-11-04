//! LastPass HTTP API

#![warn(missing_docs)]

#[macro_use]
extern crate log;
extern crate curl;
extern crate openssl;
extern crate base64;
extern crate libc;
extern crate xml as xml_sax;

mod http;
mod error;
mod secure;
mod xml;

pub mod kdf;

use std::u32;
use std::str::FromStr;

pub use error::{Result, Error};
pub use secure::Storage as SecureStorage;

/// Version of lpass-rs set in Cargo.toml
pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

/// Session state
pub struct Session {
    /// Login of the user, used to log into the server and to derive
    /// the keys
    username: String,
    /// Server name (e.g. "lastpass.com")
    server: String,
    /// Number of iterations for the key derivation functions
    iterations: Option<u32>,
}

impl Session {
    /// Create a new session for `username`. Usernames are always
    /// lowercase so `username` will be converted if necessary.
    pub fn new(username: &str) -> Session {
        curl::init();

        Session {
            // The username is always converted to lowercase in the
            // API.
            username: username.to_lowercase(),
            server: "lastpass.com".to_owned(),
            iterations: None,
        }
    }

    /// Return `true` if the session is authenticated on the server.
    pub fn is_authenticated(&self) -> bool {
        false
    }

    /// Return the server name used by this session.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Return the username used by this session. Usernames are always
    /// lowercase.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Return the number of key derivation iterations for this
    /// username.
    pub fn iterations(&mut self) -> Result<u32> {
        // We cache the value in order not to query the server every
        // time we need this.
        match self.iterations {
            Some(i) => Ok(i),
            None => {
                let iterations = try!(self.server_iterations());
                self.iterations = Some(iterations);
                Ok(iterations)
            }
        }
    }

    /// Query the server for the number of iterations required for
    /// this session's `username`
    fn server_iterations(&self) -> Result<u32> {
        let response =
            try!(self.post("iterations.php",
                           &[(b"email", self.username().as_bytes())]));

        let s = try!(String::from_utf8(response));

        let iter = try!(u32::from_str(&s));

        debug!("Iterations for {}: {}", self.username(), iter);

        Ok(iter)
    }

    /// Attempt to log into the server using `login_key`. If `trust`
    /// is true then we tell the server that two factor authentication
    /// won't be necessary for subsequents logins.
    pub fn login(&mut self,
                 password: SecureStorage,
                 trust: bool) -> Result<()> {

        let iterations = try!(self.iterations());

        let login_key =
            try!(kdf::login_key(&self.username(), &password, iterations));

        let iter_str = format!("{}", try!(self.iterations()));

        // hex-encode the key
        let mut hex_key =
            try!(SecureStorage::from_vec(vec![0; login_key.len() * 2]));

        for (i, b) in login_key.iter().enumerate() {
            let to_hex = b"0123456789abcdef";

            hex_key[i * 2] = to_hex[(b >> 4) as usize];
            hex_key[i * 2 + 1] = to_hex[(b & 0xf) as usize];
        }

        let _ = trust;

        // Lifted from the C command line client, not sure if any of those
        // should be made configurable.
        let params: &[(&[u8], &[u8])] = &[
            (b"xml", b"2"),
            (b"username", self.username().as_bytes()),
            (b"hash", &hex_key),
            (b"iterations", iter_str.as_bytes()),
            (b"includeprivatekeyenc", b"1"),
            (b"method", b"cli"),
            (b"outofbandsupported", b"1"),
        ];

        let response =
            try!(self.post("login.php", params));

        let xml =
            try!(xml::Dom::parse(&response as &[u8]));

        println!("{}", String::from_utf8_lossy(&response));

        Ok(())
    }

    fn post(&self,
            page: &str,
            params: &[(&[u8], &[u8])]) -> Result<Vec<u8>> {
        http::post(self.server(), page, params)
    }
}
