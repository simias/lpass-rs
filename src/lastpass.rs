//! LastPass HTTP API

use Result;

use std::u32;
use std::str::FromStr;

use http;

/// Return the number of iterations for `login`
pub fn iterations(session: &http::Session, login: &str) -> Result<u32> {
    let login = login.to_lowercase();

    let response =
        try!(session.post("iterations.php", &[("email", &login)]));

    let s = try!(String::from_utf8(response));

    let iter = try!(u32::from_str(&s));

    Ok(iter)
}
