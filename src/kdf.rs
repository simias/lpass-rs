//! Key derivation functions

use Result;
use Error;
use SecureStorage;

use openssl::pkcs5;
use openssl::hash::MessageDigest;

/// Key derivation function used to generate the login key (the one
/// sent to the server)
pub fn login_key(login: &str,
                 password: &SecureStorage,
                 iterations: u32) -> Result<SecureStorage> {
    // The C client doesn't do that but it's probably not a good idea
    // to work with a very low number of iterations. The C client has
    // a special KDF implementation when iterations == 1, so look
    // there if we ever need to implement that.
    if iterations < 1000 {
        let err = format!("Iteration count too low ({})", iterations);

        return Err(Error::BadProtocol(err));
    }

    let mut temp = try!(SecureStorage::from_vec(vec![0; 32]));

    try!(pkcs5::pbkdf2_hmac(&password,
                            login.as_bytes(),
                            iterations as usize,
                            MessageDigest::sha256(),
                            &mut temp));

    let mut key = try!(SecureStorage::from_vec(vec![0; 32]));

    try!(pkcs5::pbkdf2_hmac(&temp,
                            &password,
                            1,
                            MessageDigest::sha256(),
                            &mut key));

    Ok(key)
}
