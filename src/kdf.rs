//! Key derivation functions

use Result;
use Error;
use SecureStorage;

use openssl::pkcs5;
use openssl::hash::MessageDigest;

/// Key derivation function used to generate the login key (the one
/// sent to the server)
pub fn login_key(username: &str,
                 password: &[u8],
                 iterations: u32) -> Result<SecureStorage> {

    // The C client doesn't do that but it's probably not a good idea
    // to work with a very low number of iterations. The C client has
    // a special KDF implementation when iterations == 1, so look
    // there if we ever need to implement that.
    if iterations < 1000 {
        let err = format!("Iteration count too low ({})", iterations);

        return Err(Error::Unsupported(err));
    }

    let decrypt_key =
        try!(crypto_key(username, password, iterations));

    let mut login_key = try!(SecureStorage::from_vec(vec![0; 32]));

    try!(pkcs5::pbkdf2_hmac(&decrypt_key,
                            password,
                            1,
                            MessageDigest::sha256(),
                            &mut login_key));

    Ok(login_key)
}

/// Key used to crypt and decrypt the data blobs. This key is never
/// sent to the server.
pub fn crypto_key(username: &str,
                  password: &[u8],
                  iterations: u32) -> Result<SecureStorage> {

    // The C client doesn't do that but it's probably not a good idea
    // to work with a very low number of iterations. The C client has
    // a special KDF implementation when iterations == 1, so look
    // there if we ever need to implement that.
    if iterations < 1000 {
        let err = format!("Iteration count too low ({})", iterations);

        return Err(Error::Unsupported(err));
    }

    let mut key = try!(SecureStorage::from_vec(vec![0; 32]));

    try!(pkcs5::pbkdf2_hmac(password,
                            username.as_bytes(),
                            iterations as usize,
                            MessageDigest::sha256(),
                            &mut key));

    Ok(key)
}

#[test]
fn test_login_key() {
    assert!(login_key("", b"", 1).is_err());

    let tests: &[(&str, &[u8], u32, [u8; 32])] = &[
        ("", b"", 5000,
         [0xa0, 0x40, 0x6b, 0x57, 0x18, 0x4d, 0x8c, 0x8f,
          0x61, 0x5e, 0xbc, 0x79, 0x68, 0xc7, 0x9e, 0xab,
          0x89, 0xc2, 0x35, 0x14, 0xcc, 0x81, 0x54, 0x3a,
          0x27, 0x5b, 0x10, 0xff, 0xd2, 0x65, 0x9d, 0x6b]),
        ("bob", b"password", 5000,
         [0xf6, 0x8e, 0xef, 0x1d, 0x32, 0x7a, 0x7f, 0x3f,
          0x2a, 0x0c, 0x2d, 0xc7, 0xa1, 0x7a, 0x63, 0xaf,
          0xa1, 0x86, 0x04, 0xe3, 0x73, 0x90, 0xc6, 0xec,
          0x37, 0xbb, 0x71, 0xbf, 0x97, 0x56, 0xb7, 0xaa]),
        ("bob", b"password", 1000,
         [0x63, 0x7a, 0x47, 0x73, 0x38, 0x6d, 0x15, 0x3c,
          0xe7, 0xfd, 0x2e, 0x28, 0x1f, 0x2f, 0x9f, 0xfd,
          0xb2, 0x89, 0x44, 0x5f, 0x79, 0x21, 0x4d, 0x0f,
          0xd5, 0xb5, 0x20, 0x10, 0xc5, 0x66, 0x7a, 0x6b]),
        ("lpass-rs", b"sr-ssapl", 1000,
         [0xac, 0x3f, 0x8b, 0xf2, 0x29, 0x90, 0x6e, 0x3c,
          0xff, 0x19, 0x64, 0x36, 0xef, 0xe7, 0x1b, 0xe7,
          0x3f, 0x05, 0x69, 0x2c, 0x04, 0x49, 0xb6, 0x33,
          0x4b, 0xd7, 0x34, 0xc3, 0x10, 0xc6, 0xa2, 0x61]),
        ("lpass-rs", b"SR-SSAPL", 1000,
         [0xe1, 0x80, 0x0c, 0x04, 0x51, 0x30, 0x3d, 0x7c,
          0x8a, 0x1b, 0x49, 0xf5, 0xeb, 0x21, 0x9a, 0xf7,
          0x7e, 0xda, 0xa7, 0x43, 0x7a, 0x8b, 0x58, 0x21,
          0xda, 0x68, 0x01, 0x24, 0xcf, 0xba, 0x4f, 0x3d]),
    ];

    for &(user, pw, iter, ref expected) in tests {
        let key = login_key(user, pw, iter).unwrap();
        let expected = SecureStorage::from_slice(expected).unwrap();

        assert!(key == expected);
    }
}
