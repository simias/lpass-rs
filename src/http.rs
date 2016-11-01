use Error;
use Result;

use std::result;
use libc::c_void;
use curl;
use openssl::{ssl, x509};
use openssl::hash::{Hasher, MessageDigest};
use base64;

pub struct Session {
    /// Server name (e.g. "lastpass.com")
    server: String,
}

pub fn init() {
    curl::init();
}

/// Perform a POST requests to `page` using the post fields
/// `params`. Returns a `Vec` containing
/// the response data or an `Error` if something goes wrong.
pub fn post(page: &str,
            session: Option<Session>,
            params: &[(&str, &str)]) -> Result<Vec<u8>> {

    let login_server =
        match session {
            Some(s) => s.server.clone(),
            None => LASTPASS_SERVER.to_owned(),
        };

    let url = format!("https://{}/{}", login_server, page);

    debug!("POST request to {}", url);

    let mut request = curl::easy::Easy::new();

    // URL-encode `params`
    let mut post = String::new();

    for &(k, v) in params {
        if !post.is_empty() {
            post.push('&');
        }

        let k = request.url_encode(k.as_bytes());
        let v = request.url_encode(v.as_bytes());

        post += &format!("{}={}", k, v);
    }

    // Build the POST request
    try!(request.url(&url));
    try!(request.useragent(&format!("LPass-rs-CLI/{}", ::VERSION)));
    try!(request.ssl_verify_host(true));
    try!(request.ssl_verify_peer(true));

    try!(request.ssl_ctx_function(validate_certificate));

    try!(request.fail_on_error(true));
    try!(request.progress(false));

    // TODO: http.c uses the progress function to check for interrupt,
    // do we want to do that?

    if !post.is_empty() {
        try!(request.post_fields_copy(post.as_bytes()));
    }

    // TODO: handle session

    let mut received = Vec::new();

    {
        let mut transfer = request.transfer();

        try!(transfer.write_function(|data| {
            received.extend_from_slice(data);
            Ok(data.len())
        }));

        try!(transfer.perform());
    }

    let response_code = try!(request.response_code());

    if response_code != 200 {
        Err(Error::HttpError(response_code))
    } else {
        Ok(received)
    }
}

fn validate_certificate(ssl_ctx: *mut c_void) -> result::Result<(), curl::Error> {
    assert!(!ssl_ctx.is_null());

    // XXX Is it safe to assume that this is an OpenSSL context? The C
    // code seems to think so but the doc is a bit more ambiguous.
    let mut ctx = unsafe {
        // XXX `SslContextBuilder` assumes it own the context but it
        // doesn't here. Make sure to `forget` it when we're done with
        // it.
        ssl::SslContextBuilder::from_ptr(ssl_ctx as *mut _)
    };

    // Register the certificate verification callback
    ctx.set_verify_callback(ssl::SSL_VERIFY_PEER, verify_pinned_certificate);

    // We don't want to delete the context since we don't really own
    // it. Let's prevent the `drop` from running. If we don't do that
    // then we're going to segfault down the line.
    ::std::mem::forget(ctx);

    Ok(())
}

fn verify_pinned_certificate(preverify_ok: bool,
                             store: &x509::X509StoreContextRef) -> bool {
    if !preverify_ok {
        return false;
    }

    let chain =
        match store.get_chain() {
            Some(c) => c,
            None => {
                error!("Empty certificate chain!");
                return false;
            }
        };

    // Look for the public keys in the certificate chain, compute
    // their base64-encoded SHA256 hash and compare them with the
    // values in the PINNED_CERTIFICATES list.
    for cert in chain {
        if let Ok(pkey) = cert.public_key() {
            if let Ok(der) = pkey.public_key_to_der() {
                let mut h = Hasher::new(MessageDigest::sha256()).unwrap();

                h.update(&der).unwrap();

                let sha = h.finish().unwrap();

                let encoded = base64::encode(&sha);

                debug!("SSL certificate signature: {}", encoded);

                for pin in &PINNED_CERTIFICATES {
                    if &encoded == pin {
                        // We found a pinned certificate, we can proceed
                        debug!("Found {} in pinned certificate list", encoded);
                        return true;
                    }
                }
            }
        }
    }

    debug!("No pinned certificate found in certificate chain, aborting");
    false
}

/// Domain name of the lastpass server
static LASTPASS_SERVER: &'static str = "lastpass.com";

/// List of the base64-encoded SHA256 public key signatures for the
/// pinned certificates. Lifted straight from the C client.
static PINNED_CERTIFICATES: [&'static str; 7] = [
    // current lastpass.com primary (Thawte)
    "HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=",
    // current lastpass.eu primary (AddTrust)
    "lCppFqbkrlJ3EcVFAkeip0+44VaoJUymbnOaEUk7tEU=",
    // future lastpass root CA (GlobalSign R2)
    "iie1VXtL7HzAMF+/PVPR9xzT80kQxdZeJ+zduCB3uj0=",
    // future lastpass.com primary (leaf)
    "0hkr5YW/WE6Nq5hNTcApxpuaiwlwy5HUFiOt3Qd9VBc=",
    // future lastpass.com backup (leaf)
    "8CzY4qWQKZjFDwHXTOIpsVfWkiVnrhQOJEM4Q2b2Ar4=",
    // future lastpass.eu primary (leaf)
    "SQAWwwYXoceSd8VNbiyxspGXEjFndkklEO2XzLMts10=",
    // future lastpass.eu backup (leaf)
    "qr2VCNpUi0PK80PfRyF7lFBIEU1Gzz931k03hrD+xGQ=",
];
