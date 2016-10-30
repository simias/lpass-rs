use Error;
use Result;

use curl;

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
    // TODO: Implement certificate pinning! curl-rust doesn't seem to
    // support CURLOPT_SSL_CTX_FUNCTION, implement it or find a way
    // around it.

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

static LASTPASS_SERVER: &'static str = "lastpass.com";
