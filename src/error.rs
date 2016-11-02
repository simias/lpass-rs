use std::convert::From;
use std::io;
use std::fmt;
use std::num;
use std::string;
use std::result;

use curl;
use openssl;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Command usage error
    BadUsage,
    /// User aborted the command
    UserAbort,
    /// Input/output error
    IoError(io::Error),
    /// CURL library error
    CurlError(curl::Error),
    /// OpenSSL library error
    OpensslError(openssl::error::ErrorStack),
    /// HTTP request didn't receive a 200 response
    HttpError(u32),
    /// A server reply didn't make sense
    BadProtocol(String),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<curl::Error> for Error {
    fn from(e: curl::Error) -> Error {
        Error::CurlError(e)
    }
}

impl From<num::ParseIntError> for Error {
    fn from(_: num::ParseIntError) -> Error {
        Error::BadProtocol("Integer conversion failed".to_owned())
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(_: string::FromUtf8Error) -> Error {
        Error::BadProtocol("Non-UTF8 string received".to_owned())
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Error {
        Error::OpensslError(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::CurlError(ref e) =>
                write!(f, "CURL library error: {}", e),
            &Error::BadProtocol(ref e) =>
                write!(f, "Protocol error: {}", e),
            e => write!(f, "{:?}", e)
        }
    }
}
