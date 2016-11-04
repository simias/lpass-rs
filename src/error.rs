use std::convert::From;
use std::io;
use std::fmt;
use std::num;
use std::string;
use std::result;

use curl;
use openssl;
use xml_sax::reader as xml_reader;

use OtpMethod;

/// Specialized `Result` type for the lpass API
pub type Result<T> = result::Result<T, Error>;

/// Error type returned by the lpass API.
#[derive(Debug)]
pub enum Error {
    /// Command usage error
    BadUsage,
    /// User aborted the command
    UserAbort,
    /// Bad password
    InvalidPassword,
    /// Bad username
    InvalidUser,
    /// Action failed because OTP auth is required
    OtpRequired(OtpMethod),
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
    /// We encountered a valid but unsupported action
    Unsupported(String),
    /// Server returned an invalid XML
    XmlError(xml_reader::Error),
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

impl From<xml_reader::Error> for Error {
    fn from(e: xml_reader::Error) -> Error {
        Error::XmlError(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::CurlError(ref e) =>
                write!(f, "CURL library error: {}", e),
            &Error::BadProtocol(ref e) =>
                write!(f, "Protocol error: {}", e),
            &Error::Unsupported(ref e) =>
                write!(f, "Unsupported: {}", e),
            &Error::XmlError(ref e) =>
                write!(f, "Received invalid XML: {}", e),
            e => write!(f, "{:?}", e)
        }
    }
}
