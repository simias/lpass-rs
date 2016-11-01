use std::convert::From;
use std::io;
use std::fmt;
use std::num;
use std::string;
use std::result;

use curl;

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
    /// HTTP request didn't receive a 200 response
    HttpError(u32),
    /// String to integer conversion failed
    ParseIntError(num::ParseIntError),
    /// String conversion failed
    Utf8Error(string::FromUtf8Error),
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
    fn from(e: num::ParseIntError) -> Error {
        Error::ParseIntError(e)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Error {
        Error::Utf8Error(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::CurlError(ref e) =>
                write!(f, "CURL library error: {}", e),
            e => write!(f, "{:?}", e)
        }
    }
}
