use libc;

use std::ops::{Deref, DerefMut};
use std::io;

use error::Result;

/// Secure storage using `mlock` to avoid sensitive data being
/// swapped.
pub struct Storage(Box<[u8]>);

impl Storage {
    pub fn new() -> Storage {
        Storage(Box::new([]))
    }

    pub fn from_vec(v: Vec<u8>) -> Result<Storage> {
        Storage::from_buf(v.into_boxed_slice())
    }

    pub fn from_buf(buf: Box<[u8]>) -> Result<Storage> {
        if buf.len() > 0 {
            let ret =
                unsafe {
                    libc::mlock(buf.as_ptr() as *const _,
                                buf.len() as _)
                };

            if ret < 0 {
                error!("mlock failed, can't lock memory pages!");
                return Err(io::Error::last_os_error().into())
            }
        }

        Ok(Storage(buf))
    }
}

impl Deref for Storage {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &*self.0
    }
}

impl DerefMut for Storage {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut *self.0
    }
}
