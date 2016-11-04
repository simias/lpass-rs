use libc;

use std::ops::{Deref, DerefMut, Drop};
use std::io;

use error::Result;

/// Secure storage using `mlock` to avoid sensitive data being
/// swapped.
pub struct Storage(Box<[u8]>);

impl Storage {
    /// Create a new empty `Storage`.
    pub fn empty() -> Storage {
        Storage(Box::new([]))
    }

    /// Convert a Vec into a secure `Storage`. Fails if we can't lock
    /// the memory.
    pub fn from_vec(v: Vec<u8>) -> Result<Storage> {
        Storage::from_buf(v.into_boxed_slice())
    }

    /// Convert a boxed slice into a secure `Storage`. Fails if we
    /// can't lock the memory.
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

impl Drop for Storage {
    fn drop(&mut self) {
        // Clear the memory before we unlock it. Since we pass the
        // buffer to `mlock` after that I don't think LLVM will
        // optimize that away.
        for b in self.iter_mut() {
            *b = 0;
        }

        // We can't do much if this call fails so let's just ignore
        // errors.
        let _ =
            unsafe {
                libc::munlock(self.as_ptr() as *const _,
                              self.len() as _)
            };
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
