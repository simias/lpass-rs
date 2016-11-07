use libc;

use std::ops::{Deref, DerefMut, Drop};
use std::cmp::{PartialEq, Eq};
use std::io;

use error::Result;

/// Secure storage using `mlock` to avoid sensitive data being
/// swapped.
pub struct Storage {
    storage: Box<[u8]>,
    len: usize,
}

impl Storage {
    /// Create a new empty `Storage`.
    pub fn empty() -> Storage {
        Storage {
            storage: Box::new([]),
            len: 0,
        }
    }

    /// Build a storage by copying the contents of a slice.
    pub fn from_slice(s: &[u8]) -> Result<Storage> {
        let mut st =
            try!(Storage::from_vec(vec![0; s.len()]));

        for (i, b) in s.iter().enumerate() {
            st[i] = *b;
        }

        Ok(st)
    }

    /// Build a `Storage` with the given capacity.
    pub fn with_capacity(capacity: usize) -> Result<Storage> {
        let mut s =
            try!(Storage::from_vec(vec![0; capacity]));

        s.len = 0;

        Ok(s)
    }

    /// Convert a Vec into a secure `Storage`. Fails if we can't lock
    /// the memory.
    pub fn from_vec(v: Vec<u8>) -> Result<Storage> {
        Storage::from_buf(v.into_boxed_slice())
    }

    /// Convert a boxed slice into a secure `Storage`. Fails if we
    /// can't lock the memory.
    pub fn from_buf(buf: Box<[u8]>) -> Result<Storage> {
        try!(mlock(&*buf));

        Ok(Storage{
            len: buf.len(),
            storage: buf,
        })
    }

    /// Push a new byte into the `Storage`, reallocating if the
    /// capacity is insufficient
    pub fn push(&mut self, b: u8) -> Result<()> {
        if self.len == self.storage.len() {
            // Need to reallocate
            let new_capacity =
                match self.len {
                    0 => 32,
                    n => n * 2,
                };

            try!(self.reallocate(new_capacity));
        }

        self.storage[self.len] = b;

        self.len += 1;

        Ok(())
    }

    fn reallocate(&mut self, new_capacity: usize) -> Result<()> {
        assert!(new_capacity > self.storage.len());

        let mut new = vec![0; new_capacity].into_boxed_slice();

        try!(mlock(&*new));

        for (i, &b) in self.storage.iter().enumerate() {
            new[i] = b;
        }

        munlock(&mut *self.storage);

        self.storage = new;

        Ok(())
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        munlock(&mut *self.storage);
    }
}

impl Deref for Storage {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.storage[0..self.len]
    }
}

impl DerefMut for Storage {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.storage[0..self.len]
    }
}

impl PartialEq for Storage {
    fn eq(&self, other: &Storage) -> bool {
        self.len() == other.len() &&
            self.iter()
            .zip(other.iter())
            .all(|(&a, &b)| a == b)
    }
}

impl Eq for Storage {}

fn mlock(s: &[u8]) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }

    let ret =
        unsafe {
            libc::mlock(s.as_ptr() as *const _,
                        s.len() as _)
        };

    if ret < 0 {
        error!("mlock failed, can't lock memory pages!");
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

fn munlock(s: &mut [u8]) {
    if s.is_empty() {
        return;
    }

    // Clear the memory before we unlock it. Since we pass the buffer
    // to `mlock` after that LLVM shouldn't optimize that away.
    for b in s.iter_mut() {
        *b = 0;
    }

    // We can't do much if this call fails so let's just ignore
    // errors.
    let _ =
        unsafe {
            libc::munlock(s.as_ptr() as *const _,
                          s.len() as _)
        };
}
