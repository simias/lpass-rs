use std::env;
use std::process;
use std::io;
use std::io::{Read, Write};

use lpass::{Result, Error};
use lpass::SecureStorage;

/// Prompt the user for a password
pub fn prompt(prompt: &str,
              desc: &str,
              error: Option<&str>) -> Result<SecureStorage> {
    // XXX Implement fallback using the terminal and
    // LPASS_DISABLE_PINENTRY

    let pinentry =
        match env::var("LPASS_PINETRY") {
            Ok(p) => p,
            Err(_) => "pinentry".to_owned(),
        };

    debug!("Spawning {}", pinentry);

    let mut pinentry = try!(process::Command::new(&pinentry)
                            .stdin(process::Stdio::piped())
                            .stdout(process::Stdio::piped())
                            .spawn());

    let r = pinentry_proto(&mut pinentry, prompt, desc, error);

    if pinentry.wait().is_err() {
        let _ = pinentry.kill();
    }

    r
}

/// Implementation of the pinentry protocol
fn pinentry_proto(pinentry: &mut process::Child,
                  prompt: &str,
                  desc: &str,
                  error: Option<&str>) -> Result<SecureStorage> {

    let bad_proto = Err(io::Error::new(io::ErrorKind::Other,
                                       "Pinentry protocol error").into());

    try!(expect_ok(pinentry));

    try!(send(pinentry, "SETTITLE lpass CLI\n"));
    try!(expect_ok(pinentry));

    try!(send(pinentry, &format!("SETPROMPT {}\n", prompt)));
    try!(expect_ok(pinentry));

    try!(send(pinentry, &format!("SETDESC {}\n", desc)));
    try!(expect_ok(pinentry));

    if let Some(error) = error {
        try!(send(pinentry, &format!("SETERROR {}\n", error)));
        try!(expect_ok(pinentry));
    }

    try!(send(pinentry, "GETPIN\n"));

    let password = try!(read_line(pinentry));

    if password.len() < 2 {
        try!(send(pinentry, "BYE\n"));
        return bad_proto;
    }

    if password.len() >= 12 && &password[0..12] == b"ERR 83886179" {
        // This weird code denotes that the user canceled the
        // operation
        return Err(Error::UserAbort);
    }

    match &password[0..2] {
        b"D " => {
            try!(expect_ok(pinentry));

            SecureStorage::from_slice(&password[2..])
        }
        // Empty/no password
        b"OK" => Ok(SecureStorage::empty()),
        _ => bad_proto,
    }
}

fn expect_ok(pinentry: &mut process::Child) -> Result<()> {
    let line = try!(read_line(pinentry));

    if line.len() < 2 || &line[0..2] != b"OK" {
        let err = io::Error::new(io::ErrorKind::Other,
                                 "Pinentry protocol error");

        return Err(Error::IoError(err));
    }

    Ok(())
}

fn read_line(pinentry: &mut process::Child) -> Result<SecureStorage> {
    let stdout =
        match pinentry.stdout {
            Some(ref mut s) => s,
            None => {
                let err = io::Error::new(io::ErrorKind::Other,
                                         "Couldn't capture pinentry stdout");

                return Err(Error::IoError(err));
            }
        };

    let mut line = try!(SecureStorage::with_capacity(64));

    for b in stdout.bytes() {
        let b = try!(b);

        if b == b'\n' {
            break;
        } else {
            try!(line.push(b));
        }
    }

    Ok(line)
}

fn send(pinentry: &mut process::Child, data: &str) -> Result<()> {
    let stdin =
        match pinentry.stdin {
            Some(ref mut s) => s,
            None => {
                let err = io::Error::new(io::ErrorKind::Other,
                                         "Couldn't capture pinentry stdin");

                return Err(Error::IoError(err));
            }
        };

    try!(stdin.write_all(data.as_bytes()));

    Ok(())
}
