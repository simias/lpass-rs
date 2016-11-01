/// Terminal-specific handling

use lpass::{Result, Error};

use std::sync::atomic::{AtomicBool, ATOMIC_BOOL_INIT, Ordering};
use std::io;
use std::io::Write;

/// Prompt the user for a yes-or-no question, return `Ok(())` if they
/// reply "yes", `Err(Error::UserAbort)` if they reply "no". Can also
/// return an I/O error if reading from the terminal fails somehow.
pub fn ask_yes_no(default_yes: bool, prompt: &str) -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("{}{}{}",
               color(Color::FgYellow),
               prompt,
               color(Color::Reset));

        if default_yes {
            print!("[{}Y{}/n] ", color(Color::Bold), color(Color::Reset));
        } else {
            print!("[y/{}N{}] ", color(Color::Bold), color(Color::Reset));
        }

        try!(stdout.flush());

        let mut reply = String::new();

        // XXX should we check if stdin is not a tty and do something?
        try!(stdin.read_line(&mut reply));

        let ok = Ok(());
        let err = Err(Error::UserAbort);

        match reply.as_str() {
            "\n" =>
                if default_yes {
                    return ok
                } else {
                    return err
                },
            "no\n" | "n\n" => return err,
            "yes\n" | "y\n" => return ok,
            _ => println!("{}Error{}: Response not understood.",
                          color(Color::FgRed), color(Color::Reset)),
        }
    }
}

/// If true colored output is enabled
static COLOR_ENABLED: AtomicBool = ATOMIC_BOOL_INIT;

/// Terminal color handling
#[derive(Copy, Clone)]
pub enum ColorMode {
    Auto,
    Never,
    Always,
}

pub fn stdout_is_a_tty() -> bool {
    let is_a_tty = unsafe {
        ::libc::isatty(::libc::STDOUT_FILENO)
    };

    is_a_tty == 1
}

pub fn set_color_mode(mode: ColorMode) {
    let enabled =
        match mode {
            ColorMode::Never => false,
            ColorMode::Always => true,
            ColorMode::Auto => stdout_is_a_tty(),
        };

    COLOR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub enum Color {
    FgRed,
    FgYellow,
    Bold,
    /// Reset to the default foreground and background color
    Reset,
}

/// Return the terminal color code (ANSI escape code) for the given
/// color if `COLOR_ENABLED` is `true`, otherwise return ""
pub fn color(col: Color) -> &'static str {
    if !COLOR_ENABLED.load(Ordering::Relaxed) {
        return ""
    }

    // XXX should we query terminfo or something like that instead of
    // hardcoding those?
    match col {
        Color::FgRed => "\x1b[31m",
        Color::FgYellow => "\x1b[33m",
        Color::Bold => "\x1b[1m",
        Color::Reset => "\x1b[0m",
    }
}
