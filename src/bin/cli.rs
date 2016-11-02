#[macro_use]
extern crate log;
extern crate libc;
extern crate env_logger;
extern crate lpass;
extern crate getopts;

use getopts::{Options, Matches};
use lpass::{Result, Error};

use terminal::{color, Color};

mod terminal;
mod commands;
mod password;

fn main() {
    // Do not remove this umask. Always keep at top.
    unsafe {
        // Set the file mode creation mask and return the previous
        // value. Can't fail.
        libc::umask(0o077);
    }

    env_logger::init().unwrap();

    // Default to have colored output if stdout is a terminal
    terminal::set_color_mode(terminal::ColorMode::Auto);

    // TODO: load_saved_environment

    let args: Vec<_> = std::env::args().collect();

    let res =
        if args.len() >= 2 && args[1].as_bytes()[0] != b'-' {
            process_command(&args)
        } else {
            global_options(&args)
        };

    let exit_code =
        match res {
            Ok(_) => 0,
            Err(e) => {
                println!("{}Command failed{}: {}",
                         color(Color::FgRed),
                         color(Color::Reset),
                         e);

                1
            }
        };

    std::process::exit(exit_code);
}

fn version() {
    println!("LPass-rs CLI v{}", lpass::VERSION);
}

fn help(exe: &str) {
    println!("Usage:");
    println!("  {} --help|-h", exe);
    println!("  {} --version|-v", exe);
    println!("  {} COMMAND [OPTION]", exe);
    println!("");
    println!("Commands:");
    println!("");

    for c in &COMMANDS {
        command_help(exe, c);
    }
}

fn command_help(exe: &str, command: &Command) {
    let opts = command.options();

    let cmd = format!("  {} {} [OPTIONS] {}",
                      exe, command.name, command.free_args);

    println!("{}", opts.usage(&cmd));
}

fn process_command(args: &[String]) -> Result<()> {
    let exe = &args[0];
    let command = &args[1];
    let options = &args[2..];

    // TODO: expand_aliases
    for c in &COMMANDS {
        if c.name == command {
            let res = run_command(c, options);

            if let Err(Error::BadUsage) = res {
                println!("");
                println!("Usage:");
                command_help(exe, c);
            }

            return res;
        }
    }

    help(exe);

    Err(Error::BadUsage)
}

fn run_command(command: &Command, options: &[String]) -> Result<()> {
    match command.options().parse(options) {
        Ok(matches) => {
            if let Some(mode) = matches.opt_str("C") {
                let cm =
                    match mode.as_str() {
                        "auto" => terminal::ColorMode::Auto,
                        "never" => terminal::ColorMode::Never,
                        "always" => terminal::ColorMode::Always,
                        _ => {
                            println!("Invalid color mode '{}'", mode);
                            return Err(Error::BadUsage)
                        }
                    };

                terminal::set_color_mode(cm);
            }

            // Execute the command
            (command.command)(&matches)
        }
        Err(e) => {
            println!("{}", e.to_string());
            Err(Error::BadUsage)
        }
    }
}

fn global_options(args: &[String]) -> Result<()> {
    let exe = &args[0];

    let mut opts = Options::new();

    opts.optflag("v", "version", "display version information and quit");
    opts.optflag("h", "help", "display help message and quit");

    match opts.parse(&args[1..]) {
        Ok(matches) => {
            if matches.opt_present("h") {
                version();
                println!("");
                help(exe);
                Ok(())
            } else if matches.opt_present("v") {
                version();
                Ok(())
            } else {
                // Should not be reached?
                help(exe);
                Err(Error::BadUsage)
            }
        }
        Err(f) => {
            println!("{}", f.to_string());
            help(exe);
            Err(Error::BadUsage)
        }
    }
}

struct CommandOption {
    /// Short option name (i.e. "h" for "-h", "" for none)
    short_name: &'static str,
    /// Long option name (i.e. "help" for "--help", "" for none)
    long_name: &'static str,
    /// Option description displayed in the usage
    description: &'static str,
    /// If the option takes a parameter this should be set to
    /// `Some("<parameter-description>")`. If the option is a simple
    /// flag this should be set to `None`.
    argument: Option<&'static str>,
}

/// Command description and callback
pub struct Command {
    /// Name (used to invoke from the command line)
    name: &'static str,
    /// Command-specific options
    options: &'static [CommandOption],
    /// Description of the free arguments
    free_args: &'static str,
    /// Command implementation
    command: fn(&Matches) -> Result<()>,
}

impl Command {
    /// Build this command's options object and add the common option
    /// flags
    fn options(&self) -> Options {
        let mut opts = Options::new();

        for o in self.options {
            match o.argument {
                Some(argdesc) =>
                    opts.optopt(o.short_name,
                                o.long_name,
                                o.description,
                                argdesc),
                None =>
                    opts.optflag(o.short_name, o.long_name, o.description),
            };
        }

        // Common options for all commands
        opts.optopt("C", "color",
                    "terminal color mode",
                    "auto|never|always");

        opts
    }
}

static COMMANDS: [Command; 1] = [
    commands::login::LOGIN_COMMAND,
];
