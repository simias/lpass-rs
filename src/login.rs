use Result;
use Error;
use CommandOption;

use http;
use lastpass;
use terminal::ask_yes_no;

use getopts::Matches;

pub fn login(options: &Matches) -> Result<()> {

    let _trust = options.opt_present("t");
    let plaintext_key = options.opt_present("P");
    let force = options.opt_present("f");

    let login =
        match options.free.get(0) {
            Some(l) => l,
            None => {
                println!("Missing LOGIN");
                return Err(Error::BadUsage)
            }
        };

    if plaintext_key && !force {
        try!(ask_yes_no(false,
                        "You have used the --plaintext-key option. \
                         This option will greatly reduce the security \
                         of your passwords. You are advised, instead, \
                         to use the agent, whose timeout can be disabled \
                         by settting LPASS_AGENT_TIMEOUT=0. Are you sure \
                         you would like to do this?"))
    }

    let session = http::Session::new(LASTPASS_SERVER.to_owned());

    let iterations = try!(lastpass::iterations(&session, &login));

    debug!("Iterations for {}: {}", login, iterations);

    Ok(())
}

/// Domain name of the lastpass server
static LASTPASS_SERVER: &'static str = "lastpass.com";

pub const LOGIN_COMMAND: ::Command = ::Command {
    name: "login",
    options: &[
        CommandOption {
            short_name: "t",
            long_name: "trust",
            description: "subsequent logins won't require 2FA",
            argument: None,
        },
        CommandOption {
            short_name: "P",
            long_name: "plaintext-key",
            description: "decryption key will be stored in plaintext",
            argument: None,
        },
        CommandOption {
            short_name: "f",
            long_name: "force",
            description: "Don't ask for confirmation if \
                          plaintext-key is requested",
            argument: None,
        },
    ],
    free_args: "LOGIN",
    command: login,
};
