#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::{
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let cwd = std::env::current_dir().unwrap_or_default();
    let response = sentra_cli::run(&arguments, &cwd);
    if io::stdout()
        .lock()
        .write_all(response.stdout.as_bytes())
        .is_err()
        || io::stderr()
            .lock()
            .write_all(response.stderr.as_bytes())
            .is_err()
    {
        return ExitCode::from(8);
    }
    ExitCode::from(response.exit_code)
}
