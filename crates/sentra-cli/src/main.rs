#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::{
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let code = sentra_cli::run_stream(&arguments, &cwd, &mut stdin, &mut stdout, &mut stderr);
    let _ = stdout.flush();
    let _ = stderr.flush();
    ExitCode::from(code)
}
