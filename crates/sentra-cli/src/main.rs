#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::{
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let cwd = std::env::current_dir().unwrap_or_default();
    // Not locked for the whole run: `codeql analyze --cancel-on-stdin-eof` watches stdin
    // from a separate thread, which a lock held here would block forever.
    let mut stdin = io::BufReader::new(io::stdin());
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let code = sentra_cli::run_stream(&arguments, &cwd, &mut stdin, &mut stdout, &mut stderr);
    let _ = stdout.flush();
    let _ = stderr.flush();
    ExitCode::from(code)
}
