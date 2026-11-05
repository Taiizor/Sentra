use std::{env, fs, process::ExitCode};

fn count_lines(input: &str) -> Result<usize, &'static str> {
    if input.contains('\0') {
        return Err("input contains a NUL character");
    }
    Ok(input.lines().count())
}

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(path) = arguments.next() else {
        eprintln!("usage: sentra-rust-msvc-probe <utf8-file>");
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("expected exactly one input file");
        return ExitCode::from(2);
    }

    match fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|input| count_lines(&input).map_err(str::to_owned))
    {
        Ok(lines) => {
            println!("lines={lines}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("probe failed: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::count_lines;

    #[test]
    fn counts_unicode_text_with_crlf() {
        assert_eq!(count_lines("Sentra\r\nUnicode: \u{fc}\r\n"), Ok(2));
    }

    #[test]
    fn rejects_nul_input() {
        assert_eq!(
            count_lines("before\0after"),
            Err("input contains a NUL character")
        );
    }

    #[test]
    fn accepts_empty_input() {
        assert_eq!(count_lines(""), Ok(0));
    }
}
