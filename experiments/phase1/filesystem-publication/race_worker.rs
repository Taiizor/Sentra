// Independent process race worker
// Location: experiments/phase1/filesystem-publication/race_worker.rs

use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: race_worker <src_path> <dst_path>");
        process::exit(1);
    }

    let src = &args[1];
    let dst = &args[2];

    match fs::hard_link(src, dst) {
        Ok(_) => {
            // Success: Winner
            process::exit(0);
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                // Collision: Expected loser
                process::exit(183);
            } else {
                eprintln!("Unexpected error: {:?}", e);
                process::exit(2);
            }
        }
    }
}
