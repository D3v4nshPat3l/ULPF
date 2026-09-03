use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::Path;
use std::thread;
use std::time::Duration;

pub fn cmd_replay(source_file: &Path, target: &str, eps: u64) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let file = File::open(source_file)?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            lines.push(line);
        }
    }

    if lines.is_empty() {
        anyhow::bail!("Source file is empty");
    }

    println!("Replaying {} lines to {} at {} EPS...", lines.len(), target, eps);
    let sleep_duration = Duration::from_micros(1_000_000 / eps.max(1));

    let mut i = 0;
    loop {
        let line = &lines[i % lines.len()];
        // Note: Simple replay for now. A real replay engine would parse and rewrite timestamps.
        socket.send_to(line.as_bytes(), target)?;
        i += 1;

        if i % (eps as usize) == 0 {
            println!("Sent {} events...", i);
        }

        thread::sleep(sleep_duration);
    }
}
