//! Replay a raw log file over UDP to stand in for a live device.
//!
//! Pacing is deadline-based rather than sleep-per-event. Sleeping after every
//! datagram caps the sender at roughly 1,000 EPS on Windows, where the timer
//! granularity is about a millisecond — which silently makes the *sender* the
//! bottleneck and understates what the collector can absorb. Here each event
//! has an absolute deadline from a fixed start instant, so error cannot
//! accumulate, and the loop only sleeps when it is genuinely ahead of schedule.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::UdpSocket;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

/// Sleeping for less than this is not worth the syscall: the OS will overshoot
/// it anyway. Below the threshold the loop just keeps sending and lets the
/// deadline arithmetic even the rate out over the next few events.
const MIN_SLEEP: Duration = Duration::from_millis(2);

pub fn cmd_replay(
    source_file: &Path,
    target: &str,
    eps: u64,
    count: Option<u64>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    // Keep memory usage constant even when replaying multi-gigabyte corpora.
    // The previous implementation collected every line into a Vec<String>;
    // replaying the 2.6 GB Blue Coat corpus could therefore require several
    // additional gigabytes of RAM before the first datagram was sent.
    let file = File::open(source_file)?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut found_event = false;

    match count {
        Some(n) => println!(
            "Streaming {} to {} at {} EPS ({} events, then stop)...",
            source_file.display(),
            target,
            eps,
            n
        ),
        None => println!(
            "Streaming {} to {} at {} EPS (Ctrl-C to stop)...",
            source_file.display(),
            target,
            eps
        ),
    }

    let start = Instant::now();
    let interval = Duration::from_nanos(1_000_000_000 / eps.max(1));
    let mut sent: u64 = 0;

    loop {
        if let Some(limit) = count {
            if sent >= limit {
                break;
            }
        }

        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            if !found_event {
                anyhow::bail!("Source file is empty");
            }
            reader.seek(SeekFrom::Start(0))?;
            continue;
        }

        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if line.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }

        found_event = true;
        socket.send_to(&line, target)?;
        sent += 1;

        if sent % eps.max(1) == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            println!(
                "Sent {} events ({:.0} EPS actual)",
                sent,
                sent as f64 / elapsed.max(f64::EPSILON)
            );
        }

        // Absolute deadline for the *next* event, measured from the start.
        // Falling behind simply means no sleep, so the loop catches up instead
        // of drifting further out.
        let deadline_ns = (sent as u128) * interval.as_nanos();
        let elapsed_ns = start.elapsed().as_nanos();
        if deadline_ns > elapsed_ns {
            let ahead =
                Duration::from_nanos((deadline_ns - elapsed_ns).min(u64::MAX as u128) as u64);
            if ahead >= MIN_SLEEP {
                thread::sleep(ahead);
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "Done: {} events in {:.2}s = {:.0} EPS",
        sent,
        elapsed,
        sent as f64 / elapsed.max(f64::EPSILON)
    );
    Ok(())
}
