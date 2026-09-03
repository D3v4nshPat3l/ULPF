//! Replay a raw log file over UDP to stand in for a live device.
//!
//! Pacing is deadline-based rather than sleep-per-event. Sleeping after every
//! datagram caps the sender at roughly 1,000 EPS on Windows, where the timer
//! granularity is about a millisecond — which silently makes the *sender* the
//! bottleneck and understates what the collector can absorb. Here each event
//! has an absolute deadline from a fixed start instant, so error cannot
//! accumulate, and the loop only sleeps when it is genuinely ahead of schedule.

use std::fs::File;
use std::io::{BufRead, BufReader};
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

    match count {
        Some(n) => println!(
            "Replaying {} lines to {} at {} EPS ({} events, then stop)...",
            lines.len(),
            target,
            eps,
            n
        ),
        None => println!(
            "Replaying {} lines to {} at {} EPS (Ctrl-C to stop)...",
            lines.len(),
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

        let line = &lines[(sent as usize) % lines.len()];
        socket.send_to(line.as_bytes(), target)?;
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
