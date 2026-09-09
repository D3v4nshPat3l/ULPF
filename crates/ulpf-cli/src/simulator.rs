//! The traffic simulator behind the `/dev` console.
//!
//! Each stream replays one *real* public corpus over UDP at a chosen rate, so
//! what the collector receives during a demo is byte-for-byte what the Honeynet
//! and Loghub captures contain. Nothing here fabricates a log line. If a corpus
//! is not on disk the source is reported absent and cannot be switched on — an
//! honest empty state is worth more than a convincing fake one, because the
//! whole claim being demonstrated is that ULPF handles real vendor output.
//!
//! Streams are plain OS threads rather than tasks: they are long-lived, they do
//! blocking sends, and there are at most a dozen. Each owns a stop flag and a
//! counter, so the console can poll status without taking the pipeline lock.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Same deadline-pacing rationale as `replay.rs`: sleeping per datagram caps a
/// stream near the OS timer granularity, which on Windows is about 1 kHz.
const MIN_SLEEP: Duration = Duration::from_millis(2);

/// One replayable corpus.
///
/// The registry mirrors `tools/measure_coverage.py`, so the sources a judge can
/// switch on are exactly the sources the published coverage table was measured
/// against.
pub struct Source {
    pub id: &'static str,
    pub label: &'static str,
    pub category: &'static str,
    pub origin: &'static str,
    pub file: &'static str,
}

pub const SOURCES: &[Source] = &[
    Source {
        id: "iptables",
        label: "Netfilter / iptables",
        category: "Firewall",
        origin: "Honeynet SotM34",
        file: "iptables.log",
    },
    Source {
        id: "snort",
        label: "Snort IDS",
        category: "IDS",
        origin: "Honeynet SotM34",
        file: "snort.log",
    },
    Source {
        id: "dragon",
        label: "Enterasys Dragon NIDS",
        category: "IDS",
        origin: "Honeynet Dragon",
        file: "dragon-nids.log",
    },
    Source {
        id: "apache",
        label: "Apache access",
        category: "Web",
        origin: "Honeynet SotM34",
        file: "apache-access.log",
    },
    Source {
        id: "apache-err",
        label: "Apache error",
        category: "Web",
        origin: "Loghub",
        file: "Apache_2k.log",
    },
    Source {
        id: "openssh",
        label: "OpenSSH auth",
        category: "Auth",
        origin: "Loghub",
        file: "OpenSSH_2k.log",
    },
    Source {
        id: "linux-hn",
        label: "Linux syslog",
        category: "Host",
        origin: "Honeynet SotM34",
        file: "linux-messages.log",
    },
    Source {
        id: "linux-lh",
        label: "Linux (production)",
        category: "Host",
        origin: "Loghub",
        file: "Linux_2k.log",
    },
    Source {
        id: "sendmail",
        label: "Sendmail MTA",
        category: "Mail",
        origin: "Honeynet SotM34",
        file: "sendmail.log",
    },
    Source {
        id: "proxifier",
        label: "Proxifier",
        category: "Proxy",
        origin: "Loghub",
        file: "Proxifier_2k.log",
    },
];

struct Stream {
    stop: Arc<AtomicBool>,
    sent: Arc<AtomicU64>,
    eps: u64,
    handle: Option<JoinHandle<()>>,
}

pub struct Simulator {
    data_dir: PathBuf,
    target: String,
    streams: HashMap<String, Stream>,
}

impl Simulator {
    pub fn new(data_dir: PathBuf, target: String) -> Self {
        Self {
            data_dir,
            target,
            streams: HashMap::new(),
        }
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    fn path_for(&self, source: &Source) -> PathBuf {
        self.data_dir.join(source.file)
    }

    /// Every registered source with its on-disk state and live counters.
    pub fn status(&self) -> Vec<serde_json::Value> {
        SOURCES
            .iter()
            .map(|source| {
                let path = self.path_for(source);
                let present = path.is_file();
                let bytes = path.metadata().map(|m| m.len()).unwrap_or(0);
                let stream = self.streams.get(source.id);
                serde_json::json!({
                    "id": source.id,
                    "label": source.label,
                    "category": source.category,
                    "origin": source.origin,
                    "file": source.file,
                    "present": present,
                    "bytes": bytes,
                    "running": stream.is_some(),
                    "eps": stream.map(|s| s.eps).unwrap_or(0),
                    "sent": stream.map(|s| s.sent.load(Ordering::Relaxed)).unwrap_or(0),
                })
            })
            .collect()
    }

    pub fn total_sent(&self) -> u64 {
        self.streams
            .values()
            .map(|s| s.sent.load(Ordering::Relaxed))
            .sum()
    }

    pub fn running_count(&self) -> usize {
        self.streams.len()
    }

    /// Turn one stream on. Idempotent: starting a running stream is a no-op, so
    /// a double-click on the switch cannot spawn two senders for one source.
    pub fn start(&mut self, id: &str, eps: u64) -> anyhow::Result<()> {
        if self.streams.contains_key(id) {
            return Ok(());
        }
        let source = SOURCES
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown source: {id}"))?;

        let path = self.path_for(source);
        if !path.is_file() {
            anyhow::bail!(
                "{} is not present. Fetch the corpora first: python tools/fetch_datasets.py",
                source.file
            );
        }

        let lines = read_lines(&path)?;
        if lines.is_empty() {
            anyhow::bail!("{} contains no records", source.file);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicU64::new(0));
        let eps = eps.clamp(1, 200_000);
        let target = self.target.clone();
        let label = source.label;

        let handle = {
            let stop = Arc::clone(&stop);
            let sent = Arc::clone(&sent);
            thread::spawn(move || {
                if let Err(error) = pump(&lines, &target, eps, &stop, &sent) {
                    tracing::warn!("simulator stream '{}' stopped: {}", label, error);
                }
            })
        };

        self.streams.insert(
            id.to_string(),
            Stream {
                stop,
                sent,
                eps,
                handle: Some(handle),
            },
        );
        Ok(())
    }

    pub fn stop(&mut self, id: &str) {
        if let Some(mut stream) = self.streams.remove(id) {
            stream.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = stream.handle.take() {
                let _ = handle.join();
            }
        }
    }

    pub fn set_target(&mut self, new_target: &str) {
        if self.target == new_target {
            return;
        }
        self.target = new_target.to_string();

        let mut running = Vec::new();
        for (id, stream) in &self.streams {
            running.push((id.clone(), stream.eps));
        }

        self.stop_all();

        for (id, eps) in running {
            let _ = self.start(&id, eps);
        }
    }

    pub fn stop_all(&mut self) {
        let ids: Vec<String> = self.streams.keys().cloned().collect();
        for id in ids {
            self.stop(&id);
        }
    }
}

impl Drop for Simulator {
    fn drop(&mut self) {
        self.stop_all();
    }
}

fn read_lines(path: &Path) -> anyhow::Result<Vec<String>> {
    let reader = BufReader::new(File::open(path)?);
    let mut lines = Vec::new();
    for line in reader.lines() {
        // Real captures contain the occasional non-UTF-8 byte. Skipping those
        // records is right for a replay source; the collector's own decoders
        // are what get exercised on the well-formed remainder.
        match line {
            Ok(text) if !text.trim().is_empty() => lines.push(text),
            _ => continue,
        }
    }
    Ok(lines)
}

/// Send `lines` in a loop at `eps`, stopping when the flag is set.
fn pump(
    lines: &[String],
    target: &str,
    eps: u64,
    stop: &AtomicBool,
    sent: &AtomicU64,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let start = Instant::now();
    let interval = Duration::from_nanos(1_000_000_000 / eps.max(1));
    let mut count: u64 = 0;

    while !stop.load(Ordering::Relaxed) {
        let line = &lines[(count as usize) % lines.len()];
        // One unroutable datagram must not take the stream down; the console
        // reports the rate, and a persistent failure shows up as a flat count.
        if socket.send_to(line.as_bytes(), target).is_ok() {
            count += 1;
            sent.store(count, Ordering::Relaxed);
        } else {
            thread::sleep(Duration::from_millis(50));
            continue;
        }

        let deadline_ns = (count as u128) * interval.as_nanos();
        let elapsed_ns = start.elapsed().as_nanos();
        if deadline_ns > elapsed_ns {
            let ahead =
                Duration::from_nanos((deadline_ns - elapsed_ns).min(u64::MAX as u128) as u64);
            if ahead >= MIN_SLEEP {
                // Wake up regularly so a stop request is honoured promptly
                // instead of waiting out a long inter-event gap.
                thread::sleep(ahead.min(Duration::from_millis(200)));
            }
        }
    }
    Ok(())
}
