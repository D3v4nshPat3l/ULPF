//! Hot reload: recompile the Source Pack library when the directory changes.
//!
//! This is requirement (e) — onboarding a device is dropping a file into a
//! folder, with no restart and no rebuild — and it is also the last step of
//! the console's approve flow, which writes the approved pack into that same
//! directory and expects it to start claiming traffic.
//!
//! # The debounce that ate the events
//!
//! An earlier version kept `last_reload` and skipped any event arriving
//! within 500 ms of it. The intent was to collapse the burst of events a
//! single save produces. What it actually did was drop reloads on the two
//! cases that matter most:
//!
//! * A file being *written* generates several events a few hundred
//!   microseconds apart. The first one triggered a reload and set
//!   `last_reload`; every later one in that burst was then inside the window
//!   and discarded — including, on Windows, the event that fires once the
//!   contents are actually on disk. `load_dir` therefore ran against a file
//!   that existed but was still empty or half-written, that file failed to
//!   parse, and the library swapped in without it. The pack count never
//!   moved and nothing said why.
//! * The same burst behaviour meant a freshly *created* pack — exactly what
//!   `/api/approve` writes — was routinely read before it was complete.
//!
//! Measured on this machine before the change: adding a pack file did not
//! reload, editing one did not reload, and deleting one did, because a delete
//! is a single event with nothing left to read.
//!
//! # What it does now
//!
//! Coalesce rather than discard. Any relevant event marks the library dirty;
//! the loop then waits for the directory to go quiet for `SETTLE` before
//! reloading once. A burst of twenty events produces one reload, and that
//! reload happens *after* the writer has finished, which is the property the
//! old version was missing.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use notify::{Event, RecursiveMode, Watcher};
use ulpf_pack::PackLibrary;

/// Quiet period the directory must show before a reload is attempted.
///
/// Long enough that a multi-event save has finished landing, short enough
/// that an operator who just approved a pack sees it take effect while still
/// looking at the screen.
const SETTLE: Duration = Duration::from_millis(400);

/// Whether an event could plausibly change the set of packs on disk.
///
/// Deliberately permissive. Different platforms describe the same save with
/// different event kinds, and the cost of reloading once too often is a few
/// milliseconds of parsing, while the cost of ignoring a real change is a
/// pack the operator believes is live and is not.
fn is_relevant(event: &Event) -> bool {
    use notify::EventKind;
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) | EventKind::Any
    )
}

/// Watch `packs_dir` and swap a freshly compiled library into `shared_packs`.
pub fn spawn_pack_watcher(
    packs_dir: PathBuf,
    shared_packs: Arc<RwLock<Arc<PackLibrary>>>,
) -> anyhow::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher = notify::RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        notify::Config::default(),
    )?;

    // Non-recursive, matching `PackLibrary::load_dir`, which reads only the
    // files directly in this directory. Watching recursively while loading
    // flat meant a pack dropped in a subfolder triggered a reload that then
    // did not include it — a reload that reports success and changes nothing.
    watcher.watch(&packs_dir, RecursiveMode::NonRecursive)?;

    std::thread::spawn(move || {
        let _watcher = watcher;
        loop {
            // Block until something happens, then drain whatever else arrives
            // until the directory is quiet. One save, one reload.
            let Ok(first) = rx.recv() else {
                return; // sender dropped: the collector is shutting down
            };
            let mut dirty = is_relevant(&first);
            while let Ok(event) = rx.recv_timeout(SETTLE) {
                dirty |= is_relevant(&event);
            }
            if !dirty {
                continue;
            }

            match PackLibrary::load_dir(&packs_dir) {
                Ok((library, errors)) => {
                    for (path, error) in &errors {
                        tracing::error!(
                            path = %path.display(),
                            %error,
                            "pack failed to load during reload; keeping the rest"
                        );
                    }
                    // A directory that momentarily reads as empty — an editor
                    // replacing a file, a delete mid-batch — must not blank
                    // the collector.
                    if library.is_empty() {
                        tracing::warn!(
                            "pack directory reloaded to zero usable packs; keeping the previous library"
                        );
                        continue;
                    }
                    let count = library.len();
                    match shared_packs.write() {
                        Ok(mut lock) => {
                            *lock = Arc::new(library);
                            tracing::info!(packs = count, "Source Packs reloaded");
                        }
                        Err(_) => tracing::error!("pack library lock is poisoned; not reloading"),
                    }
                }
                Err(error) => tracing::error!(%error, "failed to reload the pack library"),
            }
        }
    });

    Ok(())
}
