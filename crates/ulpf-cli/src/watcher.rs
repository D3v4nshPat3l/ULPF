use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use notify::{Event, RecursiveMode, Watcher};
use ulpf_pack::PackLibrary;

/// Spawns a background thread to watch the packs directory.
/// Recompiles packs on change and updates the shared library lock.
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
        notify::Config::default().with_poll_interval(Duration::from_secs(1)),
    )?;

    watcher.watch(&packs_dir, RecursiveMode::Recursive)?;

    std::thread::spawn(move || {
        let _watcher = watcher;
        let mut last_reload = std::time::Instant::now();

        for event in rx {
            if last_reload.elapsed() < Duration::from_millis(500) {
                continue;
            }

            match event.kind {
                notify::EventKind::Modify(_)
                | notify::EventKind::Create(_)
                | notify::EventKind::Remove(_) => {
                    tracing::info!("pack file changed, recompiling library...");
                    match PackLibrary::load_dir(&packs_dir) {
                        Ok((library, errors)) => {
                            for (path, err) in &errors {
                                tracing::error!(path = %path.display(), %err, "pack failed to load during reload");
                            }
                            if !library.is_empty() {
                                if let Ok(mut lock) = shared_packs.write() {
                                    *lock = Arc::new(library);
                                    tracing::info!("packs reloaded successfully");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(%e, "failed to reload pack library");
                        }
                    }
                    last_reload = std::time::Instant::now();
                }
                _ => {}
            }
        }
    });

    Ok(())
}
