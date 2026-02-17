mod generator;
mod onion;
mod torkeys;

use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "onion-gen", about = "Vanity v3 .onion address generator")]
struct Cli {
    /// Prefixes (or regexes with --regex) to search for
    prefixes: Vec<String>,

    /// Number of matches to find before stopping
    #[arg(short, long, default_value_t = 1)]
    count: usize,

    /// Number of worker threads (default: num_cpus - 1)
    #[arg(short, long)]
    workers: Option<usize>,

    /// Output directory
    #[arg(short, long, default_value = "./hostnames")]
    output: PathBuf,

    /// Also save Tor-native hs_ed25519_* key files
    #[arg(long)]
    tor_keys: bool,

    /// Treat arguments as regex instead of prefix
    #[arg(long)]
    regex: bool,

    /// Shortcut: search for yppr, ypp, yp
    #[arg(long, conflicts_with = "regex")]
    yapper: bool,

    /// Verbose output (progress stats every 5s)
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    let prefixes: Vec<String> = if cli.yapper {
        vec!["yppr".into(), "ypp".into(), "yp".into()]
    } else if cli.prefixes.is_empty() {
        eprintln!("Error: provide at least one prefix (or use --yapper)");
        std::process::exit(1);
    } else {
        cli.prefixes
    };

    // Validate base32 charset for prefix mode
    if !cli.regex {
        let valid = "abcdefghijklmnopqrstuvwxyz234567";
        for p in &prefixes {
            let lower = p.to_lowercase();
            if let Some(bad) = lower.chars().find(|c| !valid.contains(*c)) {
                eprintln!("Error: prefix '{p}' contains '{bad}' which is not in base32 alphabet (a-z, 2-7)");
                std::process::exit(1);
            }
        }
    }

    if cli.count == 0 {
        eprintln!("Nothing to do (--count 0).");
        return;
    }

    let default_workers = num_cpus::get().saturating_sub(1).max(1);
    let workers = cli.workers.unwrap_or(default_workers);

    eprintln!("Searching for {} match(es) using {workers} workers", cli.count);
    if cli.regex {
        eprintln!("Regex mode: {prefixes:?}");
    } else {
        eprintln!("Prefixes: {prefixes:?}");
    }

    let matcher = if cli.regex {
        generator::Matcher::Regex(
            prefixes
                .iter()
                .map(|p| {
                    regex::Regex::new(p).unwrap_or_else(|e| {
                        eprintln!("Invalid regex '{p}': {e}");
                        std::process::exit(1);
                    })
                })
                .collect(),
        )
    } else {
        generator::Matcher::Prefix(prefixes.iter().map(|p| p.to_lowercase()).collect())
    };

    let stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let (tx, rx) = crossbeam_channel::unbounded();

    // Spawn workers
    let mut handles = Vec::new();
    for _ in 0..workers {
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let attempts = Arc::clone(&attempts);
        let matcher = matcher.clone();
        let handle = std::thread::spawn(move || {
            generator::worker(tx, stop, attempts, &matcher);
        });
        handles.push(handle);
    }
    drop(tx);

    // Progress reporter
    let verbose = cli.verbose;
    let stop_progress = Arc::clone(&stop);
    let attempts_progress = Arc::clone(&attempts);
    let progress_handle = std::thread::spawn(move || {
        let start = Instant::now();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            if stop_progress.load(Ordering::Relaxed) {
                break;
            }
            let total = attempts_progress.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let rate = total as f64 / elapsed;
            if verbose {
                eprintln!("[progress] {total} attempts, {rate:.0}/sec, {elapsed:.1}s elapsed");
            }
        }
    });

    // Collect results
    let start = Instant::now();
    let mut found = 0;
    for result in &rx {
        found += 1;
        eprintln!("[{found}/{}] Found: {}.onion", cli.count, result.onion_address);

        if let Err(e) = torkeys::save_keys(&cli.output, &result, cli.tor_keys) {
            eprintln!("Error saving keys: {e}");
        }

        if found >= cli.count {
            stop.store(true, Ordering::Relaxed);
            break;
        }
    }

    // Wait for workers to finish
    for h in handles {
        let _ = h.join();
    }
    let _ = progress_handle.join();

    let total = attempts.load(Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();
    eprintln!("Done. {found} match(es) in {elapsed:.1}s ({total} attempts, {:.0}/sec)", total as f64 / elapsed);
}
