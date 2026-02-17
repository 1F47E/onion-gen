use crate::onion;
use crossbeam_channel::Sender;
use ed25519_dalek::SigningKey;
use rand::rngs::ThreadRng;
use regex::Regex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// A match result from a worker.
pub struct MatchResult {
    pub signing_key: SigningKey,
    pub onion_address: String,
}

/// Matching strategy — either prefix list or regex list.
#[derive(Clone)]
pub enum Matcher {
    Prefix(Vec<String>),
    Regex(Vec<Regex>),
}

impl Matcher {
    fn is_match(&self, addr: &str) -> bool {
        match self {
            Matcher::Prefix(prefixes) => prefixes.iter().any(|p| addr.starts_with(p.as_str())),
            Matcher::Regex(regexes) => regexes.iter().any(|r| r.is_match(addr)),
        }
    }
}

/// Worker loop: generate keys, check matches, send results.
pub fn worker(
    tx: Sender<MatchResult>,
    stop: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
    matcher: &Matcher,
) {
    let mut rng: ThreadRng = rand::thread_rng();
    let mut local_count: u64 = 0;

    loop {
        if local_count % 4096 == 0 && stop.load(Ordering::Relaxed) {
            break;
        }

        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes: &[u8; 32] = verifying_key.as_bytes();
        let addr = onion::encode_public_key(pubkey_bytes);

        local_count += 1;

        // Batch-update global counter every 8192 iterations to reduce contention
        if local_count % 8192 == 0 {
            attempts.fetch_add(8192, Ordering::Relaxed);
        }

        if matcher.is_match(&addr) {
            // Flush remaining local count
            attempts.fetch_add(local_count % 8192, Ordering::Relaxed);
            local_count = 0;

            let result = MatchResult {
                signing_key,
                onion_address: addr,
            };
            if tx.send(result).is_err() {
                break;
            }
        }
    }

    // Flush any remaining count
    let remainder = local_count % 8192;
    if remainder > 0 {
        attempts.fetch_add(remainder, Ordering::Relaxed);
    }
}
