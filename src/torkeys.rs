use crate::generator::MatchResult;
use sha2::{Digest, Sha512};
use std::fs;
use std::io;
use std::path::Path;

/// Save keys for a matched onion address.
///
/// Always saves:
///   - `hostname` — the .onion address
///   - `private_key` — raw 64-byte ed25519 signing key (seed + public)
///
/// With `tor_keys = true`, also saves Tor-native format:
///   - `hs_ed25519_secret_key` — Tor header + expanded secret key
///   - `hs_ed25519_public_key` — Tor header + public key
pub fn save_keys(output_dir: &Path, result: &MatchResult, tor_keys: bool) -> io::Result<()> {
    let dir = output_dir.join(&result.onion_address);
    fs::create_dir_all(&dir)?;

    // hostname
    fs::write(
        dir.join("hostname"),
        format!("{}.onion\n", result.onion_address),
    )?;

    // private_key — raw ed25519 keypair bytes (seed || public)
    let seed = result.signing_key.to_bytes();
    let pubkey = result.signing_key.verifying_key().to_bytes();
    let mut raw_key = Vec::with_capacity(64);
    raw_key.extend_from_slice(&seed);
    raw_key.extend_from_slice(&pubkey);
    fs::write(dir.join("private_key"), &raw_key)?;

    if tor_keys {
        save_tor_keys(&dir, &seed, &pubkey)?;
    }

    Ok(())
}

/// Save Tor-native hidden service key files.
///
/// hs_ed25519_secret_key format:
///   - 29 bytes: "== ed25519v1-secret: type0 ==\x00\x00\x00"
///   - 64 bytes: expanded secret key (SHA-512 of seed, clamped)
///
/// hs_ed25519_public_key format:
///   - 29 bytes: "== ed25519v1-public: type0 ==\x00\x00\x00"
///   - 32 bytes: public key
fn save_tor_keys(dir: &Path, seed: &[u8; 32], pubkey: &[u8; 32]) -> io::Result<()> {
    // Expand secret key: SHA-512 of seed, then clamp
    let mut expanded = {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let hash: [u8; 64] = hasher.finalize().into();
        hash
    };
    // Clamp per ed25519 spec
    expanded[0] &= 248;
    expanded[31] &= 63;
    expanded[31] |= 64;

    // hs_ed25519_secret_key
    let secret_header = b"== ed25519v1-secret: type0 ==\x00\x00\x00";
    let mut secret_file = Vec::with_capacity(96);
    secret_file.extend_from_slice(secret_header);
    secret_file.extend_from_slice(&expanded);
    fs::write(dir.join("hs_ed25519_secret_key"), &secret_file)?;

    // hs_ed25519_public_key
    let public_header = b"== ed25519v1-public: type0 ==\x00\x00\x00";
    let mut public_file = Vec::with_capacity(64);
    public_file.extend_from_slice(public_header);
    public_file.extend_from_slice(pubkey);
    fs::write(dir.join("hs_ed25519_public_key"), &public_file)?;

    Ok(())
}
