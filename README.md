# onion-gen

<img src="assets/banner.jpg" width="600px">

Vanity v3 .onion address generator. Multi-threaded ed25519 keygen in Rust with prefix/regex matching. Outputs Tor-native key files ready to drop into a hidden service directory.

## Install

```bash
git clone https://github.com/1F47E/onion-gen.git
cd onion-gen
cargo build --release
```

## Usage

```bash
# Find address starting with "yp"
onion-gen yp

# Multiple prefixes, find 5 matches
onion-gen --count 5 yppr ypp yp

# Save Tor-native hs_ed25519_* key files
onion-gen --tor-keys yppr

# Regex mode
onion-gen --regex "^yp[a-z]r"

# Control worker threads (default: num_cpus - 1)
onion-gen --workers 8 yppr
```

## Output

Each match saves to `./hostnames/<address>/`:

```
hostnames/
└── ypprwxvh...faid/
    ├── hostname              # ypprwxvh...faid.onion
    ├── private_key           # 64-byte ed25519 key (seed + pubkey)
    ├── hs_ed25519_secret_key # Tor-native secret key (with --tor-keys)
    └── hs_ed25519_public_key # Tor-native public key (with --tor-keys)
```

Drop the `hs_ed25519_*` files + `hostname` into your Tor hidden service directory and restart Tor.

## Performance

| Machine | Cores | Workers | Keys/sec |
|---------|-------|---------|----------|
| Apple M1 Pro | 10 | 9 | ~51K |
| Hetzner AX41 (AMD) | 24 | 23 | ~365K |

## Base32 note

Onion addresses use base32: `a-z` + `2-7`. No `0`, `1`, `8`, `9`.
