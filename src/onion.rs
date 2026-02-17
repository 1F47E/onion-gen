use data_encoding::BASE32;
use sha3::{Digest, Sha3_256};

/// Encode an ed25519 public key into a v3 .onion address (56 lowercase chars).
///
/// Format: base32(pubkey || checksum[:2] || version)
/// Where checksum = SHA3-256(".onion checksum" || pubkey || version)
pub fn encode_public_key(pubkey: &[u8; 32]) -> String {
    // checksum = SHA3-256(".onion checksum" || pubkey || 0x03)
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let checksum = hasher.finalize();

    // onion_address = base32(pubkey || checksum[:2] || version)
    let mut addr_bytes = Vec::with_capacity(35);
    addr_bytes.extend_from_slice(pubkey);
    addr_bytes.push(checksum[0]);
    addr_bytes.push(checksum[1]);
    addr_bytes.push(0x03);

    BASE32.encode(&addr_bytes).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_produces_56_chars() {
        let pubkey = [0u8; 32];
        let addr = encode_public_key(&pubkey);
        assert_eq!(addr.len(), 56);
    }

    #[test]
    fn test_encode_is_lowercase_base32() {
        let pubkey = [0xAB; 32];
        let addr = encode_public_key(&pubkey);
        assert!(addr.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')));
    }

    #[test]
    fn test_encode_deterministic() {
        let pubkey = [42u8; 32];
        let a = encode_public_key(&pubkey);
        let b = encode_public_key(&pubkey);
        assert_eq!(a, b);
    }
}
