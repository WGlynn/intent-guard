// Crypto layer for the attester firmware.
//
// - Ed25519 for Solana network attestations.
// - secp256k1 for EVM (sketched; the on-device variant is more involved
//   because k256 RFC6979 is heavier and the Cardputer's flash is tight).
// - SHA-256 for Solana digests, Keccak-256 for EVM digests.
//
// All algorithms are constant-time (ed25519-dalek, k256). Key generation
// uses the platform RNG passed in by `store.rs`.

use alloc::vec::Vec;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// What Solana | EVM the attester should sign for. The on-device adapter
/// renderer is the same; only the digest hash differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Solana,
    Evm,
}

impl Network {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "solana" => Some(Network::Solana),
            "evm" => Some(Network::Evm),
            _ => None,
        }
    }
}

/// Wraps the on-device signing key. The private bytes never leave this struct.
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Short representation for display; first 4 + last 4 bytes hex.
    pub fn public_key_short(&self) -> heapless::String<24> {
        let pk = self.public_key();
        let mut s: heapless::String<24> = heapless::String::new();
        for b in pk.iter().take(4) {
            let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{:02x}", b));
        }
        let _ = s.push_str("..");
        for b in pk.iter().skip(28) {
            let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{:02x}", b));
        }
        s
    }

    pub fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.signing.sign(digest).to_bytes()
    }
}

const DOMAIN_SEP: &[u8] = b"intentguard.v1.attest";

/// Recompute the canonical intent hash on-device. Must match the host
/// renderer's `computeIntentHash` byte-for-byte.
pub fn canonical_intent_hash(
    network: Network,
    vault: &[u8],
    nonce: u64,
    action_kind: u32,
    canonical_args: &[u8],
) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(DOMAIN_SEP.len() + vault.len() + 12 + canonical_args.len());
    buf.extend_from_slice(DOMAIN_SEP);
    buf.extend_from_slice(vault);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&action_kind.to_le_bytes());
    buf.extend_from_slice(canonical_args);
    match network {
        Network::Solana => {
            let mut h = Sha256::new();
            h.update(&buf);
            let out = h.finalize();
            let mut r = [0u8; 32];
            r.copy_from_slice(&out);
            r
        }
        Network::Evm => {
            let mut h = Keccak256::new();
            h.update(&buf);
            let out = h.finalize();
            let mut r = [0u8; 32];
            r.copy_from_slice(&out);
            r
        }
    }
}

/// Build the digest the attester signs.
pub fn attest_digest(
    vault: &[u8],
    nonce: u64,
    action_kind: u32,
    intent_hash: &[u8; 32],
    signed_at: u64,
    network: Network,
) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(DOMAIN_SEP.len() + vault.len() + 8 + 4 + 32 + 8);
    buf.extend_from_slice(DOMAIN_SEP);
    buf.extend_from_slice(vault);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&action_kind.to_le_bytes());
    buf.extend_from_slice(intent_hash);
    buf.extend_from_slice(&signed_at.to_le_bytes());
    match network {
        Network::Solana => {
            let out = Sha256::digest(&buf);
            let mut r = [0u8; 32];
            r.copy_from_slice(&out);
            r
        }
        Network::Evm => {
            let out = Keccak256::digest(&buf);
            let mut r = [0u8; 32];
            r.copy_from_slice(&out);
            r
        }
    }
}
