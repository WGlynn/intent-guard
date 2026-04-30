// Protocol message types matching attester/SPEC.md §4.
//
// On-the-wire encoding is CBOR (subset). The minicbor crate handles
// the encode/decode in transport.rs; this file just defines the message
// shapes the rest of the firmware works with.

use alloc::vec::Vec;
use crate::crypto::Network;

#[derive(Debug)]
pub enum Message<'a> {
    // host -> device
    Hello,
    Enroll,
    ProposeIntent(ProposeIntent<'a>),
    Status,

    // device -> host
    HelloAck {
        firmware_ver: &'static str,
        curves: &'static str,
        device_pubkey: [u8; 32],
    },
    EnrollAck {
        device_pubkey: [u8; 32],
    },
    IntentAck {
        proposal_id: [u8; 16],
        signature: [u8; 64],
        device_pubkey: [u8; 32],
        signed_at: u64,
        firmware_ver: &'static str,
    },
    IntentReject {
        proposal_id: [u8; 16],
        reason: &'static str,
    },
}

#[derive(Debug)]
pub struct ProposeIntent<'a> {
    pub proposal_id: [u8; 16],
    pub network: Network,
    pub vault: Vec<u8>,
    pub nonce: u64,
    pub action_kind: u32,
    pub action_args: &'a [u8],
    pub intent_hash: [u8; 32],
    pub signed_at: u64,
    pub expires_at: u64,
}
