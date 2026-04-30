// intentguard-attester firmware
//
// Reference build for the M5Stack Cardputer (ESP32-S3, 240x135 IPS, USB-C,
// 56-key + scroll wheel + side button). The firmware exposes USB CDC for
// host communication, owns its own ed25519 keypair stored in encrypted
// flash, and renders incoming intent payloads on its display before
// signing.
//
// STATUS: structurally complete. The crypto + protocol + state-machine
// layers compile and have been exercised in the host emulator. The
// hardware-touching layers (display, buttons, secure flash region) are
// stubbed against esp-hal types and need real-board testing.
//
// READ THIS FIRST: SPEC.md and THREAT_MODEL.md in the parent directory.

#![cfg_attr(not(feature = "target-host-emulator"), no_std)]
#![cfg_attr(not(feature = "target-host-emulator"), no_main)]

extern crate alloc;

#[cfg(not(feature = "target-host-emulator"))]
use esp_backtrace as _;

mod crypto;
mod protocol;
mod render;
mod store;
mod transport;
mod ui;

use protocol::{Message, ProposeIntent};

/// Maximum action_args size we'll accept. Larger payloads are rejected.
const MAX_ACTION_ARGS: usize = 1024;

/// How many recent proposal_ids to remember to defeat replays.
const REPLAY_WINDOW: usize = 64;

#[cfg_attr(not(feature = "target-host-emulator"), esp_hal::main)]
fn main() -> ! {
    // 1. Hardware init.
    let mut hw = ui::Hardware::init();
    let mut store = store::Store::open();
    let mut transport = transport::UsbCdc::open();

    // 2. Ensure we have a signing keypair. First boot generates and locks it.
    let keypair = store.load_or_generate_keypair(&mut hw.rng);

    // 3. Render boot screen.
    hw.display.show_boot(&keypair.public_key_short());

    // 4. Main loop.
    let mut replay_cache: heapless::Deque<[u8; 16], REPLAY_WINDOW> = heapless::Deque::new();
    loop {
        let msg = match transport.recv() {
            Ok(m) => m,
            Err(_) => continue,
        };
        match msg {
            Message::Hello => {
                let _ = transport.send(Message::HelloAck {
                    firmware_ver: env!("CARGO_PKG_VERSION"),
                    curves: "ed25519",
                    device_pubkey: keypair.public_key(),
                });
            }
            Message::Enroll => {
                hw.display.show_enrollment(&keypair.public_key_short());
                let _ = transport.send(Message::EnrollAck {
                    device_pubkey: keypair.public_key(),
                });
            }
            Message::ProposeIntent(p) => {
                handle_propose(&p, &keypair, &mut hw, &mut transport, &mut replay_cache);
            }
            _ => {
                // Unknown messages are silently dropped to avoid leaking state.
            }
        }
    }
}

fn handle_propose(
    p: &ProposeIntent,
    keypair: &crypto::Keypair,
    hw: &mut ui::Hardware,
    transport: &mut transport::UsbCdc,
    replay_cache: &mut heapless::Deque<[u8; 16], REPLAY_WINDOW>,
) {
    // Replay check.
    if replay_cache.iter().any(|id| id == &p.proposal_id) {
        let _ = transport.send(Message::IntentReject {
            proposal_id: p.proposal_id,
            reason: "Replay",
        });
        return;
    }

    // Size guard.
    if p.action_args.len() > MAX_ACTION_ARGS {
        let _ = transport.send(Message::IntentReject {
            proposal_id: p.proposal_id,
            reason: "ArgsTooLarge",
        });
        return;
    }

    // Decode using on-device adapter; recompute the canonical intent hash.
    let decoded = match render::decode(p.action_kind, p.action_args) {
        Ok(d) => d,
        Err(_) => {
            let _ = transport.send(Message::IntentReject {
                proposal_id: p.proposal_id,
                reason: "DecodeFailure",
            });
            return;
        }
    };
    let recomputed = crypto::canonical_intent_hash(
        p.network,
        &p.vault,
        p.nonce,
        p.action_kind,
        &decoded.canonical,
    );
    if recomputed != p.intent_hash {
        // The host's intent hash and our recomputation disagree. This is
        // the critical attack-detection branch: it means the host is either
        // buggy or lying about what we're about to sign.
        let _ = transport.send(Message::IntentReject {
            proposal_id: p.proposal_id,
            reason: "IntentMismatch",
        });
        return;
    }

    // Render on screen and wait for confirmation.
    hw.display.show_intent(&decoded.rendered);
    let confirmed = hw.buttons.wait_for_confirm_or_cancel(60_000);

    if !confirmed {
        let _ = transport.send(Message::IntentReject {
            proposal_id: p.proposal_id,
            reason: "UserCancelled",
        });
        return;
    }

    // Build the digest and sign.
    let signed_at = hw.clock.now_seconds();
    let digest = crypto::attest_digest(
        &p.vault,
        p.nonce,
        p.action_kind,
        &p.intent_hash,
        signed_at,
        p.network,
    );
    let sig = keypair.sign(&digest);

    // Update replay cache.
    if replay_cache.is_full() {
        let _ = replay_cache.pop_front();
    }
    let _ = replay_cache.push_back(p.proposal_id);

    let _ = transport.send(Message::IntentAck {
        proposal_id: p.proposal_id,
        signature: sig,
        device_pubkey: keypair.public_key(),
        signed_at,
        firmware_ver: env!("CARGO_PKG_VERSION"),
    });

    hw.display.show_complete();
}
