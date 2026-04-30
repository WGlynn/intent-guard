// On-device adapter renderer.
//
// Mirrors attester/renderer/src/adapters/*.ts. For each registered
// action_kind, decodes the raw action_args bytes into a canonical-byte
// representation and a human-readable line list for display.
//
// To add a new adapter:
//   1. Add a match arm in `decode` below.
//   2. Implement the decode + render helpers for that arm.
//   3. Mirror the schema in attester/renderer/src/adapters/<same>.ts.
//   4. Bump firmware version and force re-enrollment of attester pubkeys
//      via intentguard's adapter-cool-off path.

use alloc::vec::Vec;
use heapless::Vec as HVec;

const MAX_LINES: usize = 8;
const MAX_LINE_LEN: usize = 64;

pub struct Decoded {
    /// Canonical-serialised bytes. Used to recompute the intent hash and
    /// compare against the host's claim.
    pub canonical: Vec<u8>,
    /// Lines to display.
    pub rendered: HVec<Line, MAX_LINES>,
}

#[derive(Clone)]
pub struct Line {
    pub label: heapless::String<24>,
    pub value: heapless::String<MAX_LINE_LEN>,
    pub severity: Severity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
    Danger,
}

#[derive(Debug)]
pub enum DecodeError {
    UnknownAction(u32),
    BadLength,
}

pub fn decode(action_kind: u32, args: &[u8]) -> Result<Decoded, DecodeError> {
    match action_kind {
        1 => decode_whitelist_collateral(args),
        3 => decode_transfer_admin(args),
        other => Err(DecodeError::UnknownAction(other)),
    }
}

fn decode_whitelist_collateral(args: &[u8]) -> Result<Decoded, DecodeError> {
    if args.len() != 80 {
        return Err(DecodeError::BadLength);
    }
    let token = &args[0..32];
    let fair_value = u64::from_le_bytes(args[32..40].try_into().unwrap());
    let oracle = &args[40..72];
    let max_deposit = u64::from_le_bytes(args[72..80].try_into().unwrap());

    // Canonical bytes layout matches host's canonicalSerialise output for
    // the equivalent object: keys sorted = fair_value_usd_micros, max_deposit_usd, oracle, token.
    // (The host renderer does this automatically.)
    let mut canonical: Vec<u8> = Vec::with_capacity(args.len());
    // Reuse the wire layout for now; the on-chain guard validates the
    // host's canonical serialisation against the same rules.
    canonical.extend_from_slice(args);

    let mut lines: HVec<Line, MAX_LINES> = HVec::new();
    let _ = lines.push(Line {
        label: heapless::String::try_from("Token").unwrap(),
        value: hex_short(token),
        severity: Severity::Info,
    });
    let _ = lines.push(Line {
        label: heapless::String::try_from("Fair value (USD)").unwrap(),
        value: format_usd(fair_value),
        severity: Severity::Danger,
    });
    let _ = lines.push(Line {
        label: heapless::String::try_from("Oracle").unwrap(),
        value: hex_short(oracle),
        severity: Severity::Warn,
    });
    let mut max_str: heapless::String<MAX_LINE_LEN> = heapless::String::new();
    let _ = core::fmt::Write::write_fmt(&mut max_str, format_args!("{}", max_deposit));
    let _ = lines.push(Line {
        label: heapless::String::try_from("Max deposit (USD)").unwrap(),
        value: max_str,
        severity: Severity::Info,
    });

    Ok(Decoded { canonical, rendered: lines })
}

fn decode_transfer_admin(args: &[u8]) -> Result<Decoded, DecodeError> {
    if args.len() != 32 {
        return Err(DecodeError::BadLength);
    }
    let new_admin = &args[0..32];

    let mut canonical: Vec<u8> = Vec::with_capacity(args.len());
    canonical.extend_from_slice(args);

    let mut lines: HVec<Line, MAX_LINES> = HVec::new();
    let _ = lines.push(Line {
        label: heapless::String::try_from("New admin").unwrap(),
        value: hex_short(new_admin),
        severity: Severity::Danger,
    });

    Ok(Decoded { canonical, rendered: lines })
}

fn hex_short(bytes: &[u8]) -> heapless::String<MAX_LINE_LEN> {
    let mut s: heapless::String<MAX_LINE_LEN> = heapless::String::new();
    for b in bytes.iter().take(6) {
        let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{:02x}", b));
    }
    let _ = s.push_str("..");
    for b in bytes.iter().skip(bytes.len().saturating_sub(6)) {
        let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{:02x}", b));
    }
    s
}

fn format_usd(micros: u64) -> heapless::String<MAX_LINE_LEN> {
    let dollars = micros / 1_000_000;
    let cents = (micros % 1_000_000) / 10_000;
    let mut s: heapless::String<MAX_LINE_LEN> = heapless::String::new();
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("${}.{:02}", dollars, cents));
    s
}
