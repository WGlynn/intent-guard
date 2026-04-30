# attester: Specification

Version: 0.1 (draft)
Status: Reference protocol open for review
Audience: Firmware engineers, intentguard integrators, security reviewers

---

## 1. Goals

The attester is a hardware co-signer that operates in a separate trust domain from the council member's laptop and wallet. It receives a structured intent payload, decodes it on-device using a vendor-neutral renderer, displays the human-readable intent on its own screen, requires a physical button press, and returns a signature over `H(intent_hash || metadata)` so that `intentguard` (or any compatible guard) can require both signatures.

If the laptop's wallet UI lies about what the user is signing, the device's screen tells the truth. The user has to compare them. The on-chain guard requires both sigs.

This document specifies:
- the wire protocol between host and device,
- the canonical payload format,
- the signature scheme for Solana and EVM,
- the enrollment / pubkey distribution flow,
- the intentguard integration semantics.

It does not specify hardware (see `BUILD.md`) or specific renderer adapters (see `renderer/src/adapters/`).

## 2. Trust model

The device trusts:
- its own firmware (signed at build, verified at boot),
- its own renderer (compiled into firmware),
- the human pressing its physical button.

The device does NOT trust:
- the host laptop,
- the host's wallet UI,
- the host's RPC endpoint,
- the host's clock (the device has its own monotonic counter and accepts a `signed_at` advisory only),
- the network (USB CDC is the primary transport; even BLE traffic is treated as untrusted).

The host laptop receives the device's signature and is responsible for:
- bundling it into the `intentguard.attest` call,
- not modifying it (any modification breaks the signature),
- displaying confirmation that the device responded.

## 3. Transport

**Primary: USB CDC (serial-over-USB).** Standard, no drivers on macOS or Linux, works on Windows with the built-in `usbser.sys`. Baud rate is meaningless for USB CDC but conventionally 115200 for tooling compatibility.

**Optional: Bluetooth Low Energy (GATT).** Useful for attesters that should not be physically tethered (treasury sign-offs from a separate room). BLE expands the attack surface significantly: pairing must be out-of-band, every message must be authenticated under a session key derived from a previously-enrolled shared secret, and the device must rate-limit connections. BLE is OPTIONAL in v0.1; firmware MAY omit it.

**Framing.** Each message is a length-prefixed CBOR map. Frame:

```
| 0xA7 0x77 | u16 length BE | CBOR payload | u32 CRC32 BE |
```

The magic bytes `0xA7 0x77` ("Aw" for "attester wire") let the device discard noise. The length is the byte count of the CBOR payload. CRC32 is over the magic + length + CBOR payload.

CBOR was chosen over JSON because (a) it's binary-stable across implementations, (b) embedded Rust has a no_std CBOR implementation (`minicbor`), and (c) it's the same format `cose-rs` uses for COSE signatures, which simplifies later interop.

## 4. Message types

Every message has a `type` field. Defined types in v0.1:

- `Hello` (host → device): probe; device responds with `HelloAck` containing firmware version, supported curve(s), pubkey identifier, and free RAM.
- `Enroll` (host → device): one-time, generates a new keypair if no key is present, returns the public key. Idempotent on second call.
- `ProposeIntent` (host → device): the main flow. Carries the intent payload to render and the metadata to sign over.
- `IntentAck` (device → host): contains the signature, `signed_at` timestamp from the device's own counter, and the firmware version.
- `IntentReject` (device → host): the user pressed CANCEL, or the renderer failed to decode, or the proposal was malformed. Includes a reason code.
- `Status` (host → device): poll display state, last-seen proposal id, etc.

### 4.1 ProposeIntent payload

```cbor
{
  type:         "ProposeIntent",
  proposal_id:  bstr (16 bytes, host-chosen, used to dedupe replays on-device),
  network:      "solana" | "evm",
  vault:        bstr (32 bytes for Solana pubkey, 20 bytes for EVM address),
  nonce:        u64,
  action_kind:  u32,
  action_args:  bstr (raw, length-prefixed; passed to the on-device adapter for that action_kind),
  intent_hash:  bstr (32 bytes; host's claimed canonical intent hash),
  signed_at:    u64 (host wall clock; advisory),
  expires_at:   u64 (host wall clock; advisory),
  domain_sep:   "intentguard.v1.attest",
}
```

The device:
1. Verifies `proposal_id` has not been seen recently (the device keeps the last 64 proposal_ids in RAM and rejects duplicates).
2. Looks up the on-device adapter for `action_kind`. If none, rejects with `UnknownActionKind`.
3. Calls the adapter on `action_args`. If decoding fails, rejects with `DecodeFailure`.
4. Recomputes `intent_hash_computed = H(domain_sep || vault || nonce || action_kind || canonical(action_args))` using the device's own SHA-256 / Keccak. If `intent_hash_computed != intent_hash`, rejects with `IntentMismatch`. **This is the critical check.** It means the host cannot trick the device into displaying intent A while the host signs intent B.
5. Renders the decoded intent on the screen as one or more lines.
6. Waits for the human to press CONFIRM (within `CONFIRM_TIMEOUT_SECS`, default 60).
7. If confirmed, produces a signature (see §5).
8. Returns `IntentAck` containing the signature.

If the user presses CANCEL, returns `IntentReject` with reason `UserCancelled`.

### 4.2 IntentAck payload

```cbor
{
  type:         "IntentAck",
  proposal_id:  bstr,
  signature:    bstr (64 bytes for Ed25519, 65 bytes for secp256k1 with v),
  device_pubkey: bstr,
  signed_at:    u64 (device's own monotonic counter, NOT host time),
  firmware_ver: tstr,
}
```

The signature is over the digest defined in §5.

## 5. Signature scheme

The signed digest is:

```
digest = H(
    "intentguard.v1.attest" ||      // domain separator
    vault ||                         // 32 or 20 bytes
    u64_le(nonce) ||
    u32_le(action_kind) ||
    intent_hash ||                   // 32 bytes
    u64_le(signed_at)                // device's own clock
)
```

`H` is SHA-256 for Solana, Keccak-256 for EVM. The choice of `H` matches the host chain's native hash so that the on-chain verifier can recompute the digest with cheap built-in opcodes.

The digest is then signed:

- **Solana:** Ed25519 over `digest`. The device pubkey is a 32-byte Ed25519 public key. Verification on-chain uses `ed25519_program` (`Ed25519SigVerify` precompile).
- **EVM:** ECDSA secp256k1 over `digest`. The device pubkey is identified by its 20-byte Ethereum address. Verification on-chain uses `ecrecover`.

A device MAY support both curves and store both keys in the same flash partition; queries via `Hello` indicate which is enrolled.

## 6. Key management

### 6.1 Generation

On first boot (or on `Enroll` if no key is present), the device generates a fresh keypair using its onboard hardware RNG. The private key is stored in the device's encrypted flash region. The public key is returned in the `EnrollAck` and is what the protocol enrolls into the intentguard vault.

### 6.2 No export, ever

The private key cannot be exported. There is no firmware command for this. The flash region is locked at first-write so that even a firmware update preserving compatibility cannot re-read the key. Firmware updates that must rotate the key require the user to re-enroll.

### 6.3 Backup is by re-enrollment

Conventional hardware wallet recovery via seed phrase is *not* supported in v0.1. The threat model treats the attester as a stateless second-domain witness, not a custody device: if you lose it, you enroll a new one and the old pubkey is removed from the vault by the standard intentguard cool-off path. This is intentional. A seed-phrase-restorable attester reintroduces the laptop as the trust root.

### 6.4 Multiple attesters per signer

A council member MAY enroll multiple attester devices for redundancy (e.g., one in the office, one at home). Each is a separate pubkey in the vault. The intentguard config decides whether *any* enrolled attester for a signer is sufficient or whether *all* are required.

## 7. Intentguard integration

The intentguard vault gains a per-signer attester pubkey list:

```rust
pub struct SignerEntry {
    pub signer:        Pubkey,
    pub attesters:     Vec<Pubkey>,    // 1..=4 enrolled devices
    pub require_all:   bool,           // false = any attester suffices
}
```

The `attest` instruction now accepts an additional `attester_signatures: Vec<AttesterSig>` parameter and:

1. Verifies the signer's normal signature (unchanged).
2. For each attester sig, recomputes the digest from §5 using the *proposal's* values.
3. Verifies each attester sig against the corresponding enrolled attester pubkey.
4. Checks that the count of valid attester sigs satisfies the `require_all` policy.
5. Only then counts the attestation toward quorum.

A proposal cannot reach `Queued` state without sufficient attester signatures. The freshness window applies to the attester's `signed_at` field as well.

### 7.1 Migration from intentguard v0.1 to v0.2

Vaults can be configured with an empty `attesters` vector per signer, in which case the attester check is a no-op for that signer. This allows a phased rollout where some signers have devices and some don't, before mandating attesters everywhere.

## 8. Enrollment flow

```
1. Host calls device.Enroll() over USB.
2. Device generates keypair (or returns existing pubkey).
3. Host displays the device pubkey to the council member.
4. Council member compares the displayed pubkey against the value the device shows on its own screen.
5. If they match, the council submits an `EnrollAttester` proposal to intentguard,
   which itself goes through the standard cool-off + veto path
   (preventing a malicious laptop from enrolling its own software-defined "attester").
6. After the cool-off, the attester is active for that signer.
```

Step 4 is the critical anti-spoof step. The host cannot lie about the device's pubkey because the device displays it directly.

Step 5 is what prevents the obvious attack: a compromised laptop "enrolling" a phantom attester whose signing key it controls. The enrollment itself goes through intentguard, and the attester is expected to sign its own enrollment proposal. Bootstrap chicken-and-egg is broken by the council's first-time enrollment ceremony, in which the bootstrap attester is set under a higher-than-normal cool-off (default 7 days).

## 9. Threat model summary

Defended:
- Compromised host wallet UI displays falsified intent.
- Compromised host RPC returns falsified state.
- Pre-signed durable-nonce attacks (the attester's signature is fresh on every use).
- Replay (deduplicated by `proposal_id` on-device).
- Malicious firmware update (signed-at-build firmware verification).

Not defended (out of scope):
- The user blindly pressing CONFIRM without reading the screen.
- A compromised renderer adapter (the adapter is part of the firmware; mitigation is to ship a small, audited adapter set and force adapter additions through intentguard with a long cool-off).
- Physical tampering of the device after delivery (the device flash is encrypted, but a sufficiently determined attacker with physical access may extract keys; mitigation is to treat key extraction as a key-rotation event).
- Supply chain attacks at manufacturing (mitigation: open source firmware, reproducible builds, verify the hash of flashed firmware against the public release).

See `THREAT_MODEL.md` for the full version.

## 10. What is deliberately absent

- **No display of arbitrary content.** The device only renders intents that decode through one of its registered adapters. There is no firmware command to "display this string." Any future flexibility must come from new adapters, which are themselves a guarded action.
- **No network connectivity.** The device has no Wifi/IP stack. USB CDC and (optional) BLE are the only transports.
- **No user-loadable apps.** The device is not a Trezor-style platform. The firmware is monolithic and signed.
- **No PIN.** PINs add UX friction without meaningfully raising the bar; the threat model treats physical possession of the device as half of the trust path, with the on-chain cool-off + veto handling the other half.

## 11. Open questions

- **Per-signer vs per-device attestation.** Currently a device is owned by one signer. Should a device be transferable, or always cryptographically bound to a single human's identity?
- **Quorum of attesters across signers.** Could a small set of "guardian attesters" co-sign for multiple signers (with their consent)? Useful for emergency response without re-issuing devices.
- **Battery life tradeoffs.** USB-powered is simplest. A small battery enables physical separation but raises supply-chain considerations.

## Changelog

- **0.1 (April 2026)**: initial draft. Solana ed25519 + EVM secp256k1, USB CDC primary transport, ESP32-S3 reference firmware, M5Stack Cardputer off-the-shelf target.
