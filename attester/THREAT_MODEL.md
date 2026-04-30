# attester: Threat model

This document enumerates what the attester defends against, what it doesn't, and what assumptions must hold for the defense to work. Pair with `SPEC.md`.

## What the attester defends against

| Threat                                                     | How the attester closes it                                                                                                                |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Compromised wallet UI displays fake intent                 | Device renders intent on its own screen using its own audited renderer. User sees the truth.                                              |
| Malicious laptop swaps the calldata between sign and queue | Device signs a digest that includes `intent_hash`. If laptop changes the action, signature no longer matches.                             |
| Pre-signed Solana durable-nonce attack                     | Device's `signed_at` is its own monotonic counter and is included in the digest. Stale sigs fail freshness in intentguard.                |
| Stolen wallet seed                                         | Wallet sig alone is insufficient. Attester must also sign. Attacker would need to steal the device too.                                   |
| Stolen attester device                                     | Attester sig alone is insufficient. Wallet must also sign. Attacker would need to steal the seed too.                                     |
| Replay of a previously-confirmed proposal                  | Device caches `proposal_id` for the most recent N proposals and refuses to re-sign.                                                       |
| Malicious enrollment of a phantom attester by laptop       | Enrollment goes through intentguard's normal cool-off + veto path. A bogus attester would have to survive the public queue.               |
| Firmware swap attack via malicious USB host                | Firmware updates require physical button press AND a signed update payload from the project's release key.                                |
| Side-channel timing leakage                                | Cryptographic ops use constant-time implementations from `ed25519-dalek` / `k256`. Hardware RNG seeded at boot.                           |

## What the attester does NOT defend against

| Threat                                                                                                | Why                                                                                                                                                  | Mitigation                                                                                                                                            |
| ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| The user presses CONFIRM without reading the screen                                                   | The device cannot detect lazy reading.                                                                                                               | UI requires the user to physically scroll through a multi-line intent before CONFIRM unlocks. Long actions force a longer minimum read time.          |
| A compromised renderer adapter on the device                                                          | The adapter is in firmware. If it lies, the screen lies.                                                                                             | Ship a small, audited adapter set. New adapters are added via intentguard with a long cool-off. Reproducible firmware builds let anyone verify.       |
| Physical extraction of the signing key                                                                | A determined attacker with the device, time, and equipment may extract keys from any consumer hardware.                                              | Treat physical loss as a key-rotation event. Re-enroll a fresh device. Vaults should be configured to deactivate the lost attester on cool-off.       |
| Supply chain attack at manufacturing                                                                  | We don't control where the chips were made.                                                                                                          | Open source firmware, reproducible builds, verify the SHA-256 of flashed firmware against the public release before enrolling. BUILD.md describes.    |
| Coercion ($5 wrench, hostage scenario)                                                                | Any signing device can be coerced.                                                                                                                   | This is intentguard's cool-off + veto territory: an attacker with physical control of the device still has to wait 24 hours and survive a public queue. |
| Total laptop + device + wallet + seed compromise                                                      | If all of those are owned, the attacker is you.                                                                                                      | No primitive defends total compromise. Use multiple signers and attesters.                                                                            |
| Attester firmware bug                                                                                 | Bugs happen.                                                                                                                                         | Bug bounty, audit, reproducible builds, slow firmware update path with on-chain attestation of the new firmware hash.                                 |
| The on-chain action being fundamentally bad despite matching the displayed intent                     | The attester does not understand "good" or "bad" actions. It guarantees that what you see is what you sign, not that what you sign is wise.          | Out of scope. This is a governance and review problem.                                                                                                |

## Assumptions

For the attester's defense to hold, the following assumptions must be true:

1. **The user reads the screen and reacts to mismatches.** The strongest defense in the stack is a human noticing that the action being displayed is not what they expected. If they confirm without reading, the attester provides no protection.
2. **The device's renderer is correct.** It must produce the same canonical intent as the on-chain guard. The renderer is in scope for audit.
3. **The device's pubkey was enrolled correctly.** Specifically, the council member compared the pubkey shown on the device's own screen against the pubkey that intentguard accepted, before the enrollment cool-off ended. If a malicious laptop substituted the pubkey at enrollment time and the user didn't notice, the attacker controls the "attester" forever.
4. **Firmware updates are rare and well-controlled.** Any firmware update is a re-introduction of supply-chain risk. v0.1 expects firmware to be updated less than once a year, only by the project's release key, and only with a public on-chain hash announcement.
5. **The device is not used as a general-purpose computer.** No browsing, no app installation, no scripting. The firmware is monolithic and the only commands accepted are those defined in SPEC.md.

## Defense-in-depth context

The attester is not the whole answer. It is one layer in the stack:

```
  ┌─────────────────────────────────────────────────────┐
  │ Layer 5: Public on-chain queue + monitoring (earlybird, Forta) │
  ├─────────────────────────────────────────────────────┤
  │ Layer 4: intentguard cool-off + K-of-N veto          │
  ├─────────────────────────────────────────────────────┤
  │ Layer 3: intentguard intent binding (this is what attesters protect) │
  ├─────────────────────────────────────────────────────┤
  │ Layer 2: ATTESTER (this device)                      │
  ├─────────────────────────────────────────────────────┤
  │ Layer 1: Hardware wallet (seed-bound key)            │
  └─────────────────────────────────────────────────────┘
```

Each layer is independently breakable. The attester is the layer that closes the gap between what the human meant and what the protocol records as approved. It does not replace any other layer.

## Disclosure and bounty

Vulnerabilities in the firmware, host bridge, renderer, or protocol should be reported privately to `security@tradersguild.global` (placeholder; project will set up a real address before any production deployment).

A bug bounty program will accompany the v1.0 release.
