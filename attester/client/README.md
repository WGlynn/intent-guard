# Host client requirements

The host client moves proposal data between the protocol UI and the attester.

The host is not trusted.

It may:

- fetch proposals,
- package canonical intent bundles,
- send bundles by QR, USB, NFC, or local transport,
- receive attester signatures,
- submit attestations on-chain.

It must not be trusted to:

- decide what the intent means,
- rewrite schemas,
- hide fields,
- choose oracle feeds,
- change targets,
- decide whether a proposal is safe.

## Bundle format

Every host-to-attester bundle should contain:

- chain,
- vault,
- proposal id,
- nonce,
- action kind,
- target,
- calldata or instruction hash,
- intent hash,
- canonical intent bytes,
- schema id,
- schema version,
- expiry.

The attester must recompute all hashes before rendering.

## Easiest developer path

Use `attester/sdk` first:

1. Build an intent bundle in app code.
2. Send it to `createEmulatorAttester()` in tests.
3. Verify the returned approval in your guard tests.
4. Swap the emulator for the host bridge when hardware is available.

This keeps protocol teams from blocking on USB, firmware, or device procurement while they are still proving the integration.
