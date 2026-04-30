# intentguard attester

The attester is the missing hardware layer for intentguard.

Intentguard makes the chain verify that an approved transaction matches a typed intent. The attester makes the signer verify that the typed intent was rendered on a device that is not the signer's everyday laptop.

Goal: a public, MIT-licensed, protocol-neutral intent-rendering device that any DeFi council can adopt.

Status: design scaffold, not firmware, not audited, not production-ready.

## One sentence

The attester is a dedicated screen and signing key that displays decoded protocol intent from an audited renderer and produces a co-signature only after physical confirmation.

## Why it matters

Intent binding is only as good as the signer review path.

If a compromised laptop renders:

```text
Routine integration update
```

while the real intent is:

```text
Transfer admin to attacker
```

then the human can still be fooled before the on-chain guard ever runs.

An attester reduces that risk by moving intent rendering and approval to a separate, narrow-purpose device.

## Target properties

- **Protocol-neutral:** works for EVM, Solana, and future chains.
- **Open:** MIT-licensed firmware, renderer libraries, schemas, and host client.
- **Small trusted surface:** no browser, no wallet extensions, no arbitrary web content.
- **Deterministic renderer:** audited schemas turn canonical intent bytes into human-readable screens.
- **Physical confirmation:** the attester signs only after button/touch confirmation on the device.
- **Separate key:** the attester key is not the council member's hot wallet, Safe owner key, or laptop key.
- **Device attestation:** the device can prove firmware identity and schema bundle hash.
- **Fail closed:** unknown schemas, unknown targets, unknown feeds, malformed payloads, and oversized intents refuse to render or sign.

## What the attester signs

The attester does not sign raw calldata. It signs a canonical attestation over:

```text
domain
chain_id_or_genesis_hash
vault
proposal_id
nonce
action_kind
target
data_hash
intent_hash
schema_id
schema_version
renderer_hash
firmware_hash
display_digest
signed_at
expires_at
```

The on-chain guard can require both:

1. signer quorum over the proposal, and
2. attester quorum over the rendered intent.

## MVP path

The first useful version does not need custom silicon.

MVP 0 can be:

- an offline mobile app or desktop app running in locked-down mode,
- open renderer library,
- deterministic schema registry,
- separate attester key,
- QR-code or USB transport,
- co-signature verified by the guard.

MVP 1 can be:

- secure-enclave-backed mobile app,
- remote attestation where available,
- signed schema bundles,
- reproducible builds.

MVP 2 can be:

- dedicated hardware device,
- secure boot,
- firmware attestation,
- supply-chain controls,
- tamper-resistant key storage.

## Developer experience

The fastest way to try the attester is the software emulator and SDK:

```ts
import { buildIntentBundle, createEmulatorAttester } from "@intentguard/attester-sdk";

const bundle = buildIntentBundle({
  network: "solana",
  vault,
  nonce: 1n,
  actionKind: 1,
  actionArgs,
});

const attester = createEmulatorAttester();
const approval = await attester.attest(bundle);
```

This lets a protocol team integrate the attestation requirement before buying or flashing hardware. The emulator is for development only. Production should use hardware or secure-enclave-backed attesters.

## Message flow

```text
1. Operator drafts proposal.
2. Host client sends canonical intent bundle to attester.
3. Attester verifies schema_id and schema_version.
4. Attester renders intent on its own screen.
5. Human confirms on the attester device.
6. Attester signs the attestation payload.
7. Host submits signer signature plus attester signature.
8. intentguard verifies both before queueing.
```

## Files

- `SPEC.md`: wire protocol, digest format, enrollment flow, and integration semantics.
- `THREAT_MODEL.md`: defended cases, assumptions, and limits.
- `BUILD.md`: reference hardware path and rollout tiers.
- `renderer/`: TypeScript renderer, canonical intent hashing, adapters, and tests.
- `host/`: USB serial host bridge and software emulator.
- `sdk/`: developer-facing bundle builder and emulator attester.
- `firmware/`: no_std Rust firmware scaffold with matching on-device adapters.
- `client/README.md`: host-client transport requirements.
- `vectors/`: shared test-vector workflow for renderer, firmware, and on-chain tests.

## How to use this folder today

The useful development path is:

1. Add an adapter in `renderer/src/adapters/`.
2. Mirror the same adapter in `firmware/src/render.rs`.
3. Add renderer test vectors for normal, boundary, and malformed payloads.
4. Run the host emulator to exercise the signing flow before touching hardware.
5. Wire the attester signature into intentguard as an additional quorum requirement.

Example emulator flow:

```sh
cd attester/renderer
npm test
npm run vectors
npm run new-adapter -- transfer-admin-v2 10

cd ../host
npm run emulate
```

For a real device, replace `--emulator` with `--port <serial-path>` once firmware and secure storage are wired.

## Review notes

The attester must be judged on three byte-level invariants:

| Invariant | Why it matters |
| --- | --- |
| Host renderer canonical bytes match firmware canonical bytes | Prevents the laptop from showing one intent while the device hashes another. |
| Attester signature covers `vault`, `nonce`, `action_kind`, `intent_hash`, and `signed_at` | Prevents replay, proposal swapping, and stale durable-nonce style reuse. |
| On-chain verifier recomputes the exact same digest | Prevents signatures from being accepted for a different proposal context. |

Any new protocol adapter should ship with test vectors that can be consumed by the TypeScript renderer, firmware tests, and on-chain verifier tests.

## Non-goals

- Replacing hardware wallets.
- Signing arbitrary user transactions.
- Rendering arbitrary calldata.
- Supporting every protocol without schemas.
- Hiding malicious intent from signers for speed or convenience.

## Production warning

Do not treat this folder as a working hardware wallet. It is the design basis for the next layer of intentguard.
