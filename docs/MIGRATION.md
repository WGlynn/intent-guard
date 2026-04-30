# Migrating to intent-guard

A protocol team's playbook for moving privileged-call control from a "naked" Safe multisig (or admin EOA / multisig variant) to a Safe + IntentGuardModule + adapters configuration.

This walks through the operations, not the contract changes — see [`docs/HOWTO.md`](./HOWTO.md) for the upstream contract integration guide. The fork's adapters cover the surfaces; this doc covers the *roll-out*.

## Prerequisites

- An existing Safe (or compatible multisig) currently holding privileged authority over your contracts
- A clear inventory of which calls you want to gate (treasury withdraws, upgrades, peer configs, etc.)
- A staging chain (testnet) for end-to-end verification before mainnet
- A signer set willing to sign on the new `IntentGuardAttestation` typed-data shape

## Phases

### Phase 0 — Inventory & threat model

Before deploying anything: enumerate the privileged calls that exist today.

For each privileged call:

1. Who can call it now? (Safe address? Admin EOA? Both?)
2. What's the worst-case outcome of a malicious call? (Funds drained? Protocol upgraded to attacker code? Peer redirected to attacker chain?)
3. Which adapter from the fork covers this surface? (UUPS, DAOTreasury, RoleGrant, etc.) Or do you need to write a new adapter for a protocol-specific call?
4. What's the right cool-off window for the protocol's risk profile? 24h for treasury and upgrades; possibly less for routine parameter tuning.

Record this in a per-call matrix. The matrix becomes the deployment checklist.

### Phase 1 — Deploy on testnet

For each item in the inventory:

1. Deploy `IntentGuardModule` once (it's a single shared contract).
2. Deploy each needed adapter (see [`script/DeployUUPSExample.s.sol`](../script/DeployUUPSExample.s.sol) as the template).
3. Initialize a vault from a testnet Safe with the proposed signer set + cool-off window.
4. Register adapters and policies (proxy allowlists, asset caps, EID pins, role allowlists, etc.).
5. **Critical**: do NOT yet transfer ownership of guarded targets to the module. The module is "shadow-mode" at this stage.

### Phase 2 — Drill on testnet

Before any mainnet move, the signer set should run a drill against testnet:

1. Generate fresh attestations for a sample proposal (e.g., a benign treasury withdrawal).
2. Walk through the full queue → cool-off → execute pipeline. Verify the target receives the call.
3. Drill the veto path: signers cancel a proposal during cool-off; verify execution reverts.
4. Drill the freshness path: try queueing with stale attestations; verify it's rejected.
5. Drill the override-attempt: try calling the target directly from the Safe (should still work since ownership hasn't transferred yet); verify the path exists. This is your "rollback" if anything is mis-configured.

The drill should produce a known-good operational runbook for each adapter type.

### Phase 3 — Cutover on mainnet

Cutover sequence per guarded target. Do NOT batch — one target at a time.

1. Deploy a fresh mainnet `IntentGuardModule` (or use one already shared with the org).
2. Deploy adapters with mainnet policies (real proxy addresses, real asset caps, real signer set).
3. Initialize the vault. Register adapters via `setAdapter()`.
4. **Transfer ownership of the guarded target to the module**, OR install a Safe Guard that blocks direct Safe → guarded-target calls, OR update the guarded contract so the privileged function only accepts calls from the module. (See upstream README for direct-bypass guidance — this is the most error-prone step.)
5. Verify with a small test call: queue a proposal, walk through cool-off, execute.
6. Document the new operational runbook for that target.

### Phase 4 — Operational hygiene

Once cut over:

- **Monitor the queue.** Run an indexer that emits an alert on every `ProposalQueued` event, ideally to a channel separate from the signing UI. The 24-hour cool-off only helps if someone is watching.
- **Drill cancellations periodically.** Once a quarter, run a drill where one signer files a fake proposal and the others cancel. Keeps the veto muscle active.
- **Rotate signer keys on any device-compromise concern.** Keep the signer set membership current — `initializeVault` is one-shot, but the upstream module supports re-initialization via vault-id rotation if you need to change signer set entirely.
- **Update adapter policies as the protocol evolves.** New covered protocols, new asset allowlist entries, new bounded-parameter baselines. These updates flow through the same governance path as any other admin action.

## Common mistakes

- **Forgetting Phase 3 step 4 (the direct-bypass block).** Enabling a Safe module does NOT prevent the Safe from calling the guarded target directly. You must remove that path explicitly. Test that direct admin calls revert before considering migration complete.
- **Skipping the testnet drill.** Adapters are easy to misconfigure. Allowlist a wrong address, set a cap one zero too high, register the wrong codehash. The testnet drill catches this for free.
- **Setting cool-off too short.** Default is 24h for a reason — it gives non-online signers time to notice an unexpected proposal and veto. Anything below 6h is operationally fragile.
- **Setting veto threshold too high.** If `vetoThreshold == threshold`, then unanimous approval and unanimous veto require the same number of signers — and a single non-online signer can prevent any cancellation. Keep `vetoThreshold` strictly lower than `threshold` (commonly `threshold - 1` or 2-of-N regardless of N).
- **Not announcing Merkle roots before queueing them** (when using `MerkleRootSetAdapter`). The adapter will reject; no funds are at risk, but the proposal is wasted. Announce first.
- **Updating `BoundedParameterAdapter` baselines too aggressively after legitimate changes.** Each `updateBaseline()` call advances the change-ratio window. If you advance it too quickly, the drift defense weakens. The pattern: change → wait at least one cool-off cycle → update baseline → next change.

## Rollback

If something goes wrong in Phase 3:

- **Before ownership transfer (Phase 3 step 4)**: just don't do step 4. The module is dormant; Safe direct calls still work.
- **After ownership transfer**: depends on the guarded target. For UUPS proxies you can typically re-route ownership through a one-shot upgrade that restores Safe direct authority, but this requires going through the module itself (cool-off applies). Plan rollback BEFORE Phase 3, and test the rollback path on testnet.

In a true emergency, the cool-off + veto provides the safety margin: even if a malicious proposal is queued, the signer set can cancel it within 24h. There is no rollback for an executed malicious proposal — the gate happens before execution.

## Related reading

- [`docs/HOWTO.md`](./HOWTO.md) — upstream contract integration guide.
- [`docs/ADAPTERS.md`](./ADAPTERS.md) — adapter authoring walkthrough.
- [`docs/THREAT_VECTORS.md`](./THREAT_VECTORS.md) — adapter-to-attack-class mapping.
- [`SECURITY.md`](../SECURITY.md) — threat model summary + disclosure path.
- [`script/DeployUUPSExample.s.sol`](../script/DeployUUPSExample.s.sol) — reference deploy script.
