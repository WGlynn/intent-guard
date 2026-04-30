# FAQ

Common questions from teams evaluating intent-guard for production use.

## "Is this audited?"

No. Both upstream and this fork ship as unaudited reference work. The fork's stack-depth refactor (`IntentGuardModule._attestationDigest` / `_verifyAttestation`) has been tested for behavior preservation but not independently reviewed. Adapters have unit + integration coverage but not external audit.

If you're evaluating for production: budget for an audit. The fork's CI builds clean on the default Foundry profile (no `--via-ir`), which removes a "did the IR pipeline introduce something" question from the audit scope.

## "Why is each adapter a separate contract instead of a config in the module?"

Two reasons:

1. **Clean separation between mechanism and policy.** The module is the mechanism (vault state, attestation verification, queue / cool-off / execute). Adapters are the per-action policy (intent-hash binding for *this* action shape, validate checks for *this* action's risk model). Mixing them creates a single contract that needs to know about every action class — the OpenZeppelin Ownable upgrade pattern would be in the same file as the LayerZero peer pattern.
2. **Independent upgradability.** Updating the policy for a single action class (e.g. tightening a treasury cap, adding a new asset to the allowlist) doesn't require redeploying the module or any other adapter. Each adapter has its own owner key.

The cost is that each guarded action requires its own adapter address registered via `setAdapter()`. For most protocols, that's 3-7 adapters total — manageable.

## "Can I use this with a non-Safe multisig?"

The module currently calls `ISafe(vault.safe).execTransactionFromModule(...)` directly. To use a different multisig, your multisig needs to expose the same call shape, OR you need a small shim contract that forwards module calls to your multisig's exec function.

The Solidity interface is two methods:

```solidity
function execTransactionFromModule(
    address to,
    uint256 value,
    bytes calldata data,
    uint8 operation
) external payable returns (bool success);
```

If your multisig has this (Safe-compatible) directly, you're set. Otherwise the shim is ~30 LOC.

## "What happens if all my signers are offline?"

Three states for a queued proposal:

- **Cool-off elapses, no veto, executor calls `execute`** → call lands at the target. This is the happy path.
- **Cool-off elapses, no veto, no one calls `execute`** → the proposal sits in `Queued` state until `proposalExpiresAt`. After expiry, the proposal can no longer execute (`ProposalExpired`). No funds at risk; just a wasted proposal slot.
- **Cool-off active, signers cancel** → proposal moves to `Cancelled` permanently. Even if executor tries `execute` later, it reverts.

The `proposalExpiresAt` upper bound (passed by the queuer) ensures stale proposals don't accumulate indefinitely. Set it generously — a few days past `cool-off + executeDelay` is reasonable.

## "Can I queue multiple proposals against the same target simultaneously?"

Yes. Each proposal gets a deterministic `proposalId = keccak256(vaultId, vault.nonce, target, value, dataHash, intentHash, adapter)`. The vault's nonce increments only on successful execution, so multiple proposals can sit queued. The first one to execute increments the nonce; subsequent proposals' execute calls then revert (`BadNonce`).

This gives you "first to execute wins" semantics. If you need stricter ordering, queue one at a time.

## "How do I rotate signers?"

`initializeVault` is one-shot — the signer set is fixed at vault creation. To rotate, deploy a new vault under a new `vaultId` with the new signer set, transfer guarded ownership from the old module/vault to the new one (itself a guarded operation in most setups), and decommission the old vault.

There's a tradeoff here vs. mutable signer sets. Mutable signer sets simplify rotation but add an attack surface ("malicious signer addition"). The fork's adapters can include a `vaultId` as part of the protocol-specific authority model if you want runtime rotation through a slow-vault → fast-vault pattern.

## "What's the gas cost?"

Roughly:

| Operation | Gas cost (est) |
|---|---|
| `initializeVault` | ~150k |
| `setAdapter` | ~50k |
| `queue` (2 attestations) | ~250-300k |
| `cancel` | ~60k |
| `execute` (UUPS upgrade) | ~280-330k |
| `execute` (treasury withdraw) | ~330k |

These are rough indications from the integration test gas reports. Real-world cost varies with the underlying call's gas (e.g., complex ERC20 transfer hooks add to `execute`).

For high-frequency operations, intent-guard adds meaningful overhead. It's intended for **low-frequency, high-stakes** privileged calls — upgrades, treasury moves, peer config — not routine fee collection or rebalancing.

## "Can the module's owner / deployer rug me?"

The module has no privileged owner. After deploy, only signers (per their vault config) and the vault's Safe can take privileged actions. The deployer has no special role.

The adapter's owner is privileged (sets policies). For high-stakes vaults, the adapter owner should itself be a Safe — preferably a different Safe than the one being guarded, to avoid concentration of authority. Setting policy through a separate slow-vault is the recommended pattern.

## "What if I don't see my action's selector in any adapter?"

Write your own — see [`docs/ADAPTERS.md`](./ADAPTERS.md) for the contract walkthrough and worked example. Adapters are typically ~100-150 LOC plus a 10-15 test suite. Most protocol teams will need 1-2 protocol-specific adapters even when using the fork's generic ones.

## "Why bother with `intentHash` if I'm going to validate at execute time anyway?"

Two functions, two responsibilities:

- `intentHash` is what signers approve. It's the canonical, cross-language definition of "this is the action you're consenting to." Off-chain signing tools (TS / Python / Rust / hardware) all compute the same hash from the same fields.
- `validate` is the protocol-state guard at execute time. It can do live checks that depend on chain state (oracle prices, codehashes, current parameter values).

If you only had `validate`, you'd have to trust the signed bytes match what signers reviewed — but signers might have reviewed a typed-data preview that differs from what the executor passes in. The intent hash is the contract that ensures preview-time and execute-time reference the same call.

## "Can I run slither / mythril on this?"

You can. The fork's CI doesn't run them by default to avoid workflow-runtime hits, but adding a slither workflow is straightforward (`crytic/slither-action@v0.4.0`). Findings will mostly be inheritable from upstream — the fork's adapters are short and follow conventional patterns.

## "Where do I report a bug or vulnerability?"

For the fork: see [`SECURITY.md`](../SECURITY.md). Open a GitHub Security Advisory or contact the maintainer.

For the upstream module / spec / whitepaper: open at [`uwecerron/intent-guard`](https://github.com/uwecerron/intent-guard) directly.
