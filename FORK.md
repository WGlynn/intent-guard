# Fork notes — WGlynn/intent-guard

This is a fork of [`uwecerron/intent-guard`](https://github.com/uwecerron/intent-guard) — extending the original spec + reference module with VibeSwap integration adapters, expanded test coverage, and audit-readiness fixes.

The original work — the spec, threat model, EVM/Solana reference implementations, attester design, and the [whitepaper](./intentguant.md) — is by **Uwe Cerron** ([Traders Guild](https://www.tradersguild.global/)). All credit for the underlying design belongs to him. This fork extends rather than replaces.

## What this fork ships

### Adapters (`contracts/`)

| Adapter | LOC | Tests | Surface gated |
|---|---|---|---|
| [`CollateralListingAdapter.sol`](./contracts/CollateralListingAdapter.sol) | 150 | — | (upstream example) collateral whitelist + oracle bind |
| [`UUPSUpgradeAdapter.sol`](./contracts/UUPSUpgradeAdapter.sol) | 130 | 15 | `upgradeTo` / `upgradeToAndCall` with EXTCODEHASH binding |
| [`DAOTreasuryAdapter.sol`](./contracts/DAOTreasuryAdapter.sol) | 100 | 18 | `withdraw(recipient, asset, amount)` with caps + recipient allowlist |
| [`CrossChainPeerAdapter.sol`](./contracts/CrossChainPeerAdapter.sol) | 95 | 12 | LayerZero V2 `setPeer` with EID allowlist + peer pinning |
| [`RoleGrantAdapter.sol`](./contracts/RoleGrantAdapter.sol) | 130 | 16 | OZ AccessControl `grantRole` / `revokeRole` with role-freeze + account allowlist |
| [`PausableAdapter.sol`](./contracts/PausableAdapter.sol) | 80 | 12 | OZ Pausable `pause` / `unpause` (each gated independently) |
| [`OwnershipTransferAdapter.sol`](./contracts/OwnershipTransferAdapter.sol) | 110 | 14 | OZ Ownable `transferOwnership` / `renounceOwnership` with newOwner allowlist |
| [`BoundedParameterAdapter.sol`](./contracts/BoundedParameterAdapter.sol) | 130 | 15 | Canonical `setParam(bytes32, uint256)` shape with min/max + change-ratio caps |
| [`MerkleRootSetAdapter.sol`](./contracts/MerkleRootSetAdapter.sol) | 100 | 13 | `setMerkleRoot(bytes32)` for allowlists; pre-announcement gate prevents malicious roots |

### Integration tests

Three end-to-end suites, each wiring `IntentGuardModule` + an adapter + a mock Safe + a mock target through the full **queue → cool-off → execute** pipeline with real EIP-191 signed attestations:

| Test | Adapter | Scenarios |
|---|---|---|
| [`test/IntegrationUUPS.t.sol`](./test/IntegrationUUPS.t.sol) | UUPSUpgradeAdapter | happy path, veto blocks execution, cool-off enforcement |
| [`test/IntegrationDAOTreasury.t.sol`](./test/IntegrationDAOTreasury.t.sol) | DAOTreasuryAdapter | happy path withdrawal, over-cap rejected at execute |
| [`test/IntegrationRoleGrant.t.sol`](./test/IntegrationRoleGrant.t.sol) | RoleGrantAdapter | grant on allowed account, attacker-grant blocked, frozen-role blocked |

The integration coverage demonstrates the module's adapter contract composes across action types — same module + same attestation flow drives any `IActionAdapter`.

### Module change (cherry-picked, also upstreamed)

`contracts/IntentGuardModule.sol` was refactored to extract `_attestationDigest()` and `_verifyAttestation()` helpers. The change reduces stack depth in `_verifyAttestations` so the **default Foundry profile (legacy compile pipeline) builds clean without `--via-ir`**. Behavior, ABI, events, and storage layout are unchanged. PR upstreamed at [`uwecerron/intent-guard#2`](https://github.com/uwecerron/intent-guard/pull/2), tracking issue at [`#1`](https://github.com/uwecerron/intent-guard/issues/1).

## Test coverage

```bash
forge test
```

Total: **~115 tests pass on the default profile** (no `--via-ir`).

Per-adapter coverage targets:

- Intent-hash determinism + binding to every load-bearing field
- Selector enforcement and malformed-calldata reverts
- `validate()` happy-path under each policy variant
- `validate()` revert paths for every error condition (caps, allowlists, freezes, codehashes)
- Owner-only access control on every setter

The integration test additionally exercises the on-chain attestation digest recompute path, the cool-off + veto state machine, and the Safe-module call-out.

## Why fork

The 5-invariant composition (intent binding + freshness + cool-off + oracle-bound + action whitelist) is sharper than the sum of its parts. Cerron's spec + reference impl is the cleanest articulation of that composition; better to extend it than to re-spec something equivalent. Audit cost is the same either way.

## Status

- **Unaudited.** Same caveat as upstream. Adapters and the module's refactor are starting points for protocol-specific integration and review, not drop-in production security.
- **Tracking upstream.** Improvements that aren't VibeSwap-specific (e.g. the stack-depth fix, generally-useful adapters) are filed as upstream PRs first.
- **Integration testing pending.** The integration test covers happy / veto / cool-off paths. The stale-signature path is stubbed pending a follow-up debug pass on the EIP-191 timing flow.

## Build & test

```bash
forge install                                             # pulls forge-std (submodule)
forge build                                                # default profile, no --via-ir
forge test                                                 # all suites
forge test --match-path test/UUPSUpgradeAdapter.t.sol -vv  # one suite
```

The default profile uses `via_ir = false` for fast iteration. The `--via-ir` profile remains available and produces equivalent bytecode.

## License

- Code: MIT (per upstream SPDX headers)
- Whitepaper + design docs: CC BY 4.0 (per upstream `LICENSE`)
- Attribution: Uwe Cerron / Traders Guild for the original work; this fork's adapters, integration scaffolding, and stack-depth refactor by Will Glynn

If you build on this further, please attribute Uwe's original work upstream first.
