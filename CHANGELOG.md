# Changelog — WGlynn/intent-guard fork

All changes from upstream `uwecerron/intent-guard` are tracked here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added — Adapters (`contracts/`)

- `UUPSUpgradeAdapter.sol` — Gates `upgradeTo` / `upgradeToAndCall` on UUPS proxies. Binds (target, newImpl, callDataHash) into intent. EXTCODEHASH check at validate() defends against CREATE2-redeployment attacks.
- `DAOTreasuryAdapter.sol` — Gates `withdraw(recipient, asset, amount)`. Per-asset cap enforcement and optional recipient allowlist.
- `CrossChainPeerAdapter.sol` — Gates LayerZero V2 `setPeer`. Per-OApp EID allowlist and optional per-EID peer pinning.
- `RoleGrantAdapter.sol` — Gates OZ AccessControl `grantRole` / `revokeRole`. Per-(target, role) policy with frozen flag and account allowlist for grants.
- `PausableAdapter.sol` — Gates OZ Pausable `pause` / `unpause`. Each gated independently per target (supports lock-once mode).
- `OwnershipTransferAdapter.sol` — Gates OZ Ownable `transferOwnership` / `renounceOwnership`. NewOwner allowlist + per-target renounce-default-disabled.
- `BoundedParameterAdapter.sol` — Gates `setParam(bytes32, uint256)`. Min/max bounds + change-ratio cap from registered baseline.
- `MerkleRootSetAdapter.sol` — Gates `setMerkleRoot(bytes32)`. Pre-announcement gate prevents malicious-root substitution.

### Added — Tests (`test/`)

- Per-adapter unit tests for all 8 adapters (intent-hash determinism, binding, malformed-input reverts, validate happy-path + revert paths, owner-only access control). 87 unit tests total across the adapters.
- Integration tests wiring `IntentGuardModule` + adapter + mock Safe + mock target through full queue → cool-off → execute, with EIP-191 signed attestations:
  - `IntegrationUUPS.t.sol` (4 tests: happy / veto / cool-off / freshness)
  - `IntegrationDAOTreasury.t.sol` (2 tests: happy / cap rejection)
  - `IntegrationRoleGrant.t.sol` (3 tests: happy / attacker-grant blocked / frozen-role blocked)
  - `IntegrationMerkleRoot.t.sol` (2 tests: announced root / unannounced blocked)
  - `IntegrationOwnership.t.sol` (3 tests: happy / attacker blocked / renounce default-disabled)
  - `IntegrationBoundedParameter.t.sol` (3 tests: within ratio / ratio exceeded / above absolute max)
  - `IntegrationCrossChainPeer.t.sol` (2 tests: pinned-peer set / peer substitution blocked)
  - `IntegrationPausable.t.sol` (2 tests: pause applied / unpause blocked under lock-once)
- Shared scaffolding via `test/helpers/IntegrationBase.t.sol`. New integration tests are ~120 LOC instead of ~250 LOC.

### Added — Documentation

- `FORK.md` — Fork inventory + roadmap.
- `docs/ADAPTERS.md` — Adapter-authoring guide with worked example.
- `docs/THREAT_VECTORS.md` — Adapter-to-attack-class mapping with reference incidents.
- `docs/MIGRATION.md` — Operational rollout playbook (4 phases, common mistakes, rollback).
- `CONTRIBUTING.md` — Where-changes-land matrix + adapter-authoring pointer.
- `SECURITY.md` — Threat-model summary + disclosure path.
- `contracts/README.md` — Adapter inventory.
- `README.md` — Fork banner with concrete adapter / test counts.

### Added — Tooling

- `.github/workflows/test.yml` — CI runs `forge build` + `forge test` on both default and `--via-ir` profiles for every push and PR.
- `script/DeployUUPSExample.s.sol` — Worked deploy template demonstrating the canonical setup flow.
- `signer-cli/src/adapters.ts` — TypeScript intent-hash helpers for all 8 adapters, mirroring the on-chain computation for off-chain attestation tooling.

### Changed — Upstream module (cherry-picked, also upstreamed via PR)

- `contracts/IntentGuardModule.sol`: extracted `_attestationDigest()` and `_verifyAttestation()` helpers from `_verifyAttestations`. The default Foundry profile (legacy compile pipeline) now builds clean — previously failed with "Stack too deep" without `--via-ir`. Behavior, ABI, events, and storage layout are unchanged.
- Tracking: upstream issue [`uwecerron/intent-guard#1`](https://github.com/uwecerron/intent-guard/issues/1) and PR [`uwecerron/intent-guard#2`](https://github.com/uwecerron/intent-guard/pull/2).

### Test status

136 tests pass on the default Foundry profile (no `--via-ir` flag required).

### Notes

- This fork is unaudited reference work — same caveat as upstream. Do not deploy as-is to secure funds.
- All adapter additions follow the existing upstream patterns: SPDX MIT, pragma 0.8.24, owner-only setters with explicit `NotOwner` selector, `IActionAdapter` contract, fail-closed decoders.
- Improvements that aren't VibeSwap-specific are filed as upstream PRs first; the fork carries them only when needed for downstream development to continue.

---

## [Upstream] - 2026-04-30

Initial upstream commit by Uwe Cerron at `uwecerron/intent-guard`. See upstream `README.md` and `intentguard.md` for the original spec, threat model, and reference implementation.
