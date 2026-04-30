# Contracts

`IntentGuardModule.sol` is the upstream module (Cerron). Everything else in this directory is either an upstream example (`CollateralListingAdapter`) or a fork addition.

| File | Origin | Purpose |
|---|---|---|
| `IntentGuardModule.sol` | upstream + fork stack-depth refactor (PR #2) | The guarded execution core. Vault config, proposal state machine, attestation verification. |
| `CollateralListingAdapter.sol` | upstream | Example adapter — collateral whitelist with oracle-bound fair-value check. |
| `UUPSUpgradeAdapter.sol` | fork | Gates `upgradeTo` / `upgradeToAndCall` on UUPS proxies. EXTCODEHASH-bound. |
| `BeaconUpgradeAdapter.sol` | fork | Gates `upgradeTo` on OZ `UpgradeableBeacon`. One Beacon serves N BeaconProxies — fan-out leverage. EXTCODEHASH-bound, per-beacon impl allowlist. |
| `DAOTreasuryAdapter.sol` | fork | Gates `withdraw(recipient, asset, amount)`. Per-asset cap + optional recipient allowlist. |
| `CrossChainPeerAdapter.sol` | fork | Gates LayerZero V2 `setPeer`. Per-OApp EID allowlist + optional peer pinning. |
| `RoleGrantAdapter.sol` | fork | Gates OZ AccessControl `grantRole` / `revokeRole`. Per-(target, role) freeze + account allowlist for grants. |
| `PausableAdapter.sol` | fork | Gates OZ Pausable `pause` / `unpause`. Each gated independently per target. |
| `OwnershipTransferAdapter.sol` | fork | Gates OZ Ownable `transferOwnership` / `renounceOwnership`. NewOwner allowlist + per-target renounce-disabled default. |
| `BoundedParameterAdapter.sol` | fork | Gates the canonical `setParam(bytes32, uint256)` shape. Min/max bounds + change-ratio cap from registered baseline. |
| `MerkleRootSetAdapter.sol` | fork | Gates `setMerkleRoot(bytes32)` for allowlist-via-Merkle protocols. Pre-announcement gate prevents malicious roots from being signed. |

## How they compose

All adapters implement `IActionAdapter`:

```solidity
interface IActionAdapter {
    function intentHash(address target, uint256 value, bytes calldata data) external view returns (bytes32);
    function validate(address target, uint256 value, bytes calldata data, bytes32 expectedIntentHash) external view;
}
```

The module calls `intentHash` at queue time to verify what signers approved matches the actual call. It calls `validate` at execute time after cool-off has elapsed for live checks (oracle, codehash, caps, allowlists).

Adapters are independent of each other and of the protocol they gate. A single vault can register multiple adapters for different `(target, adapter)` pairs — e.g., one vault with UUPSUpgradeAdapter for proxy upgrades AND DAOTreasuryAdapter for the treasury withdrawals AND RoleGrantAdapter for role administration, all on different target contracts.

## Authoring more adapters

See [`../docs/ADAPTERS.md`](../docs/ADAPTERS.md) for the contract walkthrough, the worked example, and common pitfalls.

## Testing

Every adapter has a corresponding suite under `../test/`. Two integration tests under `../test/Integration*.t.sol` exercise the full module + adapter + target call path with signed attestations.

```bash
forge test                                                    # all
forge test --match-path test/UUPSUpgradeAdapter.t.sol -vv     # one suite
forge test --match-path test/IntegrationUUPS.t.sol -vv        # integration
```
