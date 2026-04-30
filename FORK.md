# Fork notes — WGlynn/intent-guard

This is a fork of [`uwecerron/intent-guard`](https://github.com/uwecerron/intent-guard) maintained for VibeSwap integration and audit hardening.

The original work — the spec, threat model, reference implementations for EVM and Solana, attester design, and the [whitepaper](./intentguard.md) — is by **Uwe Cerron** ([Traders Guild](https://www.tradersguild.global/)). All credit for the underlying design belongs to him. This fork extends rather than replaces.

## What this fork adds

VibeSwap-specific adapters in [`contracts/`](./contracts/):

| Adapter | Status | Purpose |
|---|---|---|
| [`UUPSUpgradeAdapter.sol`](./contracts/UUPSUpgradeAdapter.sol) | shipped | Gates `upgradeTo` / `upgradeToAndCall` on UUPS proxies. Binds (proxy, newImpl, callDataHash) into the intent and verifies impl EXTCODEHASH at execute time. Closes the CREATE2-redeployment class of upgrade attacks. |
| `DAOTreasuryAdapter.sol` | planned | Binds (recipient, asset, amount, reason) for treasury withdrawals. |
| `CrossChainPeerAdapter.sol` | planned | Binds LayerZero `setPeer` / `setEnforcedOptions` against peer allowlists per endpoint ID. |
| `CircuitBreakerParamAdapter.sol` | planned | Binds threshold-parameter changes against per-parameter caps. |
| `TWAPSourceAdapter.sol` | planned | Binds oracle source registration with feed allowlists + staleness checks. |

Foundry tests in [`test/`](./test/) cover each adapter's intent-hash determinism, validate-time invariants, and access control.

## Why fork instead of writing our own implementation

The 5-invariant composition (intent binding + freshness + cool-off + oracle-bound + action whitelist) is sharper than the sum of its parts. Cerron's spec + reference impl is the cleanest articulation of that composition I've found. Better to extend it than to re-spec something equivalent — the audit cost is the same either way, but extending compounds rather than duplicates.

## Status

- **Unaudited.** Same caveat as upstream. The reference module + this fork's adapters are starting points for protocol-specific integration and review, not drop-in production security.
- **Tracking upstream.** This fork tracks `uwecerron/intent-guard` `main`. Improvements not specific to VibeSwap (e.g. bug fixes in the module itself, generally-useful adapters) get filed as upstream PRs first.

## Build & test

```bash
forge install              # pulls forge-std and any other deps
forge build
forge test --match-path test/UUPSUpgradeAdapter.t.sol -vv
```

The default profile uses `via_ir = false` for fast iteration. Use `FOUNDRY_PROFILE=ci` for the via-IR validation profile when prepping for audit.

## License

- Code: MIT (per upstream SPDX headers)
- Whitepaper + design docs: CC BY 4.0 (per upstream `LICENSE`)
- Attribution: Uwe Cerron / Traders Guild for the original work; this fork's adapters and integration scaffolding by Will Glynn

If you build on this further, please attribute Uwe's original work upstream first.
