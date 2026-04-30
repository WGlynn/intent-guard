# Contributing

This is a fork of [`uwecerron/intent-guard`](https://github.com/uwecerron/intent-guard). Pull requests against this fork are welcome; pull requests that aren't VibeSwap-specific should generally land upstream first.

## What goes where

| Change kind | Land it here? | Land it upstream? |
|---|---|---|
| Bug fix in `contracts/IntentGuardModule.sol` | Yes (cherry-pick after upstream merge) | Yes — open the upstream PR first |
| Generally-useful new adapter (covers a common admin surface) | Yes | Yes — propose upstream too if appropriate |
| VibeSwap-specific adapter | Yes | No |
| Test additions | Yes | If applicable upstream |
| Documentation | Yes | If applicable upstream |

For upstream contributions, follow the original project's conventions and treat this fork's additions as supplemental, not foundational.

## Setup

```bash
git clone https://github.com/WGlynn/intent-guard.git
cd intent-guard
forge install
forge build
forge test
```

Foundry's default profile (no `--via-ir`) builds clean thanks to the [stack-depth refactor](https://github.com/uwecerron/intent-guard/pull/2). The `--via-ir` profile produces equivalent bytecode if you prefer it for parity checks.

## Adding an adapter

1. Read [`docs/ADAPTERS.md`](docs/ADAPTERS.md) for the contract, patterns, and worked example.
2. Place the adapter in `contracts/<NameAdapter>.sol` and tests in `test/<NameAdapter>.t.sol`.
3. Cover at minimum: intent-hash determinism + binding, malformed-input reverts, validate happy-path and revert paths, owner-only access control on every setter.
4. If the adapter introduces a new policy concept (allowlist, cap, ratio), add a unit test for the policy edge cases.
5. Optional but encouraged: add an integration test in `test/Integration<Name>.t.sol` exercising the full module → adapter → target call path.

## Testing standards

- Each new adapter should ship with at least 10 unit tests covering the patterns in [`docs/ADAPTERS.md`](docs/ADAPTERS.md).
- All tests must pass on the default Foundry profile (no `--via-ir`). If you hit stack-too-deep, refactor — pack args into structs, extract helpers — don't paper over with `--via-ir` only.
- The CI workflow runs both default and `--via-ir` profiles; both must pass.

## Style

- Match the existing adapter file structure: SPDX header, pragma 0.8.24, NatSpec on the contract and on each adapter-specific function, errors as named selectors (not `require` strings), events on every owner setter.
- Selector constants and intent typehashes named `_SELECTOR` and `_INTENT_TYPEHASH`.
- Per-target / per-key state in structs, exposed via getter where useful.
- Owner-only setters all gated through a single `onlyOwner` modifier.

## Filing issues

For VibeSwap-specific issues: open here.

For issues with the upstream module, spec, or whitepaper: open at [`uwecerron/intent-guard`](https://github.com/uwecerron/intent-guard) and link to it from a tracking issue here if relevant to the fork.

## License

Code: MIT. Docs / whitepaper additions: CC BY 4.0 (matching upstream).

By contributing you agree your contributions will be licensed accordingly.
