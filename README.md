# intentguard

Intentguard is an on-chain guardrail for privileged DeFi operations. It makes a dangerous action prove:

1. what the signers intended,
2. what the transaction actually does,
3. whether the signatures are fresh,
4. whether the action survived a public cool-off window,
5. whether oracle-sensitive claims match allowlisted live data.

This repository currently contains a design paper plus reference implementation scaffolds for EVM and Solana. Treat the code as a starting point for review and protocol-specific integration, not an audited drop-in security product.

## Why founders should care

If you run a DeFi protocol, your biggest risk may not be a smart-contract bug. It may be one legitimate signer approving the wrong thing at the wrong time.

Audits, multisigs, hardware wallets, and bug bounties are necessary, but they do not prove that a signer understood the real effect of an admin action. A compromised laptop, fake integration partner, malicious RPC, or misleading signing flow can still turn a valid council signature into a protocol-ending event.

Intentguard matters because it gives founders an operational control for the highest-leverage failure point in a protocol: privileged action execution.

For a founder, that means:

- **Protect user funds:** upgrades, admin transfers, collateral listings, oracle changes, and treasury moves get a second layer of on-chain verification.
- **Protect the team:** council members are no longer expected to personally decode dangerous calldata under pressure.
- **Protect governance credibility:** every sensitive action has a public queue, clear intent, visible approvals, and a veto path.
- **Protect the protocol's runway:** one social-engineered signer flow should not be enough to destroy years of work, liquidity, and trust.
- **Protect integrations:** lenders, market makers, custodians, and institutional partners can see that admin power is constrained by process, not just vibes.

The founder-level takeaway: intentguard turns "trust our multisig" into "our multisig can only execute fresh, explicit, reviewable, vetoable actions." That is a stronger story for users, investors, auditors, exchanges, and your own team.

## Layout

- `intentguard.md`: whitepaper and threat model.
- `contracts/IntentGuardModule.sol`: EVM Safe-compatible guarded execution module.
- `contracts/CollateralListingAdapter.sol`: example adapter for a collateral-listing action.
- `solana/programs/intentguard/src/lib.rs`: Anchor-style Solana program scaffold.
- `signer-cli/src/intent.ts`: TypeScript helpers for intent and attestation hashes.
- `docs/HOWTO.md`: step-by-step tutorial for protocol teams and councils.
- `attester/`: protocol-neutral attester design for rendering intent on a separate device.

## One-sentence description

Intentguard is an on-chain guardrail that makes every dangerous protocol action prove what signers meant, what the transaction does, and whether the approval is still fresh before it can execute.

## Tutorial

Start with [`docs/HOWTO.md`](docs/HOWTO.md). It walks through the operational lifecycle: choosing protected actions, defining schemas, writing adapters, configuring a vault, collecting fresh signer attestations, queueing, monitoring, vetoing, and executing on EVM or Solana.

## What it mitigates and what it does not

| Risk | Mitigated by intentguard? | How |
| --- | --- | --- |
| Stale pre-signed admin transactions | Yes | Signatures must be fresh when the proposal enters the queue. |
| Misleading signer UI or blind signing | Yes | Signers approve a typed intent hash, and the guard checks the real call matches it. |
| Admin transfer to an unexpected address | Yes, if guarded | The adapter must decode the new admin and bind it into the signed intent. |
| Unsafe collateral listing | Yes, if guarded | The adapter binds token, feed, claimed value, caps, and oracle/risk checks. |
| Treasury withdrawal to a wrong recipient | Yes, if guarded | Recipient, asset, amount, and reason can be included in the typed intent. |
| Oracle/feed switch to attacker-controlled feed | Partly | Feed allowlists and slower adapter/feed changes are required. |
| A rushed malicious proposal | Partly | Cool-off and veto give honest signers time to cancel. |
| Compromised signer laptop | Partly | The chain does not trust the laptop's display, but the signer key can still approve fresh bad intent if the human is fooled. |
| Smart-contract bugs in the guarded protocol | No | Intentguard controls privileged actions, not protocol business logic. |
| Total signer collusion | No | If enough signers knowingly approve and no veto happens, no multisig guard can save the protocol. |
| Cross-chain verifier/RPC compromise | No, not by itself | Bridges need separate multi-verifier, RPC quorum, proof, and circuit-breaker controls. |

## Known failure modes and fixes

| Failure mode | Why it matters | Prevention or fix |
| --- | --- | --- |
| Direct bypass | If the Safe/admin key can still call the protocol directly, intentguard is only a dashboard. | Transfer guarded ownership to the module/PDA, install a Safe Guard that blocks covered direct calls, or update protected contracts so guarded functions only accept calls from intentguard. Test that direct admin calls revert. |
| Bad adapters | If an adapter misses a field or decodes calldata incorrectly, signers approve an incomplete intent. | Write one adapter per action kind, keep schemas explicit, add unit and fuzz tests for every selector/instruction, include all risk-relevant fields, and require independent review before allowlisting adapters. |
| Generic adapters | An adapter that accepts arbitrary calldata recreates blind signing under a new name. | Fail closed for unknown selectors, unknown targets, unknown accounts, unknown feeds, and unexpected calldata length. Do not allow "execute arbitrary bytes" as a guarded action. |
| Oracle trust | A stale, thin, attacker-controlled, or governance-selected feed can make false claims pass. | Use feed allowlists, staleness checks, confidence checks, liquidity floors, capped bootstrap limits, multi-oracle adapters for high-value assets, and longer delays for feed changes. Do not let the same proposal both add a feed and use it for major borrowing power. |
| Veto liveness | If `K` is too low, governance can be griefed. If `K` is too high, honest signers may fail to cancel during an incident. | Set `K` per vault, run cancellation drills, publish a signer availability rota, require cancellation reasons, and use separate slow and fast vaults for different authority levels. |
| Queue not monitored | A 24-hour delay only helps if people or bots notice the queued proposal. | Emit indexed events, run independent monitors, alert signers out-of-band, mirror proposals to public dashboards, and require every queued action to be announced in the expected council channel. |

## Recommended defenses by attack path

| Attack path | What can go wrong | What intentguard does | What else to add |
| --- | --- | --- | --- |
| Drift-style social engineering | Signers are cultivated over time and tricked into approving admin or collateral changes that look routine. | Binds signatures to typed intent, rejects stale approvals, queues actions publicly, enables veto, and checks oracle-bound claims. | Dedicated signer devices, attester co-signatures, mandatory out-of-band council confirmation, proposal announcements, signer drills, and strict address books. |
| Durable nonce or long-lived pre-signing | Valid signatures are collected days or months before execution and submitted later. | Requires fresh attestations at queue time and proposal expiry. | Ban informal pre-signing, monitor for durable-nonce usage, require fresh proposal IDs, and alert when old proposal material is reused. |
| Compromised signer laptop | Malware or a malicious frontend lies about what the signer is approving. | The on-chain adapter recomputes the intent from the real call, so mismatched calldata fails. | Use the attester design in `attester/`, separate signer and work machines, hardware wallets, locked-down browser profiles, and device hygiene checks. |
| RPC compromise | A bad RPC lies about simulation, state, labels, oracle values, or whether a proposal is queued. | Reduces trust in RPC-rendered calldata by verifying the real call on-chain at queue and execution. | RPC quorum reads, multi-provider simulation, local or self-hosted nodes for signing, signed address books, independent queue monitors, and circuit breakers. |
| Fake oracle or feed switch | Governance points an action at a new or attacker-controlled feed, then uses that feed for borrowing power. | Adapters can require allowlisted feeds, staleness checks, tolerance checks, and exposure caps. | Separate feed-registration actions from feed-use actions, longer delays for feed changes, multi-oracle adapters, liquidity floors, and bootstrap caps. |
| Bridge or verifier compromise | A verifier, RPC, or cross-chain message path reports false source-chain state. | Not solved by signer intent alone. Intentguard can guard verifier config changes, but not prove remote state by itself. | Multi-verifier bridge settings, RPC quorum reads, source-chain proof verification, message rate limits, withdrawal caps, and emergency circuit breakers. |
| Malicious or rushed upgrade | A signer approves an implementation address without verifying code. | Intent can bind target, implementation, calldata hash, nonce, and expected code hash if the adapter supports it. | Reproducible builds, signed artifacts, independent bytecode verification, upgrade simulations, staged rollout, and longer cool-off for upgrades. |

Short version: intentguard is strongest when the lie is about what the transaction does. For lies about external context, like RPC state, bridge state, or social pressure, pair it with independent verification, monitoring, and an attester.

## The next missing primitive: attester

The biggest remaining weakness is the rendering path. If the council member's laptop is compromised, it can still lie about what the typed intent says before the signer approves it.

The fix is a separate attester: a small, protocol-neutral device or locked-down app with its own key and screen. It receives canonical intent bytes, renders them with an audited schema library, requires physical confirmation, and produces a co-signature over the exact rendered intent.

See [`attester/`](attester/) for the draft spec.

Developers can start without hardware by using [`attester/sdk`](attester/sdk) and the software emulator. The intended path is: build an intent bundle, render it locally, get an emulator attestation in tests, then replace the emulator with a hardware or secure-enclave attester for production.

## EVM integration

1. Deploy `IntentGuardModule`.
2. Initialize a vault from the Safe with the Safe address, signer set, threshold, veto threshold, freshness window, cool-off, execute delay, and proposal lifetime.
3. Deploy protocol-specific adapters for each guarded action.
4. From the Safe, allow each `(target, adapter)` pair.
5. Move ownership of guarded protocol functions to the module, install a Safe Guard that blocks direct calls, or update protected contracts to require calls from the module.
6. Have signers sign the attestation payload over vault, nonce, target, calldata hash, intent hash, adapter, chain ID, module address, and expiry.
7. Queue the proposal with fresh attestations.
8. Monitor the queue during the cool-off.
9. Execute only after the cool-off and execute-delay windows pass, unless enough signers cancel first.

The most important EVM integration rule: enabling a Safe module does not stop Safe owners from bypassing it. You must remove or block direct Safe/admin execution for covered actions.

## Solana integration

1. Deploy the Anchor program in `solana/programs/intentguard`.
2. Initialize one vault per guarded authority.
3. Transfer guarded authority to the vault PDA.
4. Build protocol-specific adapters that decode target instructions, recompute canonical intent hashes, and perform oracle/risk checks.
5. Have signers produce ed25519 attestations over the vault, proposal, nonce, target program, adapter, intent hash, instruction data hash, and expiry.
6. Queue proposals only while attestations are fresh.
7. Monitor queued proposals and use `cancel` if anything is wrong.
8. Execute via CPI after the cool-off and execute delay.

The current Solana program includes the state machine and attestation shape, but adapter validation is intentionally left as an integration point because Solana protocols differ heavily in account layouts and instruction formats.

## Production checklist

- Direct bypass is impossible for covered actions.
- Every action has a deterministic adapter.
- Unknown actions fail closed.
- Signatures bind chain/domain, vault, nonce, target, data hash, intent hash, adapter, signer, and expiry.
- Freshness is checked before queueing.
- The queue emits alerts and is monitored outside the signing UI.
- Veto threshold is calibrated for both incident response and liveness.
- Oracle feeds are allowlisted, fresh, and hard to spoof.
- Thin or new collateral has strict caps or fails closed.
- Adapter and oracle changes use longer delays than routine parameter changes.
- Cross-chain verification has separate defenses: multi-verifier configs, RPC quorum reads, source-chain proofs where possible, and circuit breakers.

## Status

Unaudited. Do not deploy as-is to secure funds.

## Contributors

Add yourself here when you contribute.

- Uwe Cerron, creator
