---
title: intentguard
description: A primitive for closing the web2 attack vector in DeFi. Solana and EVM. Open source.
hero_label: A primitive
hero_title: Closing the web2 attack vector in DeFi.
hero_subtitle: A small on-chain gatekeeper for privileged DeFi actions on Solana and EVM. Built in response to the half-billion dollars stolen from DeFi users at Drift and Kelp in April 2026.
---

## The problem

In April 2026, more than half a billion dollars was stolen from DeFi users at Drift and Kelp. Neither incident was a smart contract bug. Both attackers exploited the gap between what signers thought they were approving and what their signature actually meant on-chain.

The Drift attack was a six-month DPRK social engineering operation. Council members were walked into pre-signing routine-looking transactions via Solana's durable nonces. When the transactions were finally broadcast, the real on-chain effect was admin handover plus the whitelisting of a worthless token at $1.00 as collateral. The attackers minted 500M of that token, deposited it, and withdrew $285M of real assets.

The system performed perfectly. The attackers won anyway.

That class of failure is what this primitive addresses.

## What intentguard does

Intentguard is a small on-chain gatekeeper that sits between a council or multisig and any privileged protocol action: admin transfers, upgrades, collateral whitelists, treasury withdrawals.

It enforces five invariants before execution.

1. **Intent binding.** Each privileged action carries a signed, machine-verifiable intent statement. The on-chain guard recomputes the actual call's intent and rejects the action if it does not match what the signers approved.
2. **Freshness window.** Signatures must be fresh when the proposal is queued (default 10 minutes). This kills the durable-nonce abuse that hit Drift.
3. **Cool-off and veto.** A 24-hour public window during which any K-of-N signers can cancel.
4. **Oracle-bound claims.** Oracle-dependent fields, such as a token's fair value, are checked against live, allowlisted feeds at execute time.
5. **Action whitelist.** Only registered action kinds with deterministic adapters can be queued. Unknown actions fail closed.

A six-month patient social engineering attack collapses into a 24-hour public confrontation. Honest signers, given visibility and time, almost always win that confrontation.

## What it mitigates

| Risk | Mitigated by intentguard? | How |
| --- | --- | --- |
| Stale pre-signed admin transactions | Yes | Signatures must be fresh when the proposal enters the queue. |
| Misleading signer UI or blind signing | Yes | Signers approve a typed intent hash, and the guard checks the real call matches it. |
| Admin transfer to an unexpected address | Yes, if guarded | The adapter must decode the new admin and bind it into the signed intent. |
| Unsafe collateral listing | Yes, if guarded | The adapter binds token, feed, claimed value, caps, and oracle or risk checks. |
| Treasury withdrawal to a wrong recipient | Yes, if guarded | Recipient, asset, amount, and reason can be included in the typed intent. |
| Oracle or feed switch to attacker-controlled feed | Partly | Feed allowlists and slower adapter or feed changes are required. |
| A rushed malicious proposal | Partly | Cool-off and veto give honest signers time to cancel. |
| Compromised signer laptop | Partly | The chain does not trust the laptop display, but the signer key can still approve fresh bad intent if the human is fooled. |
| Smart contract bugs in the guarded protocol | No | Intentguard controls privileged actions, not protocol business logic. |
| Total signer collusion | No | If enough signers knowingly approve and no veto happens, no multisig guard can save the protocol. |
| Cross-chain verifier or RPC compromise | No, not by itself | Bridges need separate multi-verifier, RPC quorum, proof, and circuit-breaker controls. |

## Known limits and fixes

| Failure mode | Why it matters | Prevention or fix |
| --- | --- | --- |
| Direct bypass | If the Safe or admin key can still call the protocol directly, intentguard is only a dashboard. | Transfer guarded ownership to the module or PDA, install a Safe Guard that blocks covered direct calls, or update protected contracts so guarded functions only accept calls from intentguard. Test that direct admin calls revert. |
| Bad adapters | If an adapter misses a field or decodes calldata incorrectly, signers approve an incomplete intent. | Write one adapter per action kind, keep schemas explicit, add unit and fuzz tests for every selector or instruction, include all risk-relevant fields, and require independent review before allowlisting adapters. |
| Generic adapters | An adapter that accepts arbitrary calldata recreates blind signing under a new name. | Fail closed for unknown selectors, unknown targets, unknown accounts, unknown feeds, and unexpected calldata length. Do not allow "execute arbitrary bytes" as a guarded action. |
| Oracle trust | A stale, thin, attacker-controlled, or governance-selected feed can make false claims pass. | Use feed allowlists, staleness checks, confidence checks, liquidity floors, capped bootstrap limits, multi-oracle adapters for high-value assets, and longer delays for feed changes. Do not let the same proposal both add a feed and use it for major borrowing power. |
| Veto liveness | If K is too low, governance can be griefed. If K is too high, honest signers may fail to cancel during an incident. | Set K per vault, run cancellation drills, publish a signer availability rota, require cancellation reasons, and use separate slow and fast vaults for different authority levels. |
| Queue not monitored | A 24-hour delay only helps if people or bots notice the queued proposal. | Emit indexed events, run independent monitors, alert signers out-of-band, mirror proposals to public dashboards, and require every queued action to be announced in the expected council channel. |

## Recommended defenses by attack path

| Attack path | What can go wrong | What intentguard does | What else to add |
| --- | --- | --- | --- |
| Drift-style social engineering | Signers are cultivated over time and tricked into approving admin or collateral changes that look routine. | Binds signatures to typed intent, rejects stale approvals, queues actions publicly, enables veto, and checks oracle-bound claims. | Dedicated signer devices, attester co-signatures, mandatory out-of-band council confirmation, proposal announcements, signer drills, and strict address books. |
| Durable nonce or long-lived pre-signing | Valid signatures are collected days or months before execution and submitted later. | Requires fresh attestations at queue time and proposal expiry. | Ban informal pre-signing, monitor for durable-nonce usage, require fresh proposal IDs, and alert when old proposal material is reused. |
| Compromised signer laptop | Malware or a malicious frontend lies about what the signer is approving. | The on-chain adapter recomputes the intent from the real call, so mismatched calldata fails. | Use the attester design, separate signer and work machines, hardware wallets, locked-down browser profiles, and device hygiene checks. |
| RPC compromise | A bad RPC lies about simulation, state, labels, oracle values, or whether a proposal is queued. | Reduces trust in RPC-rendered calldata by verifying the real call on-chain at queue and execution. | RPC quorum reads, multi-provider simulation, local or self-hosted nodes for signing, signed address books, independent queue monitors, and circuit breakers. |
| Fake oracle or feed switch | Governance points an action at a new or attacker-controlled feed, then uses that feed for borrowing power. | Adapters can require allowlisted feeds, staleness checks, tolerance checks, and exposure caps. | Separate feed-registration actions from feed-use actions, longer delays for feed changes, multi-oracle adapters, liquidity floors, and bootstrap caps. |
| Bridge or verifier compromise | A verifier, RPC, or cross-chain message path reports false source-chain state. | Not solved by signer intent alone. Intentguard can guard verifier config changes, but not prove remote state by itself. | Multi-verifier bridge settings, RPC quorum reads, source-chain proof verification, message rate limits, withdrawal caps, and emergency circuit breakers. |
| Malicious or rushed upgrade | A signer approves an implementation address without verifying code. | Intent can bind target, implementation, calldata hash, nonce, and expected code hash if the adapter supports it. | Reproducible builds, signed artifacts, independent bytecode verification, upgrade simulations, staged rollout, and longer cool-off for upgrades. |

Short version: intentguard is strongest when the lie is about what the transaction does. For lies about external context, like RPC state, bridge state, or social pressure, pair it with independent verification, monitoring, and an attester.

## The attester layer

The biggest remaining weakness is the rendering path. If the council member's laptop is compromised, it can still lie about what the typed intent says before the signer approves it.

The fix is a separate attester: a small, protocol-neutral device or locked-down app with its own key and screen. It receives canonical intent bytes, renders them with an audited schema library, requires physical confirmation, and produces a co-signature over the exact rendered intent.

## Read

The full design, threat model, and reference implementations.

- [Try the attester live in your browser](playground.html)
- [Whitepaper](intentguard.html)
- [How to use it](docs/HOWTO.html)
- [Attester spec](attester/spec/ATTESTER_SPEC.html)
- [Source code on GitHub](https://github.com/uwecerron/intent-guard)

## Why this matters

Most DeFi users turned to crypto because the existing financial system already failed them. When DeFi gets drained, they lose their savings, not the VCs.

We built a system for the debanked and wired it to a signing UX that fails the moment a recruiter sends a Calendly link.

This is one piece of a fix.

## Status

Reference design and reference implementations. Unaudited. Open for review, forks, and audits.

If you deploy intentguard, fork it, or audit it, get in touch. If you find a flaw in the design, get in touch faster.
