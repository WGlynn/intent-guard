# Debanking the debanked
## A primitive for closing the web2 attack vector in DeFi

**uwe cerron**
[tradersguild.global](https://www.tradersguild.global/) · [@traders_guild](https://x.com/traders_guild)
*April 2026*

---

## Abstract

In April 2026, more than half a billion dollars was stolen from DeFi users through two major incidents at Drift and Kelp. The exact attribution and post-mortems are still developing, but the pattern is already clear. Neither incident was a simple "missed reentrancy bug" story. Drift exposed the gap between what a council signer *thought* they were authorizing and what their signature later approved on-chain. Kelp exposed a related control-plane failure in cross-chain verification and RPC trust. This paper characterizes that broader class as the **web2 attack vector** in DeFi: failures in the human, signing, verifier, RPC, governance, and operational layer around smart contracts. It proposes **intentguard**, a small on-chain primitive for the privileged-action subset of that problem. Intentguard binds guarded actions to signed, machine-verifiable intent statements; enforces freshness at queue time (defeating durable-nonce abuse like Drift); imposes a 24-hour cool-off with K-of-N veto; and rejects oracle-dependent claims that disagree with live, allowlisted oracle readings.

---

## 1. Plain-English version

Intentguard is a bouncer for dangerous protocol actions.

Today, a multisig signer often signs a blob of transaction data and hopes the wallet, laptop, RPC, and UI told the truth about what the blob does. Intentguard changes that. A dangerous action has to arrive with a plain, typed statement of intent, such as:

> "List token CVT as collateral, price it with this exact oracle feed, cap deposits at this amount, and apply these risk limits."

The chain then checks the statement against the actual transaction before the action can move forward. If the transaction says one thing and the intent says another, it fails.

It also adds time pressure in the defender's favor. Signatures must be fresh when the proposal is queued, so an attacker cannot collect signatures in March and fire them in April. After enough fresh signatures are collected, the action still waits in public for 24 hours. During that window, a smaller veto group can cancel it.

So the primitive does three simple things:

1. It makes signers approve the meaning of an action, not only opaque transaction bytes.
2. It makes old signatures useless.
3. It gives honest signers a public window to notice and stop a bad action.

For oracle-sensitive actions, it adds a fourth rule: governance cannot simply assert that a token is worth $1.00. The guard checks an allowlisted live oracle or risk adapter, and rejects claims that disagree too much with reality.

This does not make DeFi safe by itself. It does not fix buggy contracts, compromised bridges, malicious oracles, weak laptops, or total signer collusion. It is narrower than that. It protects the privileged-action path where councils, multisigs, and developers change protocol power.

---

## 2. Who actually loses

Before any of the technical content, a clarification about who this paper is for.

The most common framing of a DeFi exploit is the dollar amount. Two hundred eighty-five million. Two hundred ninety million. The number is the headline; the headline is the story. But the dollar amount is also the most misleading thing about these incidents, because it implies the loss was distributed across people who could afford to lose it.

It wasn't.

DeFi's user base is not, mostly, the venture investors who funded the protocols. Disproportionately, it's people who turned to crypto because the existing financial system had already failed them. An Argentinian saving against ARS hyperinflation. A Lebanese family preserving capital after the banking collapse. A Filipino freelancer accepting USDC because her bank charges 7% on inbound wires. A Nigerian developer working remotely whose USD account got frozen for "compliance review" three months ago. These are the people who load up on stablecoins and put them in the protocols that promise yield. When the protocols get drained, *they* get drained. The VCs are diversified. The LPs are not.

This is the deepest moral problem with the current state of the space: **we built a financial system for the people the existing one excluded, and then we wired it to a signing UX that fails the moment a recruiter sends a Calendly link.** The end result is debanking the already-debanked. Twice.

This paper is not an apology for that. It's a small, concrete proposal for one piece of the fix.

---

## 3. The Drift incident, honestly

On April 1, 2026, $285M was drained from Drift Protocol on Solana. Two weeks later, Kelp / LayerZero was drained for roughly $290M. Public reporting has linked both incidents to DPRK-aligned operators, though the precise attribution labels and confidence levels differ across sources. The incidents should not be collapsed into one identical root cause. Drift is the clean example for this paper: a privileged signer and control-plane failure. Kelp is a neighboring warning that DeFi is increasingly dependent on off-chain and cross-chain control systems whose failure can be just as destructive as a contract bug.

The Drift attack chain, in plain terms:

1. **Six months earlier**, individuals presenting as a quantitative trading firm approached members of the Drift Security Council at industry conferences across multiple countries. They were not themselves North Korean nationals. DPRK threat actors at this level operate through third-party intermediaries to do the in-person rapport work. They built relationships. They proposed integrations.
2. **Over the following months**, Council members were walked through "integration transactions" that needed pre-signing. Solana's **durable nonces** feature allows a transaction to be signed now and submitted later. Useful for legitimate orchestration, fatal in this context. Each signature looked routine in isolation.
3. **On April 1, 2026**, the pre-signed transactions were finally broadcast together. The actual on-chain effect was admin handover and the whitelisting of a worthless token (CVT) at an artificially declared fair value of $1.00. The attackers then minted 500M CVT, deposited it as collateral, and withdrew $285M of real assets, including USDC, SOL, and ETH.

What matters about this attack is what it didn't need. It did not exploit a bug in any Drift contract. It did not break any cryptographic primitive. The Solana program that processed the transactions did exactly what it was told. The signers' keys were not stolen. Every signature was produced by a legitimate Council member, sitting at a legitimate machine, voluntarily. **The system performed perfectly. The attackers won anyway.**

That's the diagnosis we have to face, because no amount of additional auditing of the Drift contracts would have prevented it.

Kelp matters here for a different reason. The reported failure mode was not a council signing a disguised admin action. It was a cross-chain verification setup that accepted forged state after RPC and verifier compromise. Intentguard, as described below, would not by itself have stopped that class of bridge failure. It belongs in the threat model because it proves the same higher-level point: DeFi's most dangerous risks increasingly live in the control plane around contracts, not only inside contract code.

---

## 4. The web2 attack vector

The "web2" in *web2 attack vector* refers to the conventional infrastructure that surrounds privileged protocol operation: the laptop, the browser, the wallet UI, the RPC endpoint, the bridge verifier, the CI/CD system, the dependency graph, the chat room, and the human's understanding of what they're being asked to do. Web3's threat models tend to treat too much of this as out of scope. Protocols often assume that whatever calldata arrives on-chain *is what the signer intended*, and that whatever a verifier reports reflects the source chain.

This assumption is empirically false at scale. The complete kill chain shows up in incident after incident:

- **Drift (2026):** Long-form social engineering, then durable-nonce pre-signing, then admin handover.
- **Radiant Capital (2024):** Spear-phishing of multiple developers via fake job offers, malicious PDFs and npm packages, and signed transactions whose calldata had been silently rewritten before reaching the hardware wallet.
- **Munchables-adjacent incidents (2024):** A developer placed by a recruiter as an internal hire eventually signed the malicious deployment.
- **WazirX (2024):** Compromised signer environments led to a single multisig transaction draining ~$235M.
- **Atomic Wallet (2023):** Compromise of the wallet update channel meant users' "legitimate" software was signing transactions they couldn't have understood.

The pattern is consistent. The signing surface, where a human's intention is supposed to become an on-chain fact, is the weakest link in the entire stack. It is weak because **the chain has no idea what the human thought they were doing.** The signer signs `tx_data`. The `tx_data` does whatever it does. There is no semantic accountability between the two.

Auditors don't fix this. Hardware wallets don't either. A Ledger displays the calldata it was handed; the calldata it was handed is whatever the laptop chose to hand it. Multisigs don't fix this. They raise the bar to N humans, and Lazarus has demonstrated repeatedly that N humans can be cultivated over six months. Bug bounties don't fix this. There is no bug.

What's missing is a primitive that *does not trust the signer's screen* for privileged actions, and an operational discipline that does not trust a single web2 control point for cross-chain or oracle truth.

---

## 5. The intentguard primitive

Intentguard is a small on-chain gatekeeper that sits between the multisig signer set and any privileged action: admin transfers, upgrades, collateral whitelists, treasury withdrawals. It enforces five invariants before execution. None of them require trusting that the signer's wallet UI accurately rendered what was signed. All of them are enforced by the chain itself.

### 5.1 Intent binding

Every privileged action ships with a structured **Intent statement**, a canonical, schema-typed description of what the action is supposed to do. For example:

```
WhitelistCollateral {
    token:           CVT,
    fair_value_usd:  1.00,
    oracle:          Pyth/CVT-USD,
    max_deposit_usd: 500_000_000,
}
```

The signer's signature covers the proposal domain, vault, nonce, target, call data hash, typed intent hash, chain ID or genesis hash, and expiry. Before the proposal can enter the queue, the on-chain guard recomputes the typed intent through an allowlisted **action adapter** for that action kind and target. If the adapter's decoded intent does not match the embedded intent hash, the proposal is rejected.

This breaks the core attack class. A signer's approval can no longer be repurposed for an action they didn't see, because the chain itself verifies that the action they saw and the action being executed are the same object.

This adapter requirement is not optional. A generic guard cannot infer human intent from arbitrary EVM calldata or arbitrary Solana instructions. Each guarded action needs a deterministic decoder that turns the concrete call into the canonical intent object. Unknown actions are rejected.

### 5.2 Freshness window

This is the invariant that closes the specific vector that hit Drift. Each signer attestation includes a `signed_at` timestamp and an `expires_at` timestamp signed by that signer. At queue time, the guard rejects the proposal if any attestation is older than `FRESH_WINDOW_SECS` (default 600 seconds, 10 minutes), if any attestation is already expired, or if the spread between the oldest and newest attestation exceeds the window.

A pre-signed transaction can no longer sit dormant for months waiting to be paired with other pre-signed transactions in a fatal cluster. Either the attestations are fresh when the proposal enters the public queue, or they're invalid. Solana durable nonces and EIP-712 off-chain signatures both lose the property that made them weaponizable: persistence. Execution after the 24-hour cool-off checks that the queued proposal was validly queued, has not been cancelled, has not passed its proposal-level expiry, and still matches the vault nonce or dependency rules.

### 5.3 Cool-off and veto

Even with intent binding and freshness, an attacker who controls enough signers to meet quorum within a 10-minute window can still queue a malicious proposal. The cool-off invariant introduces a *separate* trust check. Once the proposal collects its `M`-of-`N` signatures, it enters a queued state for `COOLOFF_SECS` (default 24 hours). During this window, **any `K` of the `N` signers can cancel** with a single transaction.

The hypothesis is straightforward. Getting `M` signers to actively sign a deceptive proposal in 10 minutes is achievable for a patient social-engineering operation. Getting a different `N − K + 1` signers to fail to notice a queued proposal for 24 hours, when the queue is publicly visible and emits standard events that any monitoring tool consumes, is much harder.

A six-month patient attack collapses into a 24-hour public confrontation. The legitimate signers are much more likely to win that confrontation, because they are the majority and they have time.

This introduces an explicit liveness tradeoff. If `K` is too low, a minority can grief the protocol by vetoing every proposal. If `K` is too high, the veto stops being useful during an incident. Production deployments should set `K` per vault, require a structured cancellation reason, emit high-severity cancel events, and give proposals an expiry so stale queued actions cannot sit forever.

### 5.4 Oracle-bound claims

In the Drift attack, the fatal step was the protocol believing that CVT was worth $1.00 when its actual market price was effectively zero. The signers were tricked into approving an Action whose `fair_value_usd` field was a lie, and the protocol believed the lie because nothing on-chain was checking.

For any Intent field marked `oracle_bound` in the schema (`fair_value_usd`, `tvl_after`, `oracle_used_for_pricing`, etc.), the guard reads an allowlisted on-chain oracle at execution time. Pyth on Solana, Chainlink on EVM, or a protocol-approved multi-oracle adapter are reasonable choices. The guard rejects the action if the oracle reading deviates from the claimed value by more than `ORACLE_TOLERANCE_BPS` (default 200 bps), if the oracle reading is staler than `ORACLE_MAX_STALENESS_SECS` (default 60 seconds), if the oracle confidence interval is too wide, or if the feed identity does not exactly match the feed approved for that asset.

The Drift attackers, under intentguard, would have had to either manipulate Pyth (orders of magnitude harder than what they actually did), or get the signers to approve an Action explicitly stating `fair_value_usd = $0.0001`. The second option is the kind of thing a human reviewing a rendered intent would notice.

New collateral listings are the hard case. If an asset does not yet have a deep, independent feed, the correct behavior is not to let governance provide a price by assertion. The guarded action should either fail, cap exposure at a deliberately small bootstrap limit, or require a separate risk-adapter policy that checks liquidity, feed history, and maximum debt exposure.

### 5.5 Action whitelist

Each guarded vault declares an explicit whitelist mapping `action_kind -> allowed_targets -> adapter`. Anything outside the whitelist is rejected, even if every other invariant passes. This prevents the "we'll just register a new harmless-looking action type" escalation. Adding a new action kind itself goes through intentguard and should use a longer cool-off than ordinary parameter changes. There is no emergency escape hatch.

### 5.6 What is deliberately absent

The reference design intentionally excludes an emergency-bypass key. Many timelock implementations ship one, and in practice the bypass key is what gets stolen. The cool-off is the whole point of the primitive. Teams that legitimately need a faster path for emergencies should configure two vaults: a slow vault for non-time-critical admin authority, and a fast vault with smaller authority and a shorter cool-off for emergency response. The slow vault must not be reachable from the fast vault.

---

## 6. State machine

```
[Drafted] ──collect signatures──▶ [Pending]
                                     │ all M signatures + freshness valid
                                     ▼
                                  [Queued]
                                     │ now ≥ t_queued + COOLOFF_SECS + EXECUTE_DELAY
                                     ▼  (and not cancelled)
                                  [Executable] ──execute──▶ [Executed]
                                     │
                                     │ K cancellations during cool-off
                                     ▼
                                  [Cancelled]
```

Freshness is checked on the transition from `Pending` to `Queued`, not on final execution. `EXECUTE_DELAY_SECS` (default 60s) is a small additional window after cool-off elapses during which `cancel` still wins. It defends against a malicious signer racing `execute` past `cancel` at the moment cool-off expires.

Replay protection is enforced by a monotonically increasing per-vault `nonce` or by per-action dependency nonces. The simplest design uses one vault nonce. A proposal carries the `nonce` value at draft time and may only execute if `proposal.nonce == vault.nonce`. Execution increments the vault nonce, invalidating any other proposal still queued under the old nonce. This is conservative but serializes governance and can be griefed by queuing a harmless action ahead of an urgent one. Higher-throughput deployments should use scoped nonces such as `nonce[action_kind][target]`, plus explicit dependency declarations for actions that must be globally ordered.

---

## 7. Reference implementations

The intended reference implementations are a Solana Anchor program and an EVM Safe-compatible module, both following the same SPEC. Until those implementations are published and audited, this paper should be treated as a design proposal, not a ready-to-deploy security product.

### 7.1 Solana Anchor program

A single Anchor program, `intentguard`, deployable on Solana mainnet, devnet, or localnet. The program holds a `Vault` account per guarded protocol and a `Proposal` account per pending action. Instructions are `init_vault`, `draft_proposal`, `attest`, `cancel`, `raise_alarm`, and `execute`. Oracle reading is sketched against Pyth `PriceUpdateV2` accounts. Integrators must vendor in the appropriate Pyth or Switchboard SDK rather than trust an unimplemented stub.

The Solana implementation is roughly 400 lines of Rust. It is unaudited.

### 7.2 EVM Safe Module

`IntentGuardModule.sol` is a Safe-compatible module that gatekeeps privileged calls. It mirrors the Solana state machine and uses Chainlink AggregatorV3 feeds or an approved oracle adapter for oracle-bound claim verification. The module is added to a Safe via the standard `enableModule` flow.

There is a critical integration constraint. Enabling a Safe module does not automatically prevent Safe owners from bypassing the module with a direct Safe transaction. A protected protocol must either transfer privileged ownership from the Safe to the IntentGuard module, install a Safe Guard that blocks direct calls to covered targets, or update the protected contracts so only the module can invoke guarded functions. Otherwise intentguard is advisory, not enforceable.

The Solidity implementation is roughly 300 lines. It is unaudited. A Foundry test scaffold demonstrates the happy path, the stale-signature reject, and the veto-during-cool-off case.

### 7.3 Signer client

A reference signer CLI (`signer-cli.ts`) walks a human signer through reviewing the *rendered* intent of a proposal: decoded action arguments, live oracle reading, deviation warning, all before producing a signature. The CLI deliberately demands the signer type the action kind in capital letters as confirmation. This is the minimum out-of-band step. The strongest deployment pairs each signer with a separate attester device whose only job is to display intent and sign approval. The on-chain layout supports this without modification.

---

## 8. Usability, implementation cost, and how to use it

This section addresses the practical questions a protocol team would ask before adopting intentguard: how disruptive is it for signers, how hard is it to build into an existing system, what does the state machine feel like in day-to-day operations, and which deployment pattern fits a given protocol.

### 8.1 The signer experience

Before intentguard, a typical Solana council member signs a Squads transaction by clicking "Approve" inside a multisig UI on their laptop. The bytes they're approving are largely opaque. After intentguard, the same signer sees a rendered intent statement that names the action in plain language, lists every parameter in canonical units, shows the live oracle reading next to the claimed value, and refuses to produce a signature unless the signer types the action kind in capitals.

That added friction takes about 30 seconds per signature for a routine parameter change, and 1 to 3 minutes for a large or unfamiliar action while the signer reads the rendered intent and ideally confirms with one other council member out of band. For most protocols this is on the order of one extra minute per privileged action. The cost is small enough that signers will accept it, large enough that they actually read the screen.

There are two real usability complaints to expect. First, signers will mistype the action kind on the first attempt and have to retry. This is by design. Second, the 24-hour cool-off will frustrate teams used to landing parameter changes the same hour they're proposed. Reframe this internally. Most actions don't need same-hour landing, and the actions that feel like they do are exactly the actions that should not bypass the cool-off.

### 8.2 The state machine in practice

The state machine is small enough to remember without a diagram. Five states, three meaningful transitions:

1. A council member opens a proposal. It enters `Drafted`.
2. Other council members attest within a 10-minute window of each other. The proposal moves to `Pending` after the first attestation, and to `Queued` once the M-of-N quorum is reached and freshness checks pass.
3. The proposal sits in `Queued` for 24 hours. During that window any signer can `cancel`. K cancellations move it to `Cancelled`. Otherwise after 24 hours plus a 60-second execute delay, anyone can call `execute`, which moves it to `Executed`.

The states are durable on-chain. A signer can leave their laptop, get on a plane, land somewhere else, open a phone, and see the same proposal in the same state. There are no off-chain coordination points where state can drift.

Day-to-day, the operational pattern looks like this. A risk team drafts a proposal at 09:00. Council members attest between 09:05 and 09:15. The proposal queues at 09:15 with `executable_at` set to 09:16 the next day. The risk team posts the rendered intent in a public channel and a private signer channel. Anyone, including the public, can review the queue and raise an alarm. If nothing changes, the action executes at 09:16 the next morning.

Two operational anti-patterns to refuse from day one. Don't let the same person who drafted a proposal also be the first to attest. Don't let the team treat the cool-off as a formality. The cool-off is the defense.

### 8.3 How hard is this to implement

The reference implementations are deliberately small. The Solana program is on the order of 400 lines of Rust. The EVM Safe module is on the order of 300 lines of Solidity. Both are within reach of a single mid-level engineer working with a security reviewer over two weeks for a first draft, plus another two weeks of testing.

The actual integration cost for a protocol is in three places, in roughly increasing order of difficulty.

**Action adapters.** Each guarded action needs a deterministic decoder that turns the call into a canonical intent object. For a protocol with five guarded actions (whitelist collateral, set risk parameter, change oracle, transfer admin, withdraw treasury), this is roughly a day per adapter, plus tests. The adapters are the part that actually understands the protocol; intentguard itself does not.

**Authority migration.** Today, most protocols have a Safe or council keypair as the direct admin. To enforce intentguard you have to move privileged authority from that key to the intentguard module or PDA. On EVM that means changing every `onlyOwner` modifier path so the new effective owner is the intentguard module, or installing a Safe Guard that blocks direct calls. On Solana that means rotating upgrade authority and any program admin PDAs to one derived from the vault. This is the riskiest part of the migration because it's a one-way change for the privileged surface, and it's where you discover that you had three forgotten admin paths.

**Signer tooling.** Council members need a client that can render intent and produce attestations. The reference signer CLI is a starting point, but most teams will want a small web UI or wallet plugin built on top so the signing experience matches what their council is used to. Estimate one to three weeks of front-end work for a polished version.

For a small DeFi protocol with a single Safe and a handful of guarded functions, the full integration is two engineers for four to six weeks, including audit. For a complex protocol with many guarded functions, multiple chains, and a custom signer experience, plan on a quarter.

### 8.4 Recommended deployment patterns

There is no single right shape. Pick one of the patterns below based on protocol size and operational maturity.

**Pattern A. Small protocol, single chain.** One vault with a 5-of-7 council, K=2 veto, 24-hour cool-off, 10-minute freshness. Adapters for whitelist collateral, set risk parameter, change oracle, transfer admin. The whole council reviews everything. Weekly queue review on a public call. This is the minimum viable deployment and it would have stopped Drift.

**Pattern B. Large protocol, multiple privileged surfaces.** Two vaults: a slow vault with 7-of-11 council and 48-hour cool-off for upgrades, admin changes, and new collateral types; a fast vault with 4-of-7 council and 4-hour cool-off for parameter tuning within pre-approved bands. The fast vault has no authority over the slow vault. Cancel events from either vault page on-call.

**Pattern C. Treasury and governance separation.** One intentguard vault for treasury withdrawals, distinct from the protocol admin vault. Treasury vault uses tighter K (lower veto threshold) and longer cool-off (72 hours) because treasury withdrawals are rarely time-critical. Withdrawals over a configurable amount also require a per-action attestation from a separate finance committee.

**Pattern D. Cross-chain deployment.** One intentguard per chain. Cross-chain admin actions are coordinated at the protocol layer, not by intentguard. Pair this with multi-verifier bridge configuration and circuit breakers, because intentguard cannot defend the bridge surface itself.

### 8.5 What to do first

If a team has 30 minutes and wants to start adopting intentguard today:

1. List every privileged function on the protocol. Treasury withdrawals, parameter changes, oracle updates, upgrade calls, role grants. This list is usually shorter than expected and longer than remembered.
2. For each one, write the intent schema in plain words. What does a human need to see to know whether to sign it.
3. Pick a deployment pattern from 8.4 that fits.
4. Schedule the migration window. Authority migration is the only one-way step.

Most teams do not need a custom primitive to start. Begin with the reference implementations, audit them in your own context, and contribute fixes back. The point of an open primitive is that adoption multiplies the security review.

---

## 9. What intentguard does not solve

Being honest about scope is what separates a real security primitive from theater.

**Smart-contract bugs are out of scope.** Intentguard gates the *human-authorized* surface. If the protocol contract being guarded has a bug, such as a re-entrancy, a faulty oracle integration, or a math error, intentguard cannot help. Audit your contracts.

**Oracle compromise and thin-market pricing are out of scope.** The oracle-bound claim invariant assumes the chosen oracle and feed selection are honest. If Pyth or Chainlink is manipulated, if governance can choose a malicious feed, or if the asset has no meaningful market, intentguard's oracle check can be manipulated. Use feed allowlists, confidence checks, TWAPs, liquidity floors, and multi-oracle aggregation for high-value parameters.

**Total signer collusion is out of scope.** If `M` signers and `N − K + 1` other signers all collude, intentguard does not help. No multisig primitive does.

**The legitimate cancel-channel must work.** The cool-off only matters if the legitimate signers can actually communicate during it. Operational practice (secure messaging, periodic queue reviews, third-party monitoring) is part of the deployment, not the code.

**Cross-chain message intent is genuinely hard.** Bridge messages with "intent on chain A -> effect on chain B" semantics are not closed by single-chain intent binding. This is open work.

**Verifier and RPC compromise are not solved by signer intent.** The Kelp-style failure mode requires independent mitigations: multi-verifier bridge configuration, client diversity, RPC quorum reads, source-chain proof verification where possible, circuit breakers, and monitoring for impossible state transitions.

What intentguard *does* do is collapse the privileged-action signing attack class exemplified by Drift. It does not promise more than that. It does not need to.

---

## 10. Deployment review checklist

Intentguard is only real protection if these checks are true:

- **No direct bypass.** The guarded contract must reject direct Safe or admin calls for covered functions. Calls must come through intentguard, or intentguard is only a dashboard.
- **Action adapters exist.** Every guarded action must have a deterministic adapter that decodes the actual call into the canonical intent. Unknown actions fail closed.
- **Domain separation is complete.** Signatures must bind the vault, chain, program or contract, nonce, target, calldata hash, intent hash, signer, and expiry.
- **Freshness happens before queuing.** Signatures are checked when a proposal enters the public queue, not after the cool-off.
- **The queue is monitored.** Signers and external monitors need alerts for every queued proposal, cancellation, failed execution, and adapter change.
- **Veto is calibrated.** `K` must be low enough to stop a real incident, but not so low that one or two signers can permanently freeze governance.
- **Oracle feeds are allowlisted.** Governance should not be able to point a collateral listing at a fresh, attacker-controlled feed.
- **Thin assets are capped.** New or illiquid collateral should fail closed, or launch behind strict exposure caps and longer delays.
- **Adapter changes are slower.** Adding a new action kind, target, oracle, or adapter should have a longer cool-off than routine parameter changes.
- **Emergency power is scoped.** Fast-response vaults may exist, but they should control only limited emergency functions and should not be able to bypass the slow vault.
- **Cross-chain systems use separate defenses.** Bridge messages need multi-verifier settings, RPC quorum reads, circuit breakers, and source-chain proof validation where possible.

---

## 11. Deployment

Once an implementation exists, adopting intentguard is mechanical:

1. **Solana protocols.** Deploy the `intentguard` program. For each privileged authority (admin keypair, upgrade authority, treasury PDA), initialise a `Vault` whose signer set is the existing Council. Migrate authority from the bare keypair to a PDA derived from the Vault. Update the off-chain signing tooling to draft Proposals and attest via the CLI.
2. **EVM protocols.** Deploy `IntentGuardModule` against your existing Safe. Enable the module via the Safe UI. Migrate guarded ownership from the Safe to the module, or install an enforcing Safe Guard that prevents direct Safe bypass for covered targets. Any `onlyOwner` call path that still accepts direct Safe execution remains outside intentguard.

Migration cost is low. The change in operational tempo is significant. Actions that previously executed in minutes will now execute in 24 hours minimum. That's the cost. That's also the point.

---

## 12. Why this matters, restated

The DeFi space has spent the last several years optimizing for the wrong threat model. We have invested heavily in formal verification of contract logic and almost nothing in the question of how a human's intention becomes an on-chain fact. The result is that Lazarus does not need to break our cryptography. They need to send a Calendly link, fly an intermediary to a conference, and wait six months. The cost-per-dollar-extracted is, by any measure, the most efficient extraction operation in the history of finance.

The people paying that cost are not the people who can afford it.

A 24-hour cool-off doesn't sound like much. It's the difference between a six-month patient operation and a fair fight. Intent binding doesn't sound like much. It's the difference between a signature meaning *"I approve transferring admin to attacker_wallet"* and a signature meaning *"I approve a routine integration tweak"*. These are small primitives. They are also the smallest primitives that get the user base the security guarantees they were promised.

This is open. Fork it. Improve it. Audit it. Deploy it. Or build something better and tell me about it. The point is to stop debanking the debanked.

---

## References

1. *$285 Million Drift Hack Traced to Six-Month DPRK Social Engineering Operation.* The Hacker News, April 2026. https://thehackernews.com/2026/04/285-million-drift-hack-traced-to-six.html
2. *The Drift Protocol Hack: How Privileged Access Led to a $285 Million Loss.* Chainalysis, April 2026. https://www.chainalysis.com/blog/lessons-from-the-drift-hack/
3. *LayerZero blames Kelp's setup for $290 million exploit, attributes it to North Korea's Lazarus.* CoinDesk, April 2026. https://www.coindesk.com/tech/2026/04/20/layerzero-blames-kelp-s-setup-for-usd290-million-exploit-attributes-it-to-north-korea-s-lazarus
4. *Drift crypto platform confirms $280 million stolen in hack as researchers point finger at North Korea.* The Record from Recorded Future News, April 2026. https://therecord.media/drift-crypto-confirms-280-million-stolen-north-korea
5. *Drift Protocol Exploit: Why "Social Trust" Is the Newest Cybersecurity Gap.* Crowell & Moring LLP, April 2026. https://www.crowell.com/en/insights/client-alerts/drift-protocol-exploit-why-social-trust-is-the-newest-cybersecurity-gap
6. *North Korean Hackers Pose as Trading Firm to Steal $285M from Drift.* HackRead, April 2026. https://hackread.com/north-korean-hackers-trading-firm-drift-protocol/
7. Solana Labs, *Durable Transaction Nonces.* Solana Documentation. https://docs.solana.com/implemented-proposals/durable-tx-nonces
8. Pyth Network, *PriceUpdateV2 account format.* Pyth Documentation. https://docs.pyth.network/
9. Chainlink, *AggregatorV3Interface.* Chainlink Developer Docs. https://docs.chain.link/data-feeds
10. Safe (formerly Gnosis Safe), *Module Architecture.* Safe Documentation. https://docs.safe.global/
11. *KelpDAO/LayerZero Exploit Drains $290m, Freezes DeFi Markets.* Galaxy Research, April 2026. https://www.galaxy.com/insights/research/kelpdao-layerzero-exploit-defi

---

## License and attribution

This whitepaper is © 2026 Uwe Cerron and is released under **Creative Commons Attribution 4.0 International (CC BY 4.0)**. You are free to share, adapt, translate, and build upon it for any purpose, including commercially, provided you give appropriate credit to the author.

Any reference implementations published alongside this paper (Solana Anchor program, EVM Safe Module, signer CLI) should be released under the **MIT License**, copyright © 2026 Uwe Cerron and contributors. Forks and derivative works must preserve the MIT copyright notice.

Cite as:

> Cerron, U. (2026). *Debanking the debanked: A primitive for closing the web2 attack vector in DeFi.* tradersguild.global.

## Contact

- Web: [tradersguild.global](https://www.tradersguild.global/)
- X: [@traders_guild](https://x.com/traders_guild)

*Reviews, forks, and audits are welcome and necessary. Intentguard is not a product. It's a primitive offered as a public good in response to a problem that has cost real people their savings. If it helps even one protocol avoid being the next headline, the work was worth it.*
