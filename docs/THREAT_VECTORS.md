# Threat Vectors — adapter coverage

This document maps each fork adapter to the specific class of governance / admin attack it defends against, with reference incidents where the attack class has been demonstrated in the wild.

The intent-guard module's role is the **second layer**: it catches the case where signers were socially engineered into approving a call whose effect they didn't fully understand. The adapters' role is the **third layer**: even if a signed intent matches an action signers approved, the adapter's policy state can refuse the call at execute time when the action falls outside pre-registered safe parameters.

## UUPS proxy implementation swap

**Adapter**: `UUPSUpgradeAdapter`

**Attack class**: An attacker pre-signs an upgrade approval to `address X`, then between sign-time and execute-time replaces the bytecode at `X` (CREATE2 + SELFDESTRUCT redeployment is the canonical path). The signed intent still matches the address, but the runtime behavior is now whatever the attacker substituted.

**Defense**: The adapter records an expected EXTCODEHASH for `(proxy, impl)` at policy registration. `validate()` reads `newImpl.codehash` at execute time and rejects any mismatch. Even if signers approved the address, the bytecode at the address must match.

**Reference incidents**: Various near-miss patterns documented in audit reports for protocols using mutable CREATE2 deployments. Less common in production due to recent EVM changes (SELFDESTRUCT semantics post-Cancun), but the defense is cheap and forward-compatible.

## Treasury withdrawal substitution

**Adapter**: `DAOTreasuryAdapter`

**Attack class**: Signers approve "withdraw 100k USDC to address X" but the executor passes calldata for "withdraw 10M USDC to address Y" — same selector, different decoded fields. The signed intent doesn't match the actual call, but if the system only checked the selector or only the function name, the bait-and-switch would land.

**Defense**: Intent binding — `(recipient, asset, amount)` are all in the signed intent hash. The executor's data must produce the same intent hash to execute. Plus per-asset caps enforced at validate(): even if signers approve a 10M withdrawal within technical bounds, the cap rejects it.

**Reference incidents**: Drift Protocol's social-engineering window documented use of stale pre-signed transactions for treasury operations. The freshness invariant (10-min default) closes this.

## LayerZero peer substitution

**Adapter**: `CrossChainPeerAdapter`

**Attack class**: An attacker tricks signers into peering an OApp on a remote chain to an attacker-controlled contract. The local OApp will then accept inbound messages from that contract as authentic, giving the attacker a forged-message channel into the protocol.

**Defense**: Per-OApp EID allowlist (no peering to unrecognized chains) plus per-EID peer pinning (the peer address must match what the adapter owner registered). Even if signers approve a malicious peer on a known EID, the pinning gate fires at validate().

**Reference incidents**: Cross-chain protocols have been the highest-loss attack surface in DeFi in 2022-2024 (Wormhole, Ronin, Nomad, Multichain). Peer-config attacks on LayerZero V2-style designs are a forward-leaning concern.

## AccessControl privilege escalation

**Adapter**: `RoleGrantAdapter`

**Attack class**: An attacker doesn't need to compromise the implementation contract — they just need a signer to approve `grantRole(ADMIN_ROLE, attacker_account)`. Once the role is granted, the protocol's own access-checked functions become the attack surface.

**Defense**: Per-(target, role) account allowlist for grants — even if signers are fooled into approving a privilege escalation, only pre-registered accounts can be granted privileged roles. Plus per-role frozen flag for roles that should never change membership post-launch.

**Reference incidents**: Many DeFi protocols have suffered privilege-escalation events through governance, including some where the attacker controlled enough governance tokens to vote a role grant through a malicious DAO proposal. The on-chain freeze cannot be undone by a vote.

## Pause-without-unpause

**Adapter**: `PausableAdapter`

**Attack class**: An attacker triggers an emergency pause on a protocol while user funds are deposited but withdrawals haven't executed. Without an unpause path that's gated separately, the funds are locked indefinitely while the attacker positions elsewhere or extracts via an unprotected route.

**Defense**: Per-target independent gating of pause and unpause. A protocol can configure pause as low-friction (fast emergency response) while unpause requires the slower vault path. Or use lock-once mode (pause allowed, unpause permanently blocked) for irrevocable kill-switches.

**Reference incidents**: Several DeFi protocols have been "pause-griefed" — paused by a compromised admin and held in that state while value drains. Different gating per direction prevents this without requiring symmetric admin authority for both.

## Ownership transfer

**Adapter**: `OwnershipTransferAdapter`

**Attack class**: The protocol-ending event. `transferOwnership(attacker)` makes the attacker the root of every Ownable hierarchy in the contract. `renounceOwnership()` permanently locks the protocol with no path to upgrade or recover.

**Defense**: NewOwner allowlist for transfers (only pre-registered owner candidates can be set). Renounce default-disabled per target — owner must explicitly opt-in to the irreversible action.

**Reference incidents**: The default Ownable pattern (OZ) has been the source of many critical incidents, including some where signers approved a transfer to what they thought was a multisig but was actually an attacker EOA. Address allowlist binding prevents this regardless of signer state.

## Numeric parameter drift

**Adapter**: `BoundedParameterAdapter`

**Attack class**: An attacker doesn't change anything dramatically in any single proposal — they propose a series of small changes, each within bounds, that cumulatively defeat the cap. A circuit-breaker volume cap drifts from 1M to 1.5M to 2.25M to 3.4M over a year of "minor adjustments," each within the per-proposal bounds, but cumulatively far above any rational ceiling.

**Defense**: Per-proposal max-change ratio from a registered baseline. The owner advances the baseline only after legitimate changes through `updateBaseline()`. Drift attacks where each step is "small" still get caught because each step is measured against the baseline, not against the previous proposal.

**Reference incidents**: Documented as a class of attack in formal-methods literature (e.g. Klaus Wuestefeld's work on DeFi parameter governance). Less dramatic than single-event exploits but enables long-game extraction.

## Malicious Merkle root substitution

**Adapter**: `MerkleRootSetAdapter`

**Attack class**: An attacker computes a Merkle tree off-chain that includes their addresses with inflated allocations, then tricks signers into setting the resulting 32-byte root. The bare bytes32 has no semantics signers can verify — they must trust whoever provided the root.

**Defense**: Pre-announcement gate. The adapter owner must call `announceMerkleRoot(target, root)` BEFORE the proposal is queued, recording the announcer + timestamp. `validate()` rejects roots without a recorded announcement. Off-chain monitors can verify the root matches the team's intended computation before it ever reaches a signer.

**Reference incidents**: Several airdrop contracts have had near-miss incidents where a proposed Merkle root was caught by community auditors before submission. Adding a pre-announcement gate makes that audit a structural requirement, not a vibes-based check.

## What none of these adapters defend against

Same caveats as upstream:

- **Total signer collusion at threshold + no veto raised.** If `threshold` signers all approve and zero signers cancel within cool-off, no adapter can override their decision — that's the multi-sig contract working as intended.
- **Bugs in the guarded protocol itself.** Adapters control who-can-call-what, not what-the-call-does once it lands. A buggy `withdraw` function will still be buggy when called through the guard.
- **Compromise of the signer's signing device** to the point where the human signs whatever appears on the screen. The attester pattern (see upstream's `attester/` dir) addresses this; intent-guard alone does not.
- **Cross-chain verifier compromise**, RPC compromise, or oracle-network compromise. These are separate trust domains; intent-guard's job is governance-call gating, not state-channel verification.

## Testing the threat coverage

Each attack scenario above has end-to-end coverage in the test suite:

```bash
forge test --match-test test_endToEnd  -vv
```

`test/IntegrationUUPS.t.sol` exercises the upgrade-impl-swap defense. `test/IntegrationDAOTreasury.t.sol` exercises the over-cap rejection. `test/IntegrationCrossChainPeer.t.sol` exercises peer-substitution rejection. And so on — every adapter's threat class has a passing integration test.
