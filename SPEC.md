# intentguard — Specification

Version: 0.1 draft
Status: reference design open for review
Audience: protocol engineers, multisig operators, security councils, and security researchers

## 1. Threat model

Intentguard protects privileged protocol operations where a legitimate signer can be tricked into approving an action whose real effect they did not understand.

It is designed for:

- social-engineered admin transactions,
- stale or pre-signed approvals,
- malicious or misleading signing UIs,
- compromised signer laptops,
- unexpected admin transfers,
- unsafe collateral listings,
- oracle/feed changes,
- treasury withdrawals,
- upgrades and parameter changes.

It does not solve:

- bugs inside the guarded protocol,
- total signer collusion,
- malicious or compromised oracle networks,
- bridge/verifier compromise by itself,
- direct admin bypass left open outside the guard.

## 2. Core objects

- **Vault:** one guarded authority, such as a Safe, admin key, upgrade authority, or PDA.
- **Action:** a privileged operation against a protocol.
- **Intent:** the canonical human-readable meaning of an action.
- **Adapter:** code that decodes a concrete transaction/instruction into its canonical intent.
- **Proposal:** an action plus intent hash, nonce, expiry, signatures, and queue state.
- **Attestation:** a fresh signer approval over the proposal fields.
- **Veto:** a signer cancellation during the cool-off window.

## 3. Required invariant

A guarded action may execute only if all of these are true:

1. The action target is allowlisted.
2. The adapter is allowlisted for that target.
3. The adapter recomputes the same `intentHash` that signers reviewed.
4. Enough signers approved the proposal.
5. Every signer approval was fresh at queue time.
6. The proposal survived the cool-off and execute-delay windows.
7. The proposal was not cancelled by `K` signers.
8. The proposal nonce still matches the vault nonce or dependency nonce.
9. Oracle-bound claims still pass live oracle/risk checks.
10. The guarded protocol cannot be called directly through an unguarded admin path.

## 4. Intent hash

An intent hash must bind:

- domain/version,
- chain or genesis hash,
- vault,
- nonce,
- action kind,
- target,
- calldata or instruction hash,
- decoded risk-relevant fields,
- adapter version,
- proposal expiry.

For EVM, use `keccak256` over typed ABI-encoded data.

For Solana, use a deterministic serialized message, preferably Borsh or another fixed canonical encoding.

## 5. Freshness

Freshness is checked when a proposal enters the public queue, not at final execution.

Each attestation includes:

- signer,
- `signedAt`,
- `expiresAt`,
- proposal domain fields,
- signature.

Default freshness window: 10 minutes.

This is the control that breaks durable-nonce or long-lived pre-signing attacks.

## 6. Cool-off and veto

After enough fresh attestations are collected, the proposal enters `Queued`.

Default:

- `cooloffSecs`: 24 hours,
- `executeDelaySecs`: 60 seconds,
- `vetoK`: 2 signers.

During the cool-off, any signer can raise an alarm. Once `K` distinct signers cancel, the proposal becomes permanently cancelled.

## 7. Oracle-bound claims

For actions that depend on price, TVL, collateral value, feed identity, or liquidity, the adapter must check an allowlisted oracle or risk adapter.

The guard should reject if:

- the feed is not allowlisted,
- the reading is stale,
- the confidence interval is too wide,
- the claimed value deviates beyond tolerance,
- the asset has no meaningful market data,
- the requested exposure cap is too high for the feed/liquidity.

Governance should not be able to select an arbitrary new oracle feed inside the same action that uses it.

## 8. State machine

```text
Drafted -> Pending -> Queued -> Executed
                      |
                      +-> Cancelled
```

Fresh signatures move a proposal into `Queued`. Time plus no cancellation moves it into executable state. Execution increments the vault nonce.

## 9. Deployment requirements

Intentguard is only protective if:

- direct Safe/admin bypass is impossible,
- adapters fail closed,
- queue events are monitored,
- signers have an out-of-band cancel path,
- oracle feeds are allowlisted,
- adapter changes use longer delays,
- emergency authorities are scoped and cannot bypass the slow vault.

## 10. Founder summary

Intentguard turns "trust our multisig" into "our multisig can only execute fresh, explicit, reviewable, vetoable actions."

That gives users, auditors, partners, and council members a clearer safety story around the operational layer of a DeFi protocol.
