# How to use intentguard

This guide explains how a protocol team can use intentguard in operations. It is written for developers, security councils, and governance operators.

Status: reference implementation, unaudited. Use this to prototype, review, and adapt. Do not secure real funds with it before independent audit and protocol-specific tests.

## The idea in one minute

Intentguard sits between your council/multisig and dangerous protocol actions.

Instead of letting signers approve opaque transaction bytes, each privileged action becomes a proposal with:

- a target contract or program,
- the raw call or instruction,
- a typed intent hash,
- fresh signer approvals,
- a public cool-off window,
- a veto path,
- optional oracle checks.

If the transaction does not match the intent, it cannot execute. If the signatures are stale, it cannot queue. If signers notice something wrong during the cool-off, they can cancel it.

## What to protect first

Start with actions where one bad transaction can damage users:

- ownership or admin transfer,
- proxy or program upgrade,
- collateral listing,
- oracle/feed change,
- risk parameter change,
- treasury withdrawal,
- bridge/verifier configuration,
- pause/unpause authority.

Do not start with every function. Start with the functions that move power.

## Roles

- **Protocol developer:** writes adapters for the protocol's real calls.
- **Council signer:** reviews rendered intent and signs fresh attestations.
- **Veto signer:** watches the queue and cancels suspicious proposals.
- **Monitor:** listens for queued proposals, cancellations, alarms, and executions.
- **Risk reviewer:** approves oracle feeds, caps, and collateral policies.

One person can hold more than one role, but the operational process should treat them separately.

## The lifecycle

### 1. Define the action schema

For each protected action, define exactly what signers are approving.

Example:

```text
WhitelistCollateral {
  target: RiskManager,
  token: CVT,
  oracle: Chainlink/CVT-USD,
  fair_value_usd: 1.00,
  max_deposit_usd: 500000,
  max_ltv_bps: 0,
  expires_at: 2026-04-30T18:00:00Z
}
```

The schema should include every field that would matter to a signer. If a field changes the risk, it belongs in the intent.

### 2. Write an adapter

The adapter decodes the actual transaction and recomputes the canonical intent hash.

For EVM, see:

```text
contracts/CollateralListingAdapter.sol
```

For Solana, adapters are protocol-specific because account layouts and instructions vary. The Solana program includes the guard state machine, but each integration still needs a strict decoder for its own instructions.

Adapter rule: unknown or ambiguous calls fail closed.

### 3. Configure the vault

Pick operational parameters:

```text
quorumM: 3
signersN: 5
vetoK: 2
freshWindow: 10 minutes
cooloff: 24 hours
executeDelay: 60 seconds
proposalLifetime: 48 hours
```

Recommended defaults:

- Freshness: 10 minutes.
- Cool-off: 24 hours for upgrades, ownership, collateral, oracle, and treasury actions.
- Veto: 2-of-N for most councils.
- Longer delay for adapter or oracle allowlist changes.

### 4. Draft a proposal

A developer or operator creates the proposal:

- target address/program,
- calldata/instruction data,
- action kind,
- typed intent,
- adapter,
- expiry.

The system computes:

- `dataHash`,
- `intentHash`,
- `proposalId`,
- expected execution window.

### 5. Review and sign

Each signer reviews the rendered intent, not raw bytes.

The signer should see:

- action kind,
- target,
- recipient or new admin,
- token and oracle,
- caps and risk limits,
- code hash for upgrades,
- nonce,
- expiry,
- live oracle reading if relevant.

The signer then signs a fresh attestation. Old attestations should be useless.

The signer CLI sketch is here:

```text
clients/signer-cli.ts
```

### 6. Queue

Once the proposal has enough fresh signatures, it enters the public queue.

From this point, monitors should alert:

- all council signers,
- protocol operators,
- security partners,
- governance delegates if applicable.

The queue is the defense. If nobody watches it, the cool-off loses most of its value.

### 7. Veto or alarm

During the cool-off:

- any signer can raise an alarm,
- `K` signers can cancel,
- monitors can flag abnormal proposals.

Cancel if:

- target address is unfamiliar,
- oracle feed is new or wrong,
- collateral cap is too high,
- admin is changing unexpectedly,
- upgrade hash does not match the reviewed build,
- proposal was not announced in the expected governance channel.

### 8. Execute

After the cool-off and execute delay:

- the guard checks the proposal is still queued,
- nonce still matches,
- calldata still matches,
- oracle checks still pass,
- proposal has not expired,
- veto threshold was not reached.

Only then does it call the protected contract/program.

## EVM tutorial

Use this flow when the protected authority is a Safe or Safe-like multisig.

### Step 1: Install tools

You need Foundry:

```sh
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Then from the repo:

```sh
cd /Users/uwecerron/Desktop/primitive/evm
forge test
```

### Step 2: Deploy the module

Deploy the Safe module implementation in:

```text
evm/src/IntentGuardModule.sol
```

Constructor parameters:

```text
safe_: Safe address
quorumM_: approvals required
vetoK_: cancellations required
freshWindow_: max signer freshness
cooloff_: public waiting period
oracleToleranceBps_: oracle deviation tolerance
oracleMaxStaleness_: max oracle staleness
```

### Step 3: Enable it on the Safe

Use the Safe UI or Safe transaction builder to enable the module.

Important: enabling a module is not enough. The protected protocol must not still accept direct Safe calls for guarded functions.

Use one of these patterns:

- transfer ownership of guarded functions to the module,
- install a Safe Guard that blocks direct calls,
- change protected contracts to require `msg.sender == IntentGuardModule`.

### Step 4: Draft a proposal

For a simple parameter call:

```solidity
bytes memory data = abi.encodeWithSelector(
    RiskManager.setLtv.selector,
    token,
    newLtvBps
);
```

Draft through the module:

```solidity
uint64 id = module.draftProposal(
    ACTION_SET_LTV,
    address(riskManager),
    0,
    data,
    0,
    address(0)
);
```

For oracle-bound actions, include the claimed value and oracle address.

### Step 5: Sign

Each Safe owner reviews the rendered intent and calls:

```solidity
module.attest(id, intentHashWitness, uint64(block.timestamp));
```

The important field is `intentHashWitness`: the signer should only submit the hash they reviewed in the signer UI.

### Step 6: Monitor

Watch:

```solidity
ProposalDrafted
ProposalSigned
ProposalQueued
ProposalAlarm
ProposalCancelled
ProposalExecuted
ProposalRejected
```

Alert humans when `ProposalQueued` fires.

### Step 7: Cancel if needed

Any Safe owner can call:

```solidity
module.cancel(id);
```

Once `vetoK` owners cancel, execution is blocked.

### Step 8: Execute

After `cooloff + executeDelay`:

```solidity
module.execute(id);
```

If the oracle is stale, the claim deviates, the nonce changed, or the proposal was cancelled, execution fails.

## Solana tutorial

Use this flow when the protected authority is a Solana program authority, upgrade authority, treasury PDA, or council PDA.

### Step 1: Install tools

You need Rust, Solana CLI, and Anchor:

```sh
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
cargo install --git https://github.com/coral-xyz/anchor avm --locked
avm install latest
avm use latest
```

Then from the repo:

```sh
cd /Users/uwecerron/Desktop/primitive/solana
anchor test
```

### Step 2: Initialize a vault

Create one vault per protected authority.

Example protected authorities:

- upgrade authority,
- treasury authority,
- market admin,
- risk parameter authority.

The vault config contains:

- signer set,
- threshold,
- veto threshold,
- freshness window,
- cool-off,
- execute delay,
- proposal lifetime.

### Step 3: Transfer authority

Move the protected authority to the intentguard vault PDA.

This is the key step. If the old admin key can still call the protocol directly, intentguard is only advisory.

### Step 4: Draft and queue proposals

A proposal includes:

- target program,
- adapter,
- instruction data hash,
- intent hash,
- expiry,
- signer attestations.

Signers produce ed25519 attestations over the proposal fields. The guard checks those attestations before queueing.

### Step 5: Monitor and cancel

Watch program logs/events for queued proposals.

If something is wrong, signers call `cancel`. Once `veto_threshold` distinct signers cancel, the proposal cannot execute.

### Step 6: Execute by CPI

After the cool-off and execute delay, the program executes the queued instruction by CPI using the vault PDA.

Before production use, replace any scaffolded adapter or ed25519 parsing logic with strict protocol-specific validation.

## Signer tutorial

A signer should never be asked to approve raw bytes.

The signer UI should show:

```text
Action: WhitelistCollateral
Token: CVT
Oracle: Chainlink/CVT-USD
Claimed price: $1.00
Live price: $0.0001
Max deposit: $500,000,000
Target: 0x...
Nonce: 12
Expires: 2026-04-30 18:00 UTC
```

If anything looks wrong, do not sign. Raise an alarm or cancel.

A good signer flow:

1. Open the proposal from a trusted queue UI.
2. Verify it was announced in the expected governance/security channel.
3. Compare target addresses against an address book.
4. Check oracle feeds and caps.
5. Type the action kind to confirm.
6. Sign only if the displayed intent is correct.

## Operations runbook

For every queued proposal:

1. Post it to the council channel.
2. Alert all signers out-of-band.
3. Compare target addresses against an address book.
4. Compare calldata/instruction hash against the reviewed build or script.
5. Check oracle feed identity, staleness, and deviation.
6. Wait through the cool-off.
7. Execute only from the expected operator account.
8. Archive proposal, signatures, intent render, and execution transaction.

## First integration target

The best first protected action is usually not upgrades. Start with something easy to decode and high impact:

- treasury withdrawal,
- oracle feed change,
- collateral cap change,
- pause/unpause.

Once that path is tested, add upgrades and admin transfers.

## What not to do

- Do not leave direct admin bypass open.
- Do not let governance choose arbitrary oracle feeds in the same action.
- Do not use one generic adapter that accepts arbitrary calldata.
- Do not skip queue monitoring.
- Do not set veto threshold so high that cancellation is unrealistic.
- Do not use this unaudited code as-is for mainnet funds.

## Minimal production acceptance checklist

Before mainnet:

- independent audit complete,
- protocol-specific adapters tested,
- direct bypass removed,
- signer UI reviewed by actual council members,
- monitoring deployed,
- incident drill completed,
- veto tested on-chain,
- oracle failure cases tested,
- upgrade rollback plan documented,
- public docs explain the delay and veto process.
