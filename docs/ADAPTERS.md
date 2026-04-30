# Authoring Adapters

This is a guide for protocol teams writing their own `IActionAdapter` implementations to gate their privileged calls behind the `IntentGuardModule`. It walks through the contract, the `intentHash` / `validate` split, the test patterns the fork uses, and the common pitfalls.

## The contract

Every adapter implements one interface, defined in `contracts/IntentGuardModule.sol`:

```solidity
interface IActionAdapter {
    /// Decode the concrete call and return the canonical typed intent hash.
    function intentHash(address target, uint256 value, bytes calldata data) external view returns (bytes32);

    /// Optional final pre-execution validation, e.g. live oracle checks.
    function validate(address target, uint256 value, bytes calldata data, bytes32 expectedIntentHash) external view;
}
```

Two functions, two responsibilities.

### `intentHash` — what signers approve

`intentHash` is the function that converts raw calldata into the canonical, human-meaningful summary of what the call does. The bytes a signer signs are derived from this hash. The same call should always produce the same hash (modulo state for adapters that bind chain-time data like codehashes).

The pattern across this fork's adapters:

```solidity
function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
    (bytes32 fieldA, address fieldB, uint256 fieldC) = _decode(data);
    return keccak256(
        abi.encode(MY_INTENT_TYPEHASH, target, value, fieldA, fieldB, fieldC)
    );
}
```

Three things to get right:

1. **Decode the calldata cleanly.** Validate the selector. Validate the length. Revert on anything unexpected. Adapters fail closed by design — the module's threat model assumes adapters reject anything they don't fully recognize.

2. **Bind every load-bearing field into the hash.** If a signer would care about a field, it goes in. If two semantically different calls would produce the same hash, you have a binding bug — an attacker can substitute one for the other without breaking the signature.

3. **Use a unique typehash per intent shape.** A collision-resistant prefix per action class. Pattern: `keccak256("MyAction(address target,uint256 value,...)")` matching the EIP-712 typed-data style.

### `validate` — what the adapter checks at execute time

`validate` runs at the end of the queue → cool-off → execute pipeline, with the data the executor passes in. It's the place to do **live checks that can't be encoded in the static intent**:

- Oracle-bound claims (price within tolerance, feed allowlist + staleness)
- Codehash bindings (the new implementation's bytecode hasn't changed since signing)
- Cap enforcement (per-asset withdrawal caps, change-ratio caps from a registered baseline)
- Allowlist enforcement (recipient whitelist, peer pinning, role membership)

`validate` is where signed intent meets current reality. Don't do anything in `validate` you could do statically in `intentHash` — the test for "does this belong here?" is "would the answer change between sign-time and execute-time?"

## Worked example: `OwnershipTransferAdapter`

A walkthrough of one of the smaller adapters in this fork.

The shape we're gating:

```solidity
function transferOwnership(address newOwner) external onlyOwner;
function renounceOwnership() external onlyOwner;
```

### Step 1: enumerate selectors

```solidity
bytes4 public constant TRANSFER_OWNERSHIP_SELECTOR = bytes4(keccak256("transferOwnership(address)"));
bytes4 public constant RENOUNCE_OWNERSHIP_SELECTOR = bytes4(keccak256("renounceOwnership()"));
```

### Step 2: define the policy struct

What the adapter owner needs to register per target:

```solidity
struct TargetPolicy {
    bool transferAllowed;
    bool renounceAllowed;
}
mapping(address => TargetPolicy) public targetPolicy;
mapping(address => mapping(address => bool)) public allowedNewOwner;
```

`renounceOwnership` defaults to disabled because most protocols treat renouncing ownership as a foot-gun. `allowedNewOwner` is the per-target allowlist of who can take ownership.

### Step 3: decode + dispatch

```solidity
enum Action { Transfer, Renounce }

function _decode(bytes calldata data) internal pure returns (Action action, address newOwner) {
    if (data.length < 4) revert BadSelector();
    bytes4 selector;
    assembly { selector := calldataload(data.offset) }
    if (selector == TRANSFER_OWNERSHIP_SELECTOR) {
        if (data.length != 4 + 32) revert BadSelector();
        action = Action.Transfer;
        newOwner = abi.decode(data[4:], (address));
    } else if (selector == RENOUNCE_OWNERSHIP_SELECTOR) {
        if (data.length != 4) revert BadSelector();
        action = Action.Renounce;
        newOwner = address(0);
    } else {
        revert BadSelector();
    }
}
```

Length check on every branch; unknown selectors revert.

### Step 4: intent hash

```solidity
function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
    (Action action, address newOwner) = _decode(data);
    if (action == Action.Transfer) {
        return keccak256(abi.encode(TRANSFER_INTENT_TYPEHASH, target, value, newOwner));
    }
    return keccak256(abi.encode(RENOUNCE_INTENT_TYPEHASH, target, value));
}
```

Different typehash per action so the same target + value can't be reinterpreted between transfer and renounce.

### Step 5: validate

```solidity
function validate(address target, uint256, bytes calldata data, bytes32) external view {
    (Action action, address newOwner) = _decode(data);
    TargetPolicy memory pol = targetPolicy[target];
    if (action == Action.Transfer) {
        if (!pol.transferAllowed) revert ActionNotAllowed();
        if (!allowedNewOwner[target][newOwner]) revert NewOwnerNotAllowed();
    } else {
        if (!pol.renounceAllowed) revert ActionNotAllowed();
    }
}
```

Per-action gating. Renounce gated by a single flag (defaults off). Transfer gated by both the per-target policy AND the per-target newOwner allowlist.

That's the whole adapter. Real world: ~110 LOC.

## Test patterns

### Per-adapter unit tests

Cover, at minimum:

- Intent-hash determinism (same inputs → same output)
- Intent-hash binds every load-bearing field (changing each field changes the hash)
- Intent-hash reverts on unknown selectors and malformed calldata
- `validate` happy-path under each policy variant
- `validate` revert path for each error in the contract
- Owner-only access control on every setter

The pattern in this fork:

```solidity
function test_intentHash_bindsRecipient() public view {
    bytes32 a = adapter.intentHash(target, 0, _withdrawCalldata(recipientA, asset, 100));
    bytes32 b = adapter.intentHash(target, 0, _withdrawCalldata(recipientB, asset, 100));
    assertTrue(a != b, "different recipients must produce different intents");
}
```

One small assertion per behavior. Easy to read, easy to extend.

### Integration tests

The adapters in `contracts/` only do half the job — they need to compose with `IntentGuardModule` to actually gate calls. The integration tests in `test/IntegrationUUPS.t.sol` and `test/IntegrationDAOTreasury.t.sol` show the pattern:

1. Deploy the module + a mock Safe + the target + the adapter
2. Initialize a vault with N signers (sorted by address ascending — the module enforces strict signer ordering in attestations)
3. Set the adapter on the module via `setAdapter(vaultId, target, adapter, true)`
4. Build calldata + compute intent hash via the adapter
5. Sign attestations with `vm.sign(privKey, ethSignedDigest)` where the digest follows the module's `ATTESTATION_TYPEHASH` shape
6. `module.queue(...)` with the attestations
7. `vm.warp(...)` past cool-off + execute delay
8. `module.execute(proposalId, data)` and assert the target was called

The signing helper struct (`AttestPayload`) is necessary because the legacy compile pipeline can't fit the 9-arg signature in stack — pack the params.

## Common pitfalls

- **Stack-too-deep on the legacy compile pipeline.** Solidity's default profile has tight stack budgets. If your adapter or test has a function with > 8 args, refactor — pack into a struct, extract helpers. This fork's `IntentGuardModule` itself was refactored to fit; see `_attestationDigest` and `_verifyAttestation`.

- **Calldata length checks.** Every selector branch must validate the length of the remaining data. `abi.decode` will revert on truncated data, but a leading length check is clearer and surfaces a typed error.

- **Forgetting to bind a load-bearing field.** If your adapter handles two related actions (e.g., grant and revoke), use distinct typehashes. If the adapter has policy state (allowlists, caps), the policy values are NOT in the intent hash — the hash represents what signers approved; validate enforces the policy.

- **Reading `block.timestamp` or `block.chainid` in `intentHash`.** These are state-dependent values. Most adapters should be `pure` — if you read state, mark `view` and document why. The module recomputes `intentHash` at queue time, not at execute time, so state-dependent intents only see queue-time values.

- **`validate` doing things `intentHash` should do.** The split is: `intentHash` says "what is this call?", `validate` says "is the world right at execute time for this call to happen?". If a check would give the same answer at sign-time and execute-time, it goes in `intentHash` (or in policy state checked by `validate` against immutable inputs).

## Related reading

- `intentguard.md` — the original whitepaper. Threat model, full invariant list, attester extension.
- `SPEC.md` — the protocol spec.
- `docs/HOWTO.md` — step-by-step integration tutorial for protocol teams.
- The adapter sources in `contracts/` — every one is < 200 LOC and reads top-to-bottom.
- The integration tests in `test/Integration*.t.sol` — end-to-end demos.
