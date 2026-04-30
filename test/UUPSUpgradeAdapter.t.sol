// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {UUPSUpgradeAdapter} from "../contracts/UUPSUpgradeAdapter.sol";

contract MockImplV1 {
    uint256 public constant VERSION = 1;
}

contract MockImplV2 {
    uint256 public constant VERSION = 2;
}

contract MockImplMalicious {
    uint256 public constant EVIL = 1337;
}

contract UUPSUpgradeAdapterTest is Test {
    UUPSUpgradeAdapter adapter;
    address owner = address(0xA11CE);
    address proxy = address(0xBEEF);

    MockImplV1 implV1;
    MockImplV2 implV2;
    MockImplMalicious implEvil;

    bytes32 implV2CodeHash;
    bytes32 implEvilCodeHash;

    function setUp() public {
        adapter = new UUPSUpgradeAdapter(owner);
        implV1 = new MockImplV1();
        implV2 = new MockImplV2();
        implEvil = new MockImplMalicious();

        implV2CodeHash = address(implV2).codehash;
        implEvilCodeHash = address(implEvil).codehash;

        // Owner registers proxy + permitted impl with its codehash
        vm.startPrank(owner);
        adapter.setProxyAllowed(proxy, true);
        adapter.setImplCodehash(proxy, address(implV2), implV2CodeHash);
        vm.stopPrank();
    }

    // ============ intentHash ============

    function test_intentHash_upgradeTo_isDeterministic() public view {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        bytes32 hash1 = adapter.intentHash(proxy, 0, data);
        bytes32 hash2 = adapter.intentHash(proxy, 0, data);
        assertEq(hash1, hash2, "intentHash must be deterministic");
        assertTrue(hash1 != bytes32(0), "intentHash must be non-zero");
    }

    function test_intentHash_upgradeToAndCall_bindsCallData() public view {
        bytes memory callDataA = abi.encodeWithSignature("initialize(uint256)", 42);
        bytes memory callDataB = abi.encodeWithSignature("initialize(uint256)", 99);

        bytes memory dataA = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)",
            address(implV2),
            callDataA
        );
        bytes memory dataB = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)",
            address(implV2),
            callDataB
        );

        bytes32 hashA = adapter.intentHash(proxy, 0, dataA);
        bytes32 hashB = adapter.intentHash(proxy, 0, dataB);

        assertTrue(hashA != hashB, "different post-upgrade calldata must produce different intents");
    }

    function test_intentHash_differentImpls_differentHashes() public {
        // Both impls must be registered for both intentHash() calls to succeed
        // (after the Cerron fix, intentHash fails closed for unregistered impls).
        vm.prank(owner);
        adapter.setImplCodehash(proxy, address(implEvil), implEvilCodeHash);

        bytes memory dataV2 = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        bytes memory dataEvil = abi.encodeWithSignature("upgradeTo(address)", address(implEvil));

        bytes32 hashV2 = adapter.intentHash(proxy, 0, dataV2);
        bytes32 hashEvil = adapter.intentHash(proxy, 0, dataEvil);

        assertTrue(hashV2 != hashEvil, "different impls must produce different intent hashes");
    }

    function test_intentHash_differentTargets_differentHashes() public {
        // A second proxy must be registered to get two valid intent hashes.
        address proxy2 = address(0xCAFE);
        vm.startPrank(owner);
        adapter.setProxyAllowed(proxy2, true);
        adapter.setImplCodehash(proxy2, address(implV2), implV2CodeHash);
        vm.stopPrank();

        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));

        bytes32 hashA = adapter.intentHash(proxy, 0, data);
        bytes32 hashB = adapter.intentHash(proxy2, 0, data);

        assertTrue(hashA != hashB, "different targets must produce different intent hashes");
    }

    /// @notice After Cerron's PR #2 review: the codehash is now part of
    /// the signed intent. Different registered codehashes for the same
    /// (proxy, impl) MUST produce different intent hashes — this is the
    /// property that closes the policy-substitution attack.
    function test_intentHash_differentCodehashes_differentHashes() public {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        bytes32 hashOriginal = adapter.intentHash(proxy, 0, data);

        // Owner re-registers impl with a DIFFERENT codehash. Even though
        // (proxy, value, impl, callDataHash) are unchanged, the intent
        // hash MUST change because the codehash is now bound.
        vm.prank(owner);
        adapter.setImplCodehash(proxy, address(implV2), keccak256("different-bytecode"));

        bytes32 hashAfter = adapter.intentHash(proxy, 0, data);
        assertTrue(
            hashOriginal != hashAfter,
            "intent hash MUST change when registered codehash changes (codehash is bound into signed bytes)"
        );
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(UUPSUpgradeAdapter.BadSelector.selector);
        adapter.intentHash(proxy, 0, data);
    }

    function test_intentHash_revertsOnTruncatedUpgradeTo() public {
        // Selector + only 16 bytes (instead of full 32-byte address slot)
        bytes memory data = abi.encodePacked(adapter.UPGRADE_TO_SELECTOR(), bytes16(0));
        vm.expectRevert(UUPSUpgradeAdapter.BadSelector.selector);
        adapter.intentHash(proxy, 0, data);
    }

    /// @notice intentHash() must fail closed for unallowed proxies — signers
    /// should not be able to produce a hash for a target validate() would
    /// later reject. Hardened in response to Cerron's PR #2 review.
    function test_intentHash_revertsOnUnallowedProxy() public {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(UUPSUpgradeAdapter.ProxyNotAllowed.selector);
        adapter.intentHash(address(0xDEAD), 0, data);
    }

    /// @notice intentHash() must fail closed for unregistered impls.
    /// Hardened in response to Cerron's PR #2 review.
    function test_intentHash_revertsOnUnregisteredImpl() public {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implEvil));
        vm.expectRevert(UUPSUpgradeAdapter.ImplNotAllowed.selector);
        adapter.intentHash(proxy, 0, data);
    }

    // ============ validate ============

    function test_validate_passesForRegisteredImplWithMatchingCodehash() public view {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        adapter.validate(proxy, 0, data, bytes32(0));
        // No revert == pass.
    }

    function test_validate_passesForUpgradeToAndCall() public view {
        bytes memory callData = abi.encodeWithSignature("initialize(uint256)", 42);
        bytes memory data = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)",
            address(implV2),
            callData
        );
        adapter.validate(proxy, 0, data, bytes32(0));
    }

    function test_validate_revertsOnUnregisteredProxy() public {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(UUPSUpgradeAdapter.ProxyNotAllowed.selector);
        adapter.validate(address(0xDEAD), 0, data, bytes32(0));
    }

    function test_validate_revertsOnUnregisteredImpl() public {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implEvil));
        vm.expectRevert(UUPSUpgradeAdapter.ImplNotAllowed.selector);
        adapter.validate(proxy, 0, data, bytes32(0));
    }

    function test_validate_revertsOnCodehashMismatch() public {
        // Owner registers implV2 with a WRONG codehash, simulating a stale
        // registration where the implementation was redeployed at the same
        // address with different code (CREATE2 + SELFDESTRUCT class).
        vm.prank(owner);
        adapter.setImplCodehash(proxy, address(implV2), keccak256("staleCodehash"));

        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(UUPSUpgradeAdapter.CodehashMismatch.selector);
        adapter.validate(proxy, 0, data, bytes32(0));
    }

    function test_validate_revertsOnDisabledProxy() public {
        vm.prank(owner);
        adapter.setProxyAllowed(proxy, false);

        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(UUPSUpgradeAdapter.ProxyNotAllowed.selector);
        adapter.validate(proxy, 0, data, bytes32(0));
    }

    // ============ access control ============

    function test_setProxyAllowed_revertsForNonOwner() public {
        vm.expectRevert(UUPSUpgradeAdapter.NotOwner.selector);
        adapter.setProxyAllowed(proxy, false);
    }

    function test_setImplCodehash_revertsForNonOwner() public {
        vm.expectRevert(UUPSUpgradeAdapter.NotOwner.selector);
        adapter.setImplCodehash(proxy, address(implV2), implV2CodeHash);
    }

    function test_setImplCodehash_zeroRemovesImpl() public {
        vm.prank(owner);
        adapter.setImplCodehash(proxy, address(implV2), bytes32(0));

        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(UUPSUpgradeAdapter.ImplNotAllowed.selector);
        adapter.validate(proxy, 0, data, bytes32(0));
    }

    /// @notice Owner must NOT be able to register an EOA / empty-code
    /// address as an implementation — upgrading the proxy to an empty-code
    /// address would brick it. Hardened in response to Cerron's PR #2 review.
    function test_setImplCodehash_revertsOnEmptyCodeImpl() public {
        address eoa = address(0xE0A);
        // Sanity: address has no code.
        assertEq(eoa.code.length, 0, "test precondition: eoa must have no code");

        vm.prank(owner);
        vm.expectRevert(UUPSUpgradeAdapter.EmptyCodeImpl.selector);
        adapter.setImplCodehash(proxy, eoa, keccak256("anything"));
    }

    /// @notice Zero-codehash "remove from allowlist" must remain usable
    /// even when the impl address is empty (e.g. cleanup after a
    /// SELFDESTRUCT). Only registration of a non-zero codehash against
    /// an empty impl is rejected.
    function test_setImplCodehash_zeroCodehashAllowedForEmptyImpl() public {
        address eoa = address(0xE0A);
        vm.prank(owner);
        // No revert — zero codehash is the explicit "remove from allowlist"
        // sentinel and must be accepted unconditionally.
        adapter.setImplCodehash(proxy, eoa, bytes32(0));
    }

    // ============ adversarial: length & zero-address checks ============

    /// @notice Adversarial review finding: `_decode` enforces an exact length
    /// for `upgradeTo(address)` but the `upgradeToAndCall` branch performed no
    /// length sanity check before calling `abi.decode`. While `abi.decode`
    /// itself reverts on malformed payloads, the revert reason was not
    /// `BadSelector`, breaking the contract's documented "fail closed with
    /// BadSelector" contract for malformed inputs. This regression test
    /// asserts a too-short `upgradeToAndCall` payload reverts cleanly with
    /// BadSelector.
    function test_intentHash_revertsOnTruncatedUpgradeToAndCall() public {
        // Selector + only 16 bytes (well below the 96-byte minimum for
        // (address, bytes) ABI-encoding which needs 32-byte addr slot +
        // 32-byte offset + 32-byte length).
        bytes memory data = abi.encodePacked(
            adapter.UPGRADE_TO_AND_CALL_SELECTOR(),
            bytes16(0)
        );
        vm.expectRevert(UUPSUpgradeAdapter.BadSelector.selector);
        adapter.intentHash(proxy, 0, data);
    }

    /// @notice Adversarial review finding: deploying with `owner = address(0)`
    /// would brick the adapter (no one can ever call `setProxyAllowed` /
    /// `setImplCodehash`) — an irrecoverable state that should fail closed
    /// at construction.
    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(UUPSUpgradeAdapter.ZeroOwner.selector);
        new UUPSUpgradeAdapter(address(0));
    }

    // ============ ADVERSARIAL REGRESSION: policy-substitution attack ============

    /// @notice Direct reproduction of the vulnerability Uwe Cerron flagged
    /// in PR #2 of `uwecerron/intent-guard`.
    ///
    /// THE ATTACK (as it would have worked against the OLD adapter):
    ///   1. Adapter owner registers `(proxy, implV2, codehash_X)` where
    ///      codehash_X is the hash of legitimate v2 bytecode.
    ///   2. Signers approve an upgrade. Under the OLD intent shape, the
    ///      signed bytes bound only `(target, value, impl_addr, callDataHash)` —
    ///      NOT the codehash. The codehash was only checked at execute
    ///      time against MUTABLE adapter policy.
    ///   3. Attacker (with control over the impl address via CREATE2 +
    ///      SELFDESTRUCT) redeploys `implV2` at the same address but
    ///      with MALICIOUS bytecode — codehash_Y.
    ///   4. A colluding/compromised adapter owner calls
    ///      `setImplCodehash(proxy, implV2, codehash_Y)` to update policy
    ///      to match the new (malicious) bytecode.
    ///   5. Under the OLD shape, the original signatures still verified
    ///      against the same intent hash (codehash wasn't in the signed
    ///      bytes), and validate() now passes (policy was updated). The
    ///      proxy gets upgraded to malicious code WITHOUT any new
    ///      signatures.
    ///
    /// THE FIX: bind the codehash INTO the signed intent. After this
    /// fix, step (4) changes the intent hash itself — old signatures
    /// bound a hash computed against codehash_X, but the policy now
    /// stores codehash_Y, so anyone re-deriving the intent gets a
    /// DIFFERENT hash and the old signatures don't verify. The
    /// belt-and-suspenders codehash-equality check in validate() also
    /// catches the divergence independently.
    ///
    /// This test exercises BOTH layers explicitly.
    function test_adversarial_policySubstitutionAttackBlocked() public {
        bytes memory upgradeData = abi.encodeWithSignature(
            "upgradeTo(address)",
            address(implV2)
        );

        // === Step 1 + 2: legitimate registration + signing-time intent ===
        // implV2 already registered with its real codehash in setUp().
        bytes32 codehash_X = address(implV2).codehash;
        assertEq(adapter.getImplCodehash(proxy, address(implV2)), codehash_X);

        // The intent hash signers see at signing time. Under the OLD
        // shape this was independent of the registered codehash. Under
        // the fix, codehash_X is bound into the result.
        bytes32 intentAtSign = adapter.intentHash(proxy, 0, upgradeData);

        // === Step 3: attacker swaps the bytecode at implV2's address ===
        // Simulate CREATE2 + SELFDESTRUCT redeployment by replacing the
        // runtime code at the same address. The on-chain extcodehash
        // diverges from codehash_X.
        bytes memory maliciousRuntime = hex"60016000526001601ff3"; // small distinct stub
        vm.etch(address(implV2), maliciousRuntime);
        bytes32 codehash_Y = address(implV2).codehash;
        assertTrue(codehash_X != codehash_Y, "attack precondition: redeploy must change codehash");

        // === Step 4: compromised owner updates policy to new codehash ===
        vm.prank(owner);
        adapter.setImplCodehash(proxy, address(implV2), codehash_Y);

        // === LAYER 1 — signed-intent layer rejects the attack ===
        // Re-derive the intent hash from current state. Because the fix
        // binds the codehash, the recomputed hash MUST differ from the
        // hash signers signed. Any system that re-derives the intent at
        // execute time (the IntentGuardModule does) will see a different
        // hash and reject the old signatures as not matching.
        bytes32 intentAfterAttack = adapter.intentHash(proxy, 0, upgradeData);
        assertTrue(
            intentAtSign != intentAfterAttack,
            "ATTACK BLOCKED AT SIGNED-INTENT LAYER: intent hash MUST change when policy codehash changes; otherwise the old signatures could re-authorize new bytecode"
        );

        // === LAYER 2 — validate() codehash-mismatch catches divergence ===
        // Model the more common case where the bytecode was swapped but
        // the policy was NOT updated (owner not colluding). Reset the
        // registered codehash back to codehash_X. validate() must reject
        // because the live extcodehash (codehash_Y) ≠ stored expected
        // (codehash_X).
        vm.prank(owner);
        adapter.setImplCodehash(proxy, address(implV2), codehash_X);

        vm.expectRevert(UUPSUpgradeAdapter.CodehashMismatch.selector);
        adapter.validate(proxy, 0, upgradeData, bytes32(0));
    }
}
