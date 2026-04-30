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

    function test_intentHash_differentImpls_differentHashes() public view {
        bytes memory dataV2 = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        bytes memory dataEvil = abi.encodeWithSignature("upgradeTo(address)", address(implEvil));

        bytes32 hashV2 = adapter.intentHash(proxy, 0, dataV2);
        bytes32 hashEvil = adapter.intentHash(proxy, 0, dataEvil);

        assertTrue(hashV2 != hashEvil, "different impls must produce different intent hashes");
    }

    function test_intentHash_differentTargets_differentHashes() public view {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));

        bytes32 hashA = adapter.intentHash(proxy, 0, data);
        bytes32 hashB = adapter.intentHash(address(0xCAFE), 0, data);

        assertTrue(hashA != hashB, "different targets must produce different intent hashes");
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
}
