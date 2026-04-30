// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BeaconUpgradeAdapter} from "../contracts/BeaconUpgradeAdapter.sol";

contract MockImplV1 {
    uint256 public constant VERSION = 1;
}

contract MockImplV2 {
    uint256 public constant VERSION = 2;
}

contract MockImplMalicious {
    uint256 public constant EVIL = 1337;
}

contract BeaconUpgradeAdapterTest is Test {
    BeaconUpgradeAdapter adapter;
    address owner = address(0xA11CE);
    address beacon = address(0xBEAC07);
    address beaconAlt = address(0xBEAC08);

    MockImplV1 implV1;
    MockImplV2 implV2;
    MockImplMalicious implEvil;

    bytes32 implV2CodeHash;
    bytes32 implEvilCodeHash;

    function setUp() public {
        adapter = new BeaconUpgradeAdapter(owner);
        implV1 = new MockImplV1();
        implV2 = new MockImplV2();
        implEvil = new MockImplMalicious();

        implV2CodeHash = address(implV2).codehash;
        implEvilCodeHash = address(implEvil).codehash;

        // Owner registers beacon + permitted impl with its codehash
        vm.startPrank(owner);
        adapter.setBeaconAllowed(beacon, true);
        adapter.setImplCodehash(beacon, address(implV2), implV2CodeHash);
        vm.stopPrank();
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        bytes32 hash1 = adapter.intentHash(beacon, 0, data);
        bytes32 hash2 = adapter.intentHash(beacon, 0, data);
        assertEq(hash1, hash2, "intentHash must be deterministic");
        assertTrue(hash1 != bytes32(0), "intentHash must be non-zero");
    }

    function test_intentHash_bindsNewImpl() public view {
        bytes memory dataV2 = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        bytes memory dataEvil = abi.encodeWithSignature("upgradeTo(address)", address(implEvil));

        bytes32 hashV2 = adapter.intentHash(beacon, 0, dataV2);
        bytes32 hashEvil = adapter.intentHash(beacon, 0, dataEvil);

        assertTrue(hashV2 != hashEvil, "different impls must produce different intent hashes");
    }

    function test_intentHash_bindsTarget() public view {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));

        bytes32 hashA = adapter.intentHash(beacon, 0, data);
        bytes32 hashB = adapter.intentHash(beaconAlt, 0, data);

        assertTrue(hashA != hashB, "different beacons must produce different intent hashes");
    }

    function test_intentHash_bindsValue() public view {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));

        bytes32 hashA = adapter.intentHash(beacon, 0, data);
        bytes32 hashB = adapter.intentHash(beacon, 1 ether, data);

        assertTrue(hashA != hashB, "different values must produce different intent hashes");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo(address)", address(implV2));
        vm.expectRevert(BeaconUpgradeAdapter.BadSelector.selector);
        adapter.intentHash(beacon, 0, data);
    }

    function test_intentHash_revertsOnTruncatedCalldata() public {
        // Selector + only 16 bytes (instead of full 32-byte address slot)
        bytes memory data = abi.encodePacked(adapter.UPGRADE_TO_SELECTOR(), bytes16(0));
        vm.expectRevert(BeaconUpgradeAdapter.BadSelector.selector);
        adapter.intentHash(beacon, 0, data);
    }

    function test_intentHash_revertsOnEmptyCalldata() public {
        bytes memory data = "";
        vm.expectRevert(BeaconUpgradeAdapter.BadSelector.selector);
        adapter.intentHash(beacon, 0, data);
    }

    function test_intentHash_revertsOnExtraTrailingBytes() public {
        // upgradeTo(address) selector + 32-byte address + 32-byte trailing junk
        bytes memory data = abi.encodePacked(
            adapter.UPGRADE_TO_SELECTOR(),
            bytes32(uint256(uint160(address(implV2)))),
            bytes32(uint256(0xDEADBEEF))
        );
        vm.expectRevert(BeaconUpgradeAdapter.BadSelector.selector);
        adapter.intentHash(beacon, 0, data);
    }

    // ============ validate ============

    function test_validate_passesForRegisteredImplWithMatchingCodehash() public view {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        adapter.validate(beacon, 0, data, bytes32(0));
        // No revert == pass.
    }

    function test_validate_revertsOnUnregisteredBeacon() public {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(BeaconUpgradeAdapter.BeaconNotAllowed.selector);
        adapter.validate(address(0xDEAD), 0, data, bytes32(0));
    }

    function test_validate_revertsOnUnregisteredImpl() public {
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implEvil));
        vm.expectRevert(BeaconUpgradeAdapter.ImplNotAllowed.selector);
        adapter.validate(beacon, 0, data, bytes32(0));
    }

    function test_validate_revertsOnCodehashMismatch() public {
        // Owner registers implV2 with a WRONG codehash, simulating a stale
        // registration where the implementation was redeployed at the same
        // address with different code (CREATE2 + SELFDESTRUCT class).
        vm.prank(owner);
        adapter.setImplCodehash(beacon, address(implV2), keccak256("staleCodehash"));

        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(BeaconUpgradeAdapter.CodehashMismatch.selector);
        adapter.validate(beacon, 0, data, bytes32(0));
    }

    function test_validate_revertsOnDisabledBeacon() public {
        vm.prank(owner);
        adapter.setBeaconAllowed(beacon, false);

        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(BeaconUpgradeAdapter.BeaconNotAllowed.selector);
        adapter.validate(beacon, 0, data, bytes32(0));
    }

    function test_validate_perBeaconAllowlistIsolated() public {
        // Register implV2 on `beacon` (done in setUp). Allow `beaconAlt` but
        // do NOT register implV2 for it.
        vm.prank(owner);
        adapter.setBeaconAllowed(beaconAlt, true);

        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(BeaconUpgradeAdapter.ImplNotAllowed.selector);
        adapter.validate(beaconAlt, 0, data, bytes32(0));

        // The original beacon still works.
        adapter.validate(beacon, 0, data, bytes32(0));
    }

    // ============ access control ============

    function test_setBeaconAllowed_revertsForNonOwner() public {
        vm.expectRevert(BeaconUpgradeAdapter.NotOwner.selector);
        adapter.setBeaconAllowed(beacon, false);
    }

    function test_setImplCodehash_revertsForNonOwner() public {
        vm.expectRevert(BeaconUpgradeAdapter.NotOwner.selector);
        adapter.setImplCodehash(beacon, address(implV2), implV2CodeHash);
    }

    function test_setImplCodehash_zeroRemovesImpl() public {
        vm.prank(owner);
        adapter.setImplCodehash(beacon, address(implV2), bytes32(0));

        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(implV2));
        vm.expectRevert(BeaconUpgradeAdapter.ImplNotAllowed.selector);
        adapter.validate(beacon, 0, data, bytes32(0));
    }

    function test_setBeaconAllowed_emitsEvent() public {
        vm.expectEmit(true, false, false, true, address(adapter));
        emit BeaconUpgradeAdapter.BeaconAllowed(beaconAlt, true);
        vm.prank(owner);
        adapter.setBeaconAllowed(beaconAlt, true);
    }

    function test_setImplCodehash_emitsEvent() public {
        vm.expectEmit(true, true, false, true, address(adapter));
        emit BeaconUpgradeAdapter.ImplAllowed(beacon, address(implV1), keccak256("v1"));
        vm.prank(owner);
        adapter.setImplCodehash(beacon, address(implV1), keccak256("v1"));
    }
}
