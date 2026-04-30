// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ProxyAdminAdapter} from "../contracts/ProxyAdminAdapter.sol";

contract MockImplV1 {
    uint256 public constant VERSION = 1;
}

contract MockImplV2 {
    uint256 public constant VERSION = 2;
}

contract ProxyAdminAdapterTest is Test {
    ProxyAdminAdapter adapter;
    address owner = address(0xA11CE);
    address proxyAdmin = address(0xA0A0);
    address proxy = address(0xBEEF);
    address proxyAlt = address(0xFEED);

    MockImplV1 implV1;
    MockImplV2 implV2;

    bytes32 implV2CodeHash;

    function setUp() public {
        adapter = new ProxyAdminAdapter(owner);
        implV1 = new MockImplV1();
        implV2 = new MockImplV2();
        implV2CodeHash = address(implV2).codehash;

        vm.startPrank(owner);
        adapter.setProxyAllowed(proxyAdmin, proxy, true);
        adapter.setImplCodehash(proxyAdmin, proxy, address(implV2), implV2CodeHash);
        vm.stopPrank();
    }

    function _upgrade(address p, address impl) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("upgrade(address,address)", p, impl);
    }

    function _upgradeAndCall(address p, address impl, bytes memory cd) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("upgradeAndCall(address,address,bytes)", p, impl, cd);
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _upgrade(proxy, address(implV2));
        bytes32 a = adapter.intentHash(proxyAdmin, 0, data);
        bytes32 b = adapter.intentHash(proxyAdmin, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_bindsProxy() public view {
        bytes32 a = adapter.intentHash(proxyAdmin, 0, _upgrade(proxy, address(implV2)));
        bytes32 b = adapter.intentHash(proxyAdmin, 0, _upgrade(proxyAlt, address(implV2)));
        assertTrue(a != b);
    }

    function test_intentHash_bindsImpl() public view {
        bytes32 a = adapter.intentHash(proxyAdmin, 0, _upgrade(proxy, address(implV1)));
        bytes32 b = adapter.intentHash(proxyAdmin, 0, _upgrade(proxy, address(implV2)));
        assertTrue(a != b);
    }

    function test_intentHash_bindsCallData_upgradeAndCall() public view {
        bytes memory cdA = abi.encodeWithSignature("init(uint256)", 1);
        bytes memory cdB = abi.encodeWithSignature("init(uint256)", 2);
        bytes32 a = adapter.intentHash(proxyAdmin, 0, _upgradeAndCall(proxy, address(implV2), cdA));
        bytes32 b = adapter.intentHash(proxyAdmin, 0, _upgradeAndCall(proxy, address(implV2), cdB));
        assertTrue(a != b);
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(ProxyAdminAdapter.BadSelector.selector);
        adapter.intentHash(proxyAdmin, 0, data);
    }

    // ============ validate ============

    function test_validate_passesForRegisteredImpl() public view {
        adapter.validate(proxyAdmin, 0, _upgrade(proxy, address(implV2)), bytes32(0));
    }

    function test_validate_passesForUpgradeAndCall() public view {
        bytes memory cd = abi.encodeWithSignature("init(uint256)", 42);
        adapter.validate(proxyAdmin, 0, _upgradeAndCall(proxy, address(implV2), cd), bytes32(0));
    }

    function test_validate_revertsOnUnregisteredProxy() public {
        bytes memory data = _upgrade(proxyAlt, address(implV2));
        vm.expectRevert(ProxyAdminAdapter.ProxyNotAllowed.selector);
        adapter.validate(proxyAdmin, 0, data, bytes32(0));
    }

    function test_validate_revertsOnUnregisteredImpl() public {
        bytes memory data = _upgrade(proxy, address(implV1));
        vm.expectRevert(ProxyAdminAdapter.ImplNotAllowed.selector);
        adapter.validate(proxyAdmin, 0, data, bytes32(0));
    }

    function test_validate_revertsOnCodehashMismatch() public {
        vm.prank(owner);
        adapter.setImplCodehash(proxyAdmin, proxy, address(implV2), keccak256("wrong"));

        bytes memory data = _upgrade(proxy, address(implV2));
        vm.expectRevert(ProxyAdminAdapter.CodehashMismatch.selector);
        adapter.validate(proxyAdmin, 0, data, bytes32(0));
    }

    function test_validate_revertsOnDisabledProxy() public {
        vm.prank(owner);
        adapter.setProxyAllowed(proxyAdmin, proxy, false);

        bytes memory data = _upgrade(proxy, address(implV2));
        vm.expectRevert(ProxyAdminAdapter.ProxyNotAllowed.selector);
        adapter.validate(proxyAdmin, 0, data, bytes32(0));
    }

    // ============ access control ============

    function test_setProxyAllowed_revertsForNonOwner() public {
        vm.expectRevert(ProxyAdminAdapter.NotOwner.selector);
        adapter.setProxyAllowed(proxyAdmin, proxy, false);
    }

    function test_setImplCodehash_revertsForNonOwner() public {
        vm.expectRevert(ProxyAdminAdapter.NotOwner.selector);
        adapter.setImplCodehash(proxyAdmin, proxy, address(implV2), implV2CodeHash);
    }
}
