// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {RoleGrantAdapter} from "../../contracts/RoleGrantAdapter.sol";

contract RoleGrantAdapterFuzzTest is Test {
    RoleGrantAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);

    bytes32 constant ROLE_OPEN = keccak256("OPEN_ROLE");
    bytes32 constant ROLE_FROZEN = keccak256("FROZEN_ROLE");

    function setUp() public {
        adapter = new RoleGrantAdapter(owner);
        vm.startPrank(owner);
        adapter.setRolePolicy(target, ROLE_OPEN, true, false, false);
        adapter.setRolePolicy(target, ROLE_FROZEN, true, true, false);
        vm.stopPrank();
    }

    function _grant(bytes32 role, address account) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("grantRole(bytes32,address)", role, account);
    }

    function _revoke(bytes32 role, address account) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("revokeRole(bytes32,address)", role, account);
    }

    function testFuzz_intentHash_grantRevokeDiffer(bytes32 role, address account) public view {
        bytes32 hashGrant = adapter.intentHash(target, 0, _grant(role, account));
        bytes32 hashRevoke = adapter.intentHash(target, 0, _revoke(role, account));
        assertTrue(hashGrant != hashRevoke);
    }

    function testFuzz_intentHash_bindsRole(bytes32 r1, bytes32 r2, address account) public view {
        vm.assume(r1 != r2);
        bytes32 h1 = adapter.intentHash(target, 0, _grant(r1, account));
        bytes32 h2 = adapter.intentHash(target, 0, _grant(r2, account));
        assertTrue(h1 != h2);
    }

    function testFuzz_intentHash_bindsAccount(bytes32 role, address a1, address a2) public view {
        vm.assume(a1 != a2);
        bytes32 h1 = adapter.intentHash(target, 0, _grant(role, a1));
        bytes32 h2 = adapter.intentHash(target, 0, _grant(role, a2));
        assertTrue(h1 != h2);
    }

    function testFuzz_validate_grantsAndRevokesPassOnOpenRole(address account) public view {
        adapter.validate(target, 0, _grant(ROLE_OPEN, account), bytes32(0));
        adapter.validate(target, 0, _revoke(ROLE_OPEN, account), bytes32(0));
    }

    function testFuzz_validate_frozenRoleAlwaysReverts(address account) public {
        vm.expectRevert(RoleGrantAdapter.RoleFrozen.selector);
        adapter.validate(target, 0, _grant(ROLE_FROZEN, account), bytes32(0));
        vm.expectRevert(RoleGrantAdapter.RoleFrozen.selector);
        adapter.validate(target, 0, _revoke(ROLE_FROZEN, account), bytes32(0));
    }

    function testFuzz_validate_unregisteredRoleReverts(bytes32 randomRole, address account) public {
        vm.assume(randomRole != ROLE_OPEN && randomRole != ROLE_FROZEN);
        vm.expectRevert(RoleGrantAdapter.RoleNotAllowed.selector);
        adapter.validate(target, 0, _grant(randomRole, account), bytes32(0));
    }
}
