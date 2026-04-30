// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OwnershipTransferAdapter} from "../../contracts/OwnershipTransferAdapter.sol";

contract OwnershipTransferAdapterFuzzTest is Test {
    OwnershipTransferAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);
    address allowedNewOwner = address(0x1111);

    function setUp() public {
        adapter = new OwnershipTransferAdapter(owner);
        vm.startPrank(owner);
        adapter.setTargetPolicy(target, true, false); // transfer allowed, renounce disabled
        adapter.setAllowedNewOwner(target, allowedNewOwner, true);
        vm.stopPrank();
    }

    function _transfer(address newOwner) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transferOwnership(address)", newOwner);
    }

    function testFuzz_intentHash_deterministic(address newOwner) public view {
        bytes memory data = _transfer(newOwner);
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function testFuzz_intentHash_bindsNewOwner(address o1, address o2) public view {
        vm.assume(o1 != o2);
        bytes32 h1 = adapter.intentHash(target, 0, _transfer(o1));
        bytes32 h2 = adapter.intentHash(target, 0, _transfer(o2));
        assertTrue(h1 != h2);
    }

    function testFuzz_validate_disallowedNewOwnerReverts(address candidate) public {
        vm.assume(candidate != allowedNewOwner);
        bytes memory data = _transfer(candidate);
        vm.expectRevert(OwnershipTransferAdapter.NewOwnerNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function testFuzz_validate_renounceAlwaysRevertsByDefault() public {
        bytes memory data = abi.encodeWithSignature("renounceOwnership()");
        vm.expectRevert(OwnershipTransferAdapter.ActionNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }
}
