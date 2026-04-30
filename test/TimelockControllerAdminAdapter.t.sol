// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TimelockControllerAdminAdapter} from "../contracts/TimelockControllerAdminAdapter.sol";

contract TimelockControllerAdminAdapterTest is Test {
    TimelockControllerAdminAdapter adapter;
    address owner = address(0xA11CE);
    address timelock = address(0x71E10C);
    address timelockAlt = address(0x71E10D);

    uint256 constant MIN_DELAY = 1 days;
    uint256 constant MAX_DELAY = 30 days;

    function setUp() public {
        adapter = new TimelockControllerAdminAdapter(owner);

        vm.prank(owner);
        adapter.setDelayPolicy(timelock, true, MIN_DELAY, MAX_DELAY);
    }

    function _updateDelayCalldata(uint256 newDelay) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("updateDelay(uint256)", newDelay);
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _updateDelayCalldata(7 days);
        bytes32 hash1 = adapter.intentHash(timelock, 0, data);
        bytes32 hash2 = adapter.intentHash(timelock, 0, data);
        assertEq(hash1, hash2, "intentHash must be deterministic");
        assertTrue(hash1 != bytes32(0), "intentHash must be non-zero");
    }

    function test_intentHash_bindsNewDelay() public view {
        bytes32 hashA = adapter.intentHash(timelock, 0, _updateDelayCalldata(2 days));
        bytes32 hashB = adapter.intentHash(timelock, 0, _updateDelayCalldata(7 days));
        assertTrue(hashA != hashB, "different delays must produce different intent hashes");
    }

    function test_intentHash_bindsTarget() public view {
        bytes memory data = _updateDelayCalldata(7 days);
        bytes32 hashA = adapter.intentHash(timelock, 0, data);
        bytes32 hashB = adapter.intentHash(timelockAlt, 0, data);
        assertTrue(hashA != hashB, "different targets must produce different intent hashes");
    }

    function test_intentHash_bindsValue() public view {
        bytes memory data = _updateDelayCalldata(7 days);
        bytes32 hashA = adapter.intentHash(timelock, 0, data);
        bytes32 hashB = adapter.intentHash(timelock, 1 ether, data);
        assertTrue(hashA != hashB, "different values must produce different intent hashes");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo(uint256)", 7 days);
        vm.expectRevert(TimelockControllerAdminAdapter.BadSelector.selector);
        adapter.intentHash(timelock, 0, data);
    }

    function test_intentHash_revertsOnTruncatedCalldata() public {
        bytes memory data = abi.encodePacked(adapter.UPDATE_DELAY_SELECTOR(), bytes16(0));
        vm.expectRevert(TimelockControllerAdminAdapter.BadSelector.selector);
        adapter.intentHash(timelock, 0, data);
    }

    function test_intentHash_revertsOnExtraTrailingBytes() public {
        bytes memory data = abi.encodePacked(
            adapter.UPDATE_DELAY_SELECTOR(),
            bytes32(uint256(7 days)),
            bytes32(uint256(0xDEADBEEF))
        );
        vm.expectRevert(TimelockControllerAdminAdapter.BadSelector.selector);
        adapter.intentHash(timelock, 0, data);
    }

    // ============ validate ============

    function test_validate_passesAtMinDelay() public view {
        adapter.validate(timelock, 0, _updateDelayCalldata(MIN_DELAY), bytes32(0));
    }

    function test_validate_passesAtMaxDelay() public view {
        adapter.validate(timelock, 0, _updateDelayCalldata(MAX_DELAY), bytes32(0));
    }

    function test_validate_passesInsideBand() public view {
        adapter.validate(timelock, 0, _updateDelayCalldata(7 days), bytes32(0));
    }

    function test_validate_revertsBelowMinDelay() public {
        // The load-bearing attack: pre-signed "set delay to 1 second" call.
        vm.expectRevert(TimelockControllerAdminAdapter.BelowMinDelay.selector);
        adapter.validate(timelock, 0, _updateDelayCalldata(1), bytes32(0));
    }

    function test_validate_revertsBelowMinDelayJustUnder() public {
        vm.expectRevert(TimelockControllerAdminAdapter.BelowMinDelay.selector);
        adapter.validate(timelock, 0, _updateDelayCalldata(MIN_DELAY - 1), bytes32(0));
    }

    function test_validate_revertsAboveMaxDelay() public {
        vm.expectRevert(TimelockControllerAdminAdapter.AboveMaxDelay.selector);
        adapter.validate(timelock, 0, _updateDelayCalldata(MAX_DELAY + 1), bytes32(0));
    }

    function test_validate_revertsOnUnregisteredTarget() public {
        vm.expectRevert(TimelockControllerAdminAdapter.TargetNotAllowed.selector);
        adapter.validate(address(0xDEAD), 0, _updateDelayCalldata(7 days), bytes32(0));
    }

    function test_validate_revertsOnDisabledTarget() public {
        vm.prank(owner);
        adapter.setDelayPolicy(timelock, false, MIN_DELAY, MAX_DELAY);

        vm.expectRevert(TimelockControllerAdminAdapter.TargetNotAllowed.selector);
        adapter.validate(timelock, 0, _updateDelayCalldata(7 days), bytes32(0));
    }

    function test_validate_revertsOnGrantRoleSelector() public {
        // grantRole/revokeRole must NOT be covered by this adapter — those
        // route through RoleGrantAdapter. Confirm the calldata doesn't decode.
        bytes memory data = abi.encodeWithSignature(
            "grantRole(bytes32,address)", bytes32(uint256(1)), address(0xBEEF)
        );
        vm.expectRevert(TimelockControllerAdminAdapter.BadSelector.selector);
        adapter.validate(timelock, 0, data, bytes32(0));
    }

    // ============ access control & policy hygiene ============

    function test_setDelayPolicy_revertsForNonOwner() public {
        vm.expectRevert(TimelockControllerAdminAdapter.NotOwner.selector);
        adapter.setDelayPolicy(timelock, true, MIN_DELAY, MAX_DELAY);
    }

    function test_setDelayPolicy_revertsOnInvertedBand() public {
        vm.prank(owner);
        vm.expectRevert(TimelockControllerAdminAdapter.BadBand.selector);
        adapter.setDelayPolicy(timelock, true, MAX_DELAY, MIN_DELAY);
    }

    function test_setDelayPolicy_invertedBandAllowedWhenDisabled() public {
        // When `allowed = false`, the band check is skipped — useful for
        // disabling without resupplying valid bounds.
        vm.prank(owner);
        adapter.setDelayPolicy(timelock, false, MAX_DELAY, MIN_DELAY);
        TimelockControllerAdminAdapter.DelayPolicy memory pol = adapter.getDelayPolicy(timelock);
        assertEq(pol.allowed, false);
    }

    function test_setDelayPolicy_emitsEvent() public {
        vm.expectEmit(true, false, false, true, address(adapter));
        emit TimelockControllerAdminAdapter.DelayPolicySet(timelockAlt, true, 2 days, 14 days);
        vm.prank(owner);
        adapter.setDelayPolicy(timelockAlt, true, 2 days, 14 days);
    }

    function test_getDelayPolicy_returnsRegistered() public view {
        TimelockControllerAdminAdapter.DelayPolicy memory pol = adapter.getDelayPolicy(timelock);
        assertEq(pol.allowed, true);
        assertEq(pol.minDelay, MIN_DELAY);
        assertEq(pol.maxDelay, MAX_DELAY);
    }
}
