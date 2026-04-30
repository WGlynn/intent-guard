// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SignerSetUpdateAdapter} from "../contracts/SignerSetUpdateAdapter.sol";

contract SignerSetUpdateAdapterTest is Test {
    SignerSetUpdateAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);
    address targetFrozen = address(0xBEEF);
    address targetUnregistered = address(0xDEAD);
    address candidate = address(0xC0DE);
    address candidateAlt = address(0xFADE);

    function setUp() public {
        adapter = new SignerSetUpdateAdapter(owner);

        vm.startPrank(owner);
        // target: all three actions allowed, threshold range [2, 7]
        adapter.setPolicy(target, true, true, true, 2, 7);
        adapter.setAddCandidate(target, candidate, true);

        // targetFrozen: explicit zero policy by default — every action reverts
        // (do nothing for it)
        vm.stopPrank();
    }

    function _addCalldata(address newSigner) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("addSigner(address)", newSigner);
    }

    function _removeCalldata(address oldSigner) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("removeSigner(address)", oldSigner);
    }

    function _setThresholdCalldata(uint256 newThreshold) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setThreshold(uint256)", newThreshold);
    }

    // ============ constructor ============

    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(SignerSetUpdateAdapter.ZeroOwner.selector);
        new SignerSetUpdateAdapter(address(0));
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _addCalldata(candidate);
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_actionsDiffer() public view {
        bytes32 hashAdd = adapter.intentHash(target, 0, _addCalldata(candidate));
        bytes32 hashRemove = adapter.intentHash(target, 0, _removeCalldata(candidate));
        bytes32 hashThreshold = adapter.intentHash(target, 0, _setThresholdCalldata(3));
        assertTrue(hashAdd != hashRemove, "add and remove must differ");
        assertTrue(hashAdd != hashThreshold, "add and setThreshold must differ");
        assertTrue(hashRemove != hashThreshold, "remove and setThreshold must differ");
    }

    function test_intentHash_bindsTargetAndParam() public view {
        bytes32 a = adapter.intentHash(target, 0, _addCalldata(candidate));
        bytes32 b = adapter.intentHash(targetFrozen, 0, _addCalldata(candidate));
        bytes32 c = adapter.intentHash(target, 0, _addCalldata(candidateAlt));
        assertTrue(a != b, "different targets must differ");
        assertTrue(a != c, "different candidates must differ");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo(address)", candidate);
        vm.expectRevert(SignerSetUpdateAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnMalformedLength() public {
        // selector-only (no arg)
        bytes memory data = abi.encodePacked(adapter.ADD_SIGNER_SELECTOR());
        vm.expectRevert(SignerSetUpdateAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    // ============ validate — addSigner ============

    function test_validate_passesAddOnAllowedCandidate() public view {
        adapter.validate(target, 0, _addCalldata(candidate), bytes32(0));
    }

    function test_validate_revertsAddOnDisallowedCandidate() public {
        vm.expectRevert(SignerSetUpdateAdapter.CandidateNotAllowed.selector);
        adapter.validate(target, 0, _addCalldata(candidateAlt), bytes32(0));
    }

    function test_validate_revertsAddWhenAddNotAllowed() public {
        // Disable adds while keeping the rest of the policy live
        vm.prank(owner);
        adapter.setPolicy(target, false, true, true, 2, 7);

        vm.expectRevert(SignerSetUpdateAdapter.AddNotAllowed.selector);
        adapter.validate(target, 0, _addCalldata(candidate), bytes32(0));
    }

    function test_validate_revertsAddOnUnregisteredTarget() public {
        // Zero policy ⇒ addAllowed = false ⇒ AddNotAllowed
        vm.expectRevert(SignerSetUpdateAdapter.AddNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, _addCalldata(candidate), bytes32(0));
    }

    // ============ validate — removeSigner ============

    function test_validate_passesRemoveAnyAddress() public view {
        // Removal does not require allowlist — any address can be shed
        adapter.validate(target, 0, _removeCalldata(candidateAlt), bytes32(0));
    }

    function test_validate_revertsRemoveWhenRemoveNotAllowed() public {
        vm.prank(owner);
        adapter.setPolicy(target, true, false, true, 2, 7);

        vm.expectRevert(SignerSetUpdateAdapter.RemoveNotAllowed.selector);
        adapter.validate(target, 0, _removeCalldata(candidate), bytes32(0));
    }

    function test_validate_revertsRemoveOnUnregisteredTarget() public {
        vm.expectRevert(SignerSetUpdateAdapter.RemoveNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, _removeCalldata(candidate), bytes32(0));
    }

    // ============ validate — setThreshold ============

    function test_validate_passesThresholdAtLowerBound() public view {
        adapter.validate(target, 0, _setThresholdCalldata(2), bytes32(0));
    }

    function test_validate_passesThresholdAtUpperBound() public view {
        adapter.validate(target, 0, _setThresholdCalldata(7), bytes32(0));
    }

    function test_validate_passesThresholdInside() public view {
        adapter.validate(target, 0, _setThresholdCalldata(4), bytes32(0));
    }

    function test_validate_revertsThresholdBelowMin() public {
        vm.expectRevert(SignerSetUpdateAdapter.ThresholdOutOfRange.selector);
        adapter.validate(target, 0, _setThresholdCalldata(1), bytes32(0));
    }

    function test_validate_revertsThresholdAboveMax() public {
        vm.expectRevert(SignerSetUpdateAdapter.ThresholdOutOfRange.selector);
        adapter.validate(target, 0, _setThresholdCalldata(8), bytes32(0));
    }

    function test_validate_revertsThresholdWhenNotAllowed() public {
        vm.prank(owner);
        adapter.setPolicy(target, true, true, false, 2, 7);

        vm.expectRevert(SignerSetUpdateAdapter.ThresholdChangeNotAllowed.selector);
        adapter.validate(target, 0, _setThresholdCalldata(4), bytes32(0));
    }

    function test_validate_revertsThresholdOnUnregisteredTarget() public {
        vm.expectRevert(SignerSetUpdateAdapter.ThresholdChangeNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, _setThresholdCalldata(4), bytes32(0));
    }

    // ============ frozen / zero policy ============

    function test_validate_revertsAllActionsOnFrozenTarget() public {
        vm.expectRevert(SignerSetUpdateAdapter.AddNotAllowed.selector);
        adapter.validate(targetFrozen, 0, _addCalldata(candidate), bytes32(0));

        vm.expectRevert(SignerSetUpdateAdapter.RemoveNotAllowed.selector);
        adapter.validate(targetFrozen, 0, _removeCalldata(candidate), bytes32(0));

        vm.expectRevert(SignerSetUpdateAdapter.ThresholdChangeNotAllowed.selector);
        adapter.validate(targetFrozen, 0, _setThresholdCalldata(4), bytes32(0));
    }

    // ============ access control ============

    function test_setPolicy_revertsForNonOwner() public {
        vm.expectRevert(SignerSetUpdateAdapter.NotOwner.selector);
        adapter.setPolicy(target, true, true, true, 1, 10);
    }

    function test_setAddCandidate_revertsForNonOwner() public {
        vm.expectRevert(SignerSetUpdateAdapter.NotOwner.selector);
        adapter.setAddCandidate(target, candidate, true);
    }

    function test_setAddCandidate_canRevoke() public {
        vm.prank(owner);
        adapter.setAddCandidate(target, candidate, false);

        vm.expectRevert(SignerSetUpdateAdapter.CandidateNotAllowed.selector);
        adapter.validate(target, 0, _addCalldata(candidate), bytes32(0));
    }
}
