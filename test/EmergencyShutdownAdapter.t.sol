// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EmergencyShutdownAdapter} from "../contracts/EmergencyShutdownAdapter.sol";

contract EmergencyShutdownAdapterTest is Test {
    EmergencyShutdownAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);
    address targetTriggerOnly = address(0xBEEF);
    address targetBoth = address(0xFEED);
    address targetUnregistered = address(0xDEAD);

    function setUp() public {
        adapter = new EmergencyShutdownAdapter(owner);

        vm.startPrank(owner);
        // target: trigger only (cancel disabled — irrevocable shutdown, the safe default)
        adapter.setPolicy(target, true, false);
        // targetTriggerOnly: same shape, redundant alias for clarity in tests
        adapter.setPolicy(targetTriggerOnly, true, false);
        // targetBoth: trigger AND cancel allowed (rare opt-in, e.g. test deploys)
        adapter.setPolicy(targetBoth, true, true);
        vm.stopPrank();
    }

    function _triggerCalldata() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("triggerEmergencyShutdown()");
    }

    function _cancelCalldata() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("cancelShutdown()");
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _triggerCalldata();
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_cancelIsDeterministic() public view {
        bytes memory data = _cancelCalldata();
        bytes32 a = adapter.intentHash(targetBoth, 0, data);
        bytes32 b = adapter.intentHash(targetBoth, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_triggerAndCancelDiffer() public view {
        bytes32 hashTrigger = adapter.intentHash(target, 0, _triggerCalldata());
        bytes32 hashCancel = adapter.intentHash(target, 0, _cancelCalldata());
        assertTrue(hashTrigger != hashCancel, "trigger and cancel must produce different intents");
    }

    function test_intentHash_bindsTarget() public view {
        bytes32 a = adapter.intentHash(target, 0, _triggerCalldata());
        bytes32 b = adapter.intentHash(targetBoth, 0, _triggerCalldata());
        assertTrue(a != b, "different targets must produce different intents");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(EmergencyShutdownAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnTriggerWithExtraArgs() public {
        // triggerEmergencyShutdown() takes no args; calldata with anything
        // beyond 4 bytes is malformed
        bytes memory data = abi.encodePacked(adapter.TRIGGER_SHUTDOWN_SELECTOR(), uint256(42));
        vm.expectRevert(EmergencyShutdownAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnCancelWithExtraArgs() public {
        bytes memory data = abi.encodePacked(adapter.CANCEL_SHUTDOWN_SELECTOR(), uint256(7));
        vm.expectRevert(EmergencyShutdownAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    // ============ validate ============

    function test_validate_passesTriggerWhenAllowed() public view {
        adapter.validate(target, 0, _triggerCalldata(), bytes32(0));
    }

    function test_validate_passesCancelWhenAllowed() public view {
        adapter.validate(targetBoth, 0, _cancelCalldata(), bytes32(0));
    }

    function test_validate_revertsTriggerWhenNotAllowed() public {
        // Disable trigger on `target`, leave cancel as-is (still false)
        vm.prank(owner);
        adapter.setPolicy(target, false, false);

        vm.expectRevert(EmergencyShutdownAdapter.TriggerNotAllowed.selector);
        adapter.validate(target, 0, _triggerCalldata(), bytes32(0));
    }

    function test_validate_revertsCancelWhenNotAllowedDefault() public {
        // `target` was set with cancelAllowed=false (the safe default)
        vm.expectRevert(EmergencyShutdownAdapter.CancelNotAllowed.selector);
        adapter.validate(target, 0, _cancelCalldata(), bytes32(0));
    }

    function test_validate_revertsForUnregisteredTarget() public {
        // Unregistered targets have triggerAllowed=false by default
        vm.expectRevert(EmergencyShutdownAdapter.TriggerNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, _triggerCalldata(), bytes32(0));

        // ...and cancelAllowed=false by default
        vm.expectRevert(EmergencyShutdownAdapter.CancelNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, _cancelCalldata(), bytes32(0));
    }

    // ============ access control ============

    function test_setPolicy_revertsForNonOwner() public {
        vm.expectRevert(EmergencyShutdownAdapter.NotOwner.selector);
        adapter.setPolicy(target, true, true);
    }

    function test_setPolicy_emitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit EmergencyShutdownAdapter.PolicySet(targetUnregistered, true, false);
        vm.prank(owner);
        adapter.setPolicy(targetUnregistered, true, false);
    }

    // ============ constructor ============

    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(EmergencyShutdownAdapter.ZeroOwner.selector);
        new EmergencyShutdownAdapter(address(0));
    }
}
