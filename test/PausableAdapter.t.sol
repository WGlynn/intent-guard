// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PausableAdapter} from "../contracts/PausableAdapter.sol";

contract PausableAdapterTest is Test {
    PausableAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);
    address targetPauseOnly = address(0xBEEF);
    address targetBoth = address(0xFEED);
    address targetUnregistered = address(0xDEAD);

    function setUp() public {
        adapter = new PausableAdapter(owner);

        vm.startPrank(owner);
        // target: both pause and unpause allowed
        adapter.setTargetPolicy(target, true, true);
        // targetPauseOnly: only pause allowed (unpause blocked — can't restart)
        adapter.setTargetPolicy(targetPauseOnly, true, false);
        // targetBoth: both allowed (used to test allowed-then-disabled flow)
        adapter.setTargetPolicy(targetBoth, true, true);
        vm.stopPrank();
    }

    function _pauseCalldata() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("pause()");
    }

    function _unpauseCalldata() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("unpause()");
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _pauseCalldata();
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_pauseAndUnpauseDiffer() public view {
        bytes32 hashPause = adapter.intentHash(target, 0, _pauseCalldata());
        bytes32 hashUnpause = adapter.intentHash(target, 0, _unpauseCalldata());
        assertTrue(hashPause != hashUnpause, "pause and unpause must produce different intents");
    }

    function test_intentHash_bindsTarget() public view {
        bytes32 a = adapter.intentHash(target, 0, _pauseCalldata());
        bytes32 b = adapter.intentHash(targetPauseOnly, 0, _pauseCalldata());
        assertTrue(a != b, "different targets must produce different intents");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(PausableAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnDataWithArgs() public {
        // pause()/unpause() take no args; calldata with anything beyond
        // 4 bytes is malformed
        bytes memory data = abi.encodePacked(adapter.PAUSE_SELECTOR(), uint256(42));
        vm.expectRevert(PausableAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    // ============ validate ============

    function test_validate_passesPauseWhenAllowed() public view {
        adapter.validate(target, 0, _pauseCalldata(), bytes32(0));
    }

    function test_validate_passesUnpauseWhenAllowed() public view {
        adapter.validate(target, 0, _unpauseCalldata(), bytes32(0));
    }

    function test_validate_passesPauseOnPauseOnlyTarget() public view {
        adapter.validate(targetPauseOnly, 0, _pauseCalldata(), bytes32(0));
    }

    function test_validate_revertsUnpauseOnPauseOnlyTarget() public {
        vm.expectRevert(PausableAdapter.ActionNotAllowed.selector);
        adapter.validate(targetPauseOnly, 0, _unpauseCalldata(), bytes32(0));
    }

    function test_validate_revertsForUnregisteredTarget() public {
        vm.expectRevert(PausableAdapter.ActionNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, _pauseCalldata(), bytes32(0));
    }

    function test_validate_revertsAfterPolicyDisabled() public {
        vm.prank(owner);
        adapter.setTargetPolicy(targetBoth, false, false);

        vm.expectRevert(PausableAdapter.ActionNotAllowed.selector);
        adapter.validate(targetBoth, 0, _pauseCalldata(), bytes32(0));

        vm.expectRevert(PausableAdapter.ActionNotAllowed.selector);
        adapter.validate(targetBoth, 0, _unpauseCalldata(), bytes32(0));
    }

    // ============ access control ============

    function test_setTargetPolicy_revertsForNonOwner() public {
        vm.expectRevert(PausableAdapter.NotOwner.selector);
        adapter.setTargetPolicy(target, false, false);
    }
}
