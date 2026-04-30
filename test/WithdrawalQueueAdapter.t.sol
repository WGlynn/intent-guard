// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WithdrawalQueueAdapter} from "../contracts/WithdrawalQueueAdapter.sol";

contract WithdrawalQueueAdapterTest is Test {
    WithdrawalQueueAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);
    address targetPauseOnly = address(0xBEEF);
    address targetUnregistered = address(0xDEAD);

    // Default policy ranges for `target`
    uint256 constant MIN_DELAY = 1 days;
    uint256 constant MAX_DELAY = 30 days;
    uint256 constant MIN_MAX_PER_EPOCH = 1e18;
    uint256 constant MAX_MAX_PER_EPOCH = 1_000_000e18;

    function setUp() public {
        adapter = new WithdrawalQueueAdapter(owner);

        vm.startPrank(owner);
        // target: full policy, both pause + unpause allowed
        adapter.setWithdrawalPolicy(
            target,
            true,
            MIN_DELAY,
            MAX_DELAY,
            MIN_MAX_PER_EPOCH,
            MAX_MAX_PER_EPOCH,
            true,
            true
        );
        // targetPauseOnly: pause allowed, unpause blocked (operator-only restart)
        adapter.setWithdrawalPolicy(
            targetPauseOnly,
            true,
            MIN_DELAY,
            MAX_DELAY,
            MIN_MAX_PER_EPOCH,
            MAX_MAX_PER_EPOCH,
            true,
            false
        );
        vm.stopPrank();
    }

    // ============ calldata helpers ============

    function _setDelayCalldata(uint256 newDelay) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setWithdrawalDelay(uint256)", newDelay);
    }

    function _setMaxPerEpochCalldata(uint256 newMax) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setMaxWithdrawalPerEpoch(uint256)", newMax);
    }

    function _pauseCalldata() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("pauseWithdrawals()");
    }

    function _unpauseCalldata() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("unpauseWithdrawals()");
    }

    // ============ intentHash determinism ============

    function test_intentHash_determinismSetDelay() public view {
        bytes memory data = _setDelayCalldata(7 days);
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_determinismSetMaxPerEpoch() public view {
        bytes memory data = _setMaxPerEpochCalldata(1000e18);
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_determinismPause() public view {
        bytes32 a = adapter.intentHash(target, 0, _pauseCalldata());
        bytes32 b = adapter.intentHash(target, 0, _pauseCalldata());
        assertEq(a, b);
    }

    function test_intentHash_determinismUnpause() public view {
        bytes32 a = adapter.intentHash(target, 0, _unpauseCalldata());
        bytes32 b = adapter.intentHash(target, 0, _unpauseCalldata());
        assertEq(a, b);
    }

    // ============ intentHash binding ============

    function test_intentHash_bindsDelayValue() public view {
        bytes32 a = adapter.intentHash(target, 0, _setDelayCalldata(7 days));
        bytes32 b = adapter.intentHash(target, 0, _setDelayCalldata(14 days));
        assertTrue(a != b, "different delays must produce different intents");
    }

    function test_intentHash_bindsMaxPerEpochValue() public view {
        bytes32 a = adapter.intentHash(target, 0, _setMaxPerEpochCalldata(100e18));
        bytes32 b = adapter.intentHash(target, 0, _setMaxPerEpochCalldata(200e18));
        assertTrue(a != b, "different max-per-epoch must produce different intents");
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
        vm.expectRevert(WithdrawalQueueAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnPauseWithExtraArgs() public {
        // pauseWithdrawals() takes no args; trailing data must revert
        bytes memory data = abi.encodePacked(adapter.PAUSE_WITHDRAWALS_SELECTOR(), uint256(1));
        vm.expectRevert(WithdrawalQueueAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnSetDelayWithMissingArg() public {
        // setWithdrawalDelay requires 32 bytes of args; bare selector must revert
        bytes memory data = abi.encodePacked(adapter.SET_WITHDRAWAL_DELAY_SELECTOR());
        vm.expectRevert(WithdrawalQueueAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    // ============ validate happy paths ============

    function test_validate_passesSetDelayInRange() public view {
        adapter.validate(target, 0, _setDelayCalldata(7 days), bytes32(0));
    }

    function test_validate_passesSetDelayAtMin() public view {
        adapter.validate(target, 0, _setDelayCalldata(MIN_DELAY), bytes32(0));
    }

    function test_validate_passesSetDelayAtMax() public view {
        adapter.validate(target, 0, _setDelayCalldata(MAX_DELAY), bytes32(0));
    }

    function test_validate_passesSetMaxPerEpochInRange() public view {
        adapter.validate(target, 0, _setMaxPerEpochCalldata(500e18), bytes32(0));
    }

    function test_validate_passesPauseWhenAllowed() public view {
        adapter.validate(target, 0, _pauseCalldata(), bytes32(0));
    }

    function test_validate_passesUnpauseWhenAllowed() public view {
        adapter.validate(target, 0, _unpauseCalldata(), bytes32(0));
    }

    function test_validate_passesPauseOnPauseOnlyTarget() public view {
        adapter.validate(targetPauseOnly, 0, _pauseCalldata(), bytes32(0));
    }

    // ============ validate rejection paths ============

    function test_validate_revertsDelayBelowMin() public {
        bytes memory data = _setDelayCalldata(MIN_DELAY - 1);
        vm.expectRevert(WithdrawalQueueAdapter.DelayOutOfRange.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsDelayAboveMax() public {
        bytes memory data = _setDelayCalldata(MAX_DELAY + 1);
        vm.expectRevert(WithdrawalQueueAdapter.DelayOutOfRange.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsDelayAtMaxUint() public {
        // Lock-out attack: malicious setWithdrawalDelay(MAX_UINT)
        bytes memory data = _setDelayCalldata(type(uint256).max);
        vm.expectRevert(WithdrawalQueueAdapter.DelayOutOfRange.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsMaxPerEpochBelowMin() public {
        bytes memory data = _setMaxPerEpochCalldata(MIN_MAX_PER_EPOCH - 1);
        vm.expectRevert(WithdrawalQueueAdapter.MaxPerEpochOutOfRange.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsMaxPerEpochAboveMax() public {
        bytes memory data = _setMaxPerEpochCalldata(MAX_MAX_PER_EPOCH + 1);
        vm.expectRevert(WithdrawalQueueAdapter.MaxPerEpochOutOfRange.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsMaxPerEpochAtMaxUint() public {
        // Drain attack: malicious setMaxWithdrawalPerEpoch(MAX_UINT) removes rate limit
        bytes memory data = _setMaxPerEpochCalldata(type(uint256).max);
        vm.expectRevert(WithdrawalQueueAdapter.MaxPerEpochOutOfRange.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsUnpauseOnPauseOnlyTarget() public {
        vm.expectRevert(WithdrawalQueueAdapter.ActionNotAllowed.selector);
        adapter.validate(targetPauseOnly, 0, _unpauseCalldata(), bytes32(0));
    }

    function test_validate_revertsPauseWhenDisabled() public {
        // Reconfigure target to disable pause
        vm.prank(owner);
        adapter.setWithdrawalPolicy(
            target,
            true,
            MIN_DELAY,
            MAX_DELAY,
            MIN_MAX_PER_EPOCH,
            MAX_MAX_PER_EPOCH,
            false,
            true
        );

        vm.expectRevert(WithdrawalQueueAdapter.ActionNotAllowed.selector);
        adapter.validate(target, 0, _pauseCalldata(), bytes32(0));
    }

    function test_validate_revertsForUnregisteredTarget() public {
        vm.expectRevert(WithdrawalQueueAdapter.TargetNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, _pauseCalldata(), bytes32(0));
    }

    function test_validate_revertsForUnregisteredTargetSetDelay() public {
        vm.expectRevert(WithdrawalQueueAdapter.TargetNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, _setDelayCalldata(7 days), bytes32(0));
    }

    function test_validate_revertsForDisallowedTarget() public {
        // Policy exists but allowed=false
        vm.prank(owner);
        adapter.setWithdrawalPolicy(target, false, 0, 0, 0, 0, false, false);

        vm.expectRevert(WithdrawalQueueAdapter.TargetNotAllowed.selector);
        adapter.validate(target, 0, _setDelayCalldata(7 days), bytes32(0));
    }

    function test_validate_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(WithdrawalQueueAdapter.BadSelector.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    // ============ access control ============

    function test_setWithdrawalPolicy_revertsForNonOwner() public {
        vm.expectRevert(WithdrawalQueueAdapter.NotOwner.selector);
        adapter.setWithdrawalPolicy(
            target,
            true,
            MIN_DELAY,
            MAX_DELAY,
            MIN_MAX_PER_EPOCH,
            MAX_MAX_PER_EPOCH,
            true,
            true
        );
    }

    // ============ getter ============

    function test_getWithdrawalPolicy_returnsConfiguredValues() public view {
        WithdrawalQueueAdapter.WithdrawalPolicy memory pol = adapter.getWithdrawalPolicy(target);
        assertTrue(pol.allowed);
        assertEq(pol.minDelay, MIN_DELAY);
        assertEq(pol.maxDelay, MAX_DELAY);
        assertEq(pol.minMaxPerEpoch, MIN_MAX_PER_EPOCH);
        assertEq(pol.maxMaxPerEpoch, MAX_MAX_PER_EPOCH);
        assertTrue(pol.pauseAllowed);
        assertTrue(pol.unpauseAllowed);
    }
}
