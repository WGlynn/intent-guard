// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BoundedParameterAdapter} from "../contracts/BoundedParameterAdapter.sol";

contract BoundedParameterAdapterTest is Test {
    BoundedParameterAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);
    address targetAlt = address(0xFADE);

    bytes32 constant KEY_VOLUME_CAP = keccak256("volume_cap");
    bytes32 constant KEY_PRICE_DEVIATION = keccak256("price_deviation_bps");
    bytes32 constant KEY_UNREGISTERED = keccak256("nope");

    function setUp() public {
        adapter = new BoundedParameterAdapter(owner);

        vm.startPrank(owner);
        // volume_cap: 100k - 10M USD, current 1M, max 50% change
        adapter.setParamPolicy(
            target,
            KEY_VOLUME_CAP,
            true,
            100_000e18,
            10_000_000e18,
            5000, // 50% max change
            1_000_000e18
        );

        // price_deviation_bps: 10-1000 bps (0.1%-10%), no change-ratio cap
        adapter.setParamPolicy(target, KEY_PRICE_DEVIATION, true, 10, 1000, 0, 500);
        vm.stopPrank();
    }

    function _setParamCalldata(bytes32 key, uint256 newValue) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setParam(bytes32,uint256)", key, newValue);
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _setParamCalldata(KEY_VOLUME_CAP, 2_000_000e18);
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_bindsKey() public view {
        bytes32 a = adapter.intentHash(target, 0, _setParamCalldata(KEY_VOLUME_CAP, 1e18));
        bytes32 b = adapter.intentHash(target, 0, _setParamCalldata(KEY_PRICE_DEVIATION, 1e18));
        assertTrue(a != b);
    }

    function test_intentHash_bindsValue() public view {
        bytes32 a = adapter.intentHash(target, 0, _setParamCalldata(KEY_VOLUME_CAP, 1e18));
        bytes32 b = adapter.intentHash(target, 0, _setParamCalldata(KEY_VOLUME_CAP, 2e18));
        assertTrue(a != b);
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(BoundedParameterAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    // ============ validate ============

    function test_validate_passesWithinBoundsAndChangeRatio() public view {
        // baseline 1M, new 1.4M = 40% change, within 50% cap
        bytes memory data = _setParamCalldata(KEY_VOLUME_CAP, 1_400_000e18);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsBelowMin() public {
        bytes memory data = _setParamCalldata(KEY_VOLUME_CAP, 50_000e18);
        vm.expectRevert(BoundedParameterAdapter.BelowMin.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsAboveMax() public {
        bytes memory data = _setParamCalldata(KEY_VOLUME_CAP, 50_000_000e18);
        vm.expectRevert(BoundedParameterAdapter.AboveMax.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsAboveChangeRatio() public {
        // 1M baseline, 60% change up → 1.6M. Bounds allow up to 10M, but
        // change ratio cap is 50%, so 1.6M exceeds 1.5M cap.
        bytes memory data = _setParamCalldata(KEY_VOLUME_CAP, 1_600_000e18);
        vm.expectRevert(BoundedParameterAdapter.ExceedsChangeRatio.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsOnRatioCapDownward() public {
        // 1M baseline, 60% change down → 400k. Above min, but exceeds
        // change ratio.
        bytes memory data = _setParamCalldata(KEY_VOLUME_CAP, 400_000e18);
        vm.expectRevert(BoundedParameterAdapter.ExceedsChangeRatio.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_skipsRatioWhenZero() public view {
        // KEY_PRICE_DEVIATION has maxChangeBps == 0; ratio check skipped.
        // 500 baseline → set to 50 (90% drop) should pass since min=10
        bytes memory data = _setParamCalldata(KEY_PRICE_DEVIATION, 50);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsOnUnregisteredKey() public {
        bytes memory data = _setParamCalldata(KEY_UNREGISTERED, 100);
        vm.expectRevert(BoundedParameterAdapter.ParamNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsForUnregisteredTarget() public {
        bytes memory data = _setParamCalldata(KEY_VOLUME_CAP, 1_000_000e18);
        vm.expectRevert(BoundedParameterAdapter.ParamNotAllowed.selector);
        adapter.validate(targetAlt, 0, data, bytes32(0));
    }

    // ============ baseline update flow ============

    function test_updateBaseline_shiftsRatioWindow() public {
        // After successful change to 1.4M, baseline updated to 1.4M
        vm.prank(owner);
        adapter.updateBaseline(target, KEY_VOLUME_CAP, 1_400_000e18);

        // Now 50% from 1.4M = 700k, so 700k change cap. Setting to 2M is +600k change, within new cap.
        bytes memory data = _setParamCalldata(KEY_VOLUME_CAP, 2_000_000e18);
        adapter.validate(target, 0, data, bytes32(0));
    }

    // ============ access control ============

    function test_setParamPolicy_revertsForNonOwner() public {
        vm.expectRevert(BoundedParameterAdapter.NotOwner.selector);
        adapter.setParamPolicy(target, KEY_VOLUME_CAP, true, 0, type(uint256).max, 0, 0);
    }

    function test_updateBaseline_revertsForNonOwner() public {
        vm.expectRevert(BoundedParameterAdapter.NotOwner.selector);
        adapter.updateBaseline(target, KEY_VOLUME_CAP, 5_000_000e18);
    }
}
