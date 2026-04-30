// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OracleSourceAdapter} from "../contracts/OracleSourceAdapter.sol";

contract OracleSourceAdapterTest is Test {
    OracleSourceAdapter adapter;
    address owner = address(0xA11CE);

    address target = address(0xBEEF);
    address otherTarget = address(0xCAFE);

    address assetA = address(0xAAA1);
    address assetB = address(0xAAA2);

    address oraclePrimary = address(0x0DEC1);
    address oracleFallback = address(0x0DEC2);
    address oracleEvil = address(0xBADD);

    function setUp() public {
        adapter = new OracleSourceAdapter(owner);

        // Register primary + fallback oracle for assetA on `target`.
        vm.startPrank(owner);
        adapter.setOracleAllowed(target, assetA, oraclePrimary, true);
        adapter.setOracleAllowed(target, assetA, oracleFallback, true);
        vm.stopPrank();
    }

    function _setOracleCalldata(address asset, address oracle) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setOracle(address,address)", asset, oracle);
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _setOracleCalldata(assetA, oraclePrimary);
        bytes32 hash1 = adapter.intentHash(target, 0, data);
        bytes32 hash2 = adapter.intentHash(target, 0, data);
        assertEq(hash1, hash2, "intentHash must be deterministic");
        assertTrue(hash1 != bytes32(0), "intentHash must be non-zero");
    }

    function test_intentHash_bindsAsset() public view {
        bytes memory dataA = _setOracleCalldata(assetA, oraclePrimary);
        bytes memory dataB = _setOracleCalldata(assetB, oraclePrimary);

        bytes32 hashA = adapter.intentHash(target, 0, dataA);
        bytes32 hashB = adapter.intentHash(target, 0, dataB);

        assertTrue(hashA != hashB, "different assets must produce different intent hashes");
    }

    function test_intentHash_bindsOracle() public view {
        bytes memory dataPrimary = _setOracleCalldata(assetA, oraclePrimary);
        bytes memory dataEvil = _setOracleCalldata(assetA, oracleEvil);

        bytes32 hashPrimary = adapter.intentHash(target, 0, dataPrimary);
        bytes32 hashEvil = adapter.intentHash(target, 0, dataEvil);

        assertTrue(hashPrimary != hashEvil, "different oracles must produce different intent hashes");
    }

    function test_intentHash_bindsTarget() public view {
        bytes memory data = _setOracleCalldata(assetA, oraclePrimary);

        bytes32 hashA = adapter.intentHash(target, 0, data);
        bytes32 hashB = adapter.intentHash(otherTarget, 0, data);

        assertTrue(hashA != hashB, "different targets must produce different intent hashes");
    }

    function test_intentHash_bindsValue() public view {
        bytes memory data = _setOracleCalldata(assetA, oraclePrimary);

        bytes32 hashZero = adapter.intentHash(target, 0, data);
        bytes32 hashOne = adapter.intentHash(target, 1, data);

        assertTrue(hashZero != hashOne, "different value must produce different intent hashes");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        // 4 + 64 length so length check passes; only the selector is wrong.
        bytes memory data = abi.encodeWithSignature(
            "setNotOracle(address,address)",
            assetA,
            oraclePrimary
        );
        vm.expectRevert(OracleSourceAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnTooShortCalldata() public {
        // Selector + only one address, missing the second.
        bytes memory data = abi.encodePacked(adapter.SET_ORACLE_SELECTOR(), bytes32(uint256(uint160(assetA))));
        vm.expectRevert(OracleSourceAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnEmptyCalldata() public {
        bytes memory data = "";
        vm.expectRevert(OracleSourceAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    function test_intentHash_revertsOnSelectorOnly() public {
        // Just the selector, no args.
        bytes memory data = abi.encodePacked(adapter.SET_ORACLE_SELECTOR());
        vm.expectRevert(OracleSourceAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    // ============ validate ============

    function test_validate_passesForRegisteredOracle() public view {
        bytes memory data = _setOracleCalldata(assetA, oraclePrimary);
        adapter.validate(target, 0, data, bytes32(0));
        // No revert == pass.
    }

    function test_validate_passesForAnyRegisteredOracleOnSameAsset() public view {
        // Both primary and fallback were registered in setUp; either passes.
        bytes memory dataPrimary = _setOracleCalldata(assetA, oraclePrimary);
        bytes memory dataFallback = _setOracleCalldata(assetA, oracleFallback);

        adapter.validate(target, 0, dataPrimary, bytes32(0));
        adapter.validate(target, 0, dataFallback, bytes32(0));
    }

    function test_validate_revertsOnUnregisteredOracleForRegisteredAsset() public {
        // assetA is registered with primary + fallback; oracleEvil is not.
        bytes memory data = _setOracleCalldata(assetA, oracleEvil);
        vm.expectRevert(OracleSourceAdapter.OracleNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsOnUnregisteredAsset() public {
        // assetB has no oracles registered for `target`.
        bytes memory data = _setOracleCalldata(assetB, oraclePrimary);
        vm.expectRevert(OracleSourceAdapter.OracleNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revertsOnUnregisteredTarget() public {
        // otherTarget has no policy at all.
        bytes memory data = _setOracleCalldata(assetA, oraclePrimary);
        vm.expectRevert(OracleSourceAdapter.OracleNotAllowed.selector);
        adapter.validate(otherTarget, 0, data, bytes32(0));
    }

    function test_validate_isPerTarget_sameAssetOracleOnDifferentTargetReverts() public {
        // Register the same (asset, oracle) pair on otherTarget; the existing
        // registration on `target` does NOT carry over.
        bytes memory data = _setOracleCalldata(assetA, oraclePrimary);
        vm.expectRevert(OracleSourceAdapter.OracleNotAllowed.selector);
        adapter.validate(otherTarget, 0, data, bytes32(0));

        vm.prank(owner);
        adapter.setOracleAllowed(otherTarget, assetA, oraclePrimary, true);
        adapter.validate(otherTarget, 0, data, bytes32(0));

        // The registration on `target` is unaffected and still passes.
        adapter.validate(target, 0, data, bytes32(0));
    }

    function test_validate_revokeRemovesOracle() public {
        bytes memory data = _setOracleCalldata(assetA, oraclePrimary);
        adapter.validate(target, 0, data, bytes32(0));

        vm.prank(owner);
        adapter.setOracleAllowed(target, assetA, oraclePrimary, false);

        vm.expectRevert(OracleSourceAdapter.OracleNotAllowed.selector);
        adapter.validate(target, 0, data, bytes32(0));

        // Fallback was registered separately and should still pass.
        bytes memory dataFallback = _setOracleCalldata(assetA, oracleFallback);
        adapter.validate(target, 0, dataFallback, bytes32(0));
    }

    // ============ access control ============

    function test_setOracleAllowed_revertsForNonOwner() public {
        vm.expectRevert(OracleSourceAdapter.NotOwner.selector);
        adapter.setOracleAllowed(target, assetA, oraclePrimary, true);
    }

    function test_setOracleAllowed_revertsForNonOwnerOnRevoke() public {
        // Someone other than the owner tries to disable an existing entry.
        vm.expectRevert(OracleSourceAdapter.NotOwner.selector);
        adapter.setOracleAllowed(target, assetA, oraclePrimary, false);
    }

    function test_setOracleAllowed_emitsEvent() public {
        vm.expectEmit(true, true, true, true);
        emit OracleSourceAdapter.OracleAllowed(target, assetB, oraclePrimary, true);
        vm.prank(owner);
        adapter.setOracleAllowed(target, assetB, oraclePrimary, true);
    }
}
