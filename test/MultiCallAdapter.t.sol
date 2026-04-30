// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MultiCallAdapter} from "../contracts/MultiCallAdapter.sol";

contract MultiCallAdapterTest is Test {
    MultiCallAdapter adapter;
    address owner = address(0xA11CE);
    address multicall = address(0xBEEF);

    address subA = address(0x1111);
    address subB = address(0x2222);
    address subC = address(0x3333);
    address subEvil = address(0xDEAD);

    function setUp() public {
        adapter = new MultiCallAdapter(owner);

        vm.startPrank(owner);
        adapter.setMulticallAllowed(multicall, true);
        adapter.setSubTargetAllowed(multicall, subA, true);
        adapter.setSubTargetAllowed(multicall, subB, true);
        adapter.setSubTargetAllowed(multicall, subC, true);
        // subEvil intentionally NOT on the allowlist.
        vm.stopPrank();
    }

    // ============ Helpers ============

    function _batchCalldata(address[] memory targets, bytes[] memory payloads)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature("batchExecute(address[],bytes[])", targets, payloads);
    }

    function _twoEntry() internal view returns (address[] memory, bytes[] memory) {
        address[] memory t = new address[](2);
        bytes[] memory p = new bytes[](2);
        t[0] = subA;
        t[1] = subB;
        p[0] = abi.encodeWithSignature("foo(uint256)", 1);
        p[1] = abi.encodeWithSignature("bar(uint256)", 2);
        return (t, p);
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        (address[] memory t, bytes[] memory p) = _twoEntry();
        bytes memory data = _batchCalldata(t, p);

        bytes32 h1 = adapter.intentHash(multicall, 0, data);
        bytes32 h2 = adapter.intentHash(multicall, 0, data);
        assertEq(h1, h2, "intentHash must be deterministic");
        assertTrue(h1 != bytes32(0), "intentHash must be non-zero");
    }

    function test_intentHash_bindsTarget() public view {
        (address[] memory t, bytes[] memory p) = _twoEntry();
        bytes memory data = _batchCalldata(t, p);

        bytes32 hA = adapter.intentHash(multicall, 0, data);
        bytes32 hB = adapter.intentHash(address(0xCAFE), 0, data);
        assertTrue(hA != hB, "different multicall targets must produce different intents");
    }

    function test_intentHash_bindsValue() public view {
        (address[] memory t, bytes[] memory p) = _twoEntry();
        bytes memory data = _batchCalldata(t, p);

        bytes32 hZero = adapter.intentHash(multicall, 0, data);
        bytes32 hOne = adapter.intentHash(multicall, 1 ether, data);
        assertTrue(hZero != hOne, "different value must produce different intents");
    }

    function test_intentHash_differentSubTargets_differentHashes() public view {
        // Batch A: [subA, subB]
        (address[] memory tA, bytes[] memory pA) = _twoEntry();

        // Batch B: [subA, subC] (swap second sub-target)
        address[] memory tB = new address[](2);
        bytes[] memory pB = new bytes[](2);
        tB[0] = subA;
        tB[1] = subC;
        pB[0] = pA[0];
        pB[1] = pA[1];

        bytes32 hA = adapter.intentHash(multicall, 0, _batchCalldata(tA, pA));
        bytes32 hB = adapter.intentHash(multicall, 0, _batchCalldata(tB, pB));
        assertTrue(hA != hB, "different sub-target sets must produce different intents");
    }

    function test_intentHash_differentPayloads_differentHashes() public view {
        (address[] memory tA, bytes[] memory pA) = _twoEntry();

        // Same targets, mutate one payload byte.
        address[] memory tB = new address[](2);
        bytes[] memory pB = new bytes[](2);
        tB[0] = tA[0];
        tB[1] = tA[1];
        pB[0] = pA[0];
        pB[1] = abi.encodeWithSignature("bar(uint256)", 999); // different arg

        bytes32 hA = adapter.intentHash(multicall, 0, _batchCalldata(tA, pA));
        bytes32 hB = adapter.intentHash(multicall, 0, _batchCalldata(tB, pB));
        assertTrue(hA != hB, "different payload bytes must produce different intents");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(MultiCallAdapter.BadSelector.selector);
        adapter.intentHash(multicall, 0, data);
    }

    function test_intentHash_revertsOnTruncatedCalldata() public {
        // Selector + 16 bytes — well below the 128-byte minimum for two
        // dynamic arrays' offsets+lengths.
        bytes memory data = abi.encodePacked(
            adapter.BATCH_EXECUTE_SELECTOR(),
            bytes16(0)
        );
        vm.expectRevert(MultiCallAdapter.BadSelector.selector);
        adapter.intentHash(multicall, 0, data);
    }

    function test_intentHash_revertsOnLengthMismatch() public {
        // 2 targets but only 1 payload — abi-decode succeeds, then
        // explicit length-mismatch check fires.
        address[] memory t = new address[](2);
        bytes[] memory p = new bytes[](1);
        t[0] = subA;
        t[1] = subB;
        p[0] = abi.encodeWithSignature("foo()");
        bytes memory data = _batchCalldata(t, p);

        vm.expectRevert(MultiCallAdapter.BatchLengthMismatch.selector);
        adapter.intentHash(multicall, 0, data);
    }

    // ============ validate ============

    function test_validate_happyPath_allSubTargetsAllowlisted() public view {
        (address[] memory t, bytes[] memory p) = _twoEntry();
        bytes memory data = _batchCalldata(t, p);
        adapter.validate(multicall, 0, data, bytes32(0));
        // No revert == pass.
    }

    function test_validate_revertsOnAnySubTargetNotAllowlisted() public {
        // Mostly-benign batch with one malicious entry sneaked in.
        address[] memory t = new address[](3);
        bytes[] memory p = new bytes[](3);
        t[0] = subA;
        t[1] = subEvil; // <-- not on allowlist
        t[2] = subB;
        p[0] = abi.encodeWithSignature("foo()");
        p[1] = abi.encodeWithSignature("drain(address)", address(0xBAD));
        p[2] = abi.encodeWithSignature("bar()");

        vm.expectRevert(MultiCallAdapter.SubTargetNotAllowed.selector);
        adapter.validate(multicall, 0, _batchCalldata(t, p), bytes32(0));
    }

    function test_validate_revertsOnUnregisteredMulticallTarget() public {
        (address[] memory t, bytes[] memory p) = _twoEntry();
        vm.expectRevert(MultiCallAdapter.MulticallNotAllowed.selector);
        adapter.validate(address(0xDEAD), 0, _batchCalldata(t, p), bytes32(0));
    }

    function test_validate_revertsOnDisabledMulticall() public {
        vm.prank(owner);
        adapter.setMulticallAllowed(multicall, false);

        (address[] memory t, bytes[] memory p) = _twoEntry();
        vm.expectRevert(MultiCallAdapter.MulticallNotAllowed.selector);
        adapter.validate(multicall, 0, _batchCalldata(t, p), bytes32(0));
    }

    function test_validate_revertsOnBatchTooLarge() public {
        vm.prank(owner);
        adapter.setMaxBatchSize(multicall, 2);

        // 3-entry batch > cap of 2.
        address[] memory t = new address[](3);
        bytes[] memory p = new bytes[](3);
        t[0] = subA;
        t[1] = subB;
        t[2] = subC;
        p[0] = abi.encodeWithSignature("a()");
        p[1] = abi.encodeWithSignature("b()");
        p[2] = abi.encodeWithSignature("c()");

        vm.expectRevert(MultiCallAdapter.BatchTooLarge.selector);
        adapter.validate(multicall, 0, _batchCalldata(t, p), bytes32(0));
    }

    function test_validate_passesAtBatchSizeCap() public {
        vm.prank(owner);
        adapter.setMaxBatchSize(multicall, 2);

        (address[] memory t, bytes[] memory p) = _twoEntry();
        adapter.validate(multicall, 0, _batchCalldata(t, p), bytes32(0));
        // No revert == pass at the boundary.
    }

    /// @notice Empty batches pass `validate` (trivially safe — no sub-calls
    /// fire). The intent-hash binding still prevents replay; this is a
    /// documented design choice rather than a missing check.
    function test_validate_passesOnEmptyBatch() public view {
        address[] memory t = new address[](0);
        bytes[] memory p = new bytes[](0);
        adapter.validate(multicall, 0, _batchCalldata(t, p), bytes32(0));
    }

    function test_validate_revertsOnSubTargetRemovedFromAllowlist() public {
        // Remove subB from the allowlist after setUp; a batch containing
        // it must fail.
        vm.prank(owner);
        adapter.setSubTargetAllowed(multicall, subB, false);

        (address[] memory t, bytes[] memory p) = _twoEntry();
        vm.expectRevert(MultiCallAdapter.SubTargetNotAllowed.selector);
        adapter.validate(multicall, 0, _batchCalldata(t, p), bytes32(0));
    }

    // ============ Access control ============

    function test_setMulticallAllowed_revertsForNonOwner() public {
        vm.expectRevert(MultiCallAdapter.NotOwner.selector);
        adapter.setMulticallAllowed(multicall, false);
    }

    function test_setSubTargetAllowed_revertsForNonOwner() public {
        vm.expectRevert(MultiCallAdapter.NotOwner.selector);
        adapter.setSubTargetAllowed(multicall, subA, true);
    }

    function test_setMaxBatchSize_revertsForNonOwner() public {
        vm.expectRevert(MultiCallAdapter.NotOwner.selector);
        adapter.setMaxBatchSize(multicall, 5);
    }

    // ============ Constructor ============

    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(MultiCallAdapter.ZeroOwner.selector);
        new MultiCallAdapter(address(0));
    }
}
