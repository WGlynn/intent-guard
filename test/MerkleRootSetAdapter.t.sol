// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MerkleRootSetAdapter} from "../contracts/MerkleRootSetAdapter.sol";

contract MerkleRootSetAdapterTest is Test {
    MerkleRootSetAdapter adapter;
    address owner = address(0xA11CE);
    address target = address(0xCAFE);
    address targetNoAnnounce = address(0xFEED);
    address targetUnregistered = address(0xDEAD);

    bytes32 constant ROOT_LEGIT = bytes32(uint256(0x1111));
    bytes32 constant ROOT_MALICIOUS = bytes32(uint256(0x9999));

    function setUp() public {
        adapter = new MerkleRootSetAdapter(owner);

        vm.startPrank(owner);
        adapter.setTargetPolicy(target, true, true);
        adapter.announceMerkleRoot(target, ROOT_LEGIT);

        // targetNoAnnounce: allowed, but pre-announcement bypass enabled
        adapter.setTargetPolicy(targetNoAnnounce, true, false);
        vm.stopPrank();
    }

    function _setRootCalldata(bytes32 root) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setMerkleRoot(bytes32)", root);
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _setRootCalldata(ROOT_LEGIT);
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(target, 0, data);
        assertEq(a, b);
    }

    function test_intentHash_bindsRoot() public view {
        bytes32 a = adapter.intentHash(target, 0, _setRootCalldata(ROOT_LEGIT));
        bytes32 b = adapter.intentHash(target, 0, _setRootCalldata(ROOT_MALICIOUS));
        assertTrue(a != b);
    }

    function test_intentHash_bindsTarget() public view {
        bytes memory data = _setRootCalldata(ROOT_LEGIT);
        bytes32 a = adapter.intentHash(target, 0, data);
        bytes32 b = adapter.intentHash(targetNoAnnounce, 0, data);
        assertTrue(a != b);
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(MerkleRootSetAdapter.BadSelector.selector);
        adapter.intentHash(target, 0, data);
    }

    // ============ validate ============

    function test_validate_passesAnnouncedRoot() public view {
        adapter.validate(target, 0, _setRootCalldata(ROOT_LEGIT), bytes32(0));
    }

    function test_validate_revertsOnUnannouncedRoot() public {
        vm.expectRevert(MerkleRootSetAdapter.RootNotAnnounced.selector);
        adapter.validate(target, 0, _setRootCalldata(ROOT_MALICIOUS), bytes32(0));
    }

    function test_validate_passesAnyRootWhenAnnouncementBypassed() public view {
        // targetNoAnnounce has requireAnnouncement=false; any root passes
        adapter.validate(targetNoAnnounce, 0, _setRootCalldata(ROOT_MALICIOUS), bytes32(0));
    }

    function test_validate_revertsForUnregisteredTarget() public {
        vm.expectRevert(MerkleRootSetAdapter.TargetNotAllowed.selector);
        adapter.validate(targetUnregistered, 0, _setRootCalldata(ROOT_LEGIT), bytes32(0));
    }

    function test_validate_revertsAfterTargetDisabled() public {
        vm.prank(owner);
        adapter.setTargetPolicy(target, false, true);
        vm.expectRevert(MerkleRootSetAdapter.TargetNotAllowed.selector);
        adapter.validate(target, 0, _setRootCalldata(ROOT_LEGIT), bytes32(0));
    }

    // ============ announcement records ============

    function test_announcement_recordedWithAnnouncer() public view {
        (bool announced, address announcer, uint64 ts) = adapter.announcement(target, ROOT_LEGIT);
        assertTrue(announced);
        assertEq(announcer, owner);
        assertGt(ts, 0);
    }

    function test_announcement_distinctRootsTrackedSeparately() public {
        // ROOT_MALICIOUS not announced for `target`
        (bool announced,,) = adapter.announcement(target, ROOT_MALICIOUS);
        assertFalse(announced);

        // After announcing it, validate should pass
        vm.prank(owner);
        adapter.announceMerkleRoot(target, ROOT_MALICIOUS);
        adapter.validate(target, 0, _setRootCalldata(ROOT_MALICIOUS), bytes32(0));
    }

    // ============ access control ============

    function test_setTargetPolicy_revertsForNonOwner() public {
        vm.expectRevert(MerkleRootSetAdapter.NotOwner.selector);
        adapter.setTargetPolicy(target, false, false);
    }

    function test_announceMerkleRoot_revertsForNonOwner() public {
        vm.expectRevert(MerkleRootSetAdapter.NotOwner.selector);
        adapter.announceMerkleRoot(target, ROOT_MALICIOUS);
    }
}
