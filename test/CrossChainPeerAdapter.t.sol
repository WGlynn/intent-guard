// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CrossChainPeerAdapter} from "../contracts/CrossChainPeerAdapter.sol";

contract CrossChainPeerAdapterTest is Test {
    CrossChainPeerAdapter adapter;
    address owner = address(0xA11CE);
    address oapp = address(0xCAFE);
    address oappAlt = address(0xBEEF);

    uint32 constant EID_ETH = 30101;
    uint32 constant EID_ARB = 30110;
    uint32 constant EID_BLOCKED = 30200;

    bytes32 constant PEER_ETH_LEGIT = bytes32(uint256(uint160(0x1111)));
    bytes32 constant PEER_ETH_MALICIOUS = bytes32(uint256(uint160(0x9999)));
    bytes32 constant PEER_ARB_LEGIT = bytes32(uint256(uint160(0x2222)));

    function setUp() public {
        adapter = new CrossChainPeerAdapter(owner);

        vm.startPrank(owner);
        // ETH endpoint pinned to a specific peer
        adapter.setPeerPolicy(oapp, EID_ETH, true, PEER_ETH_LEGIT);
        // ARB endpoint allowed but no peer pinned (flexible)
        adapter.setPeerPolicy(oapp, EID_ARB, true, bytes32(0));
        // EID_BLOCKED deliberately not configured (defaults to disallowed)
        vm.stopPrank();
    }

    function _setPeerCalldata(uint32 eid, bytes32 peer) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setPeer(uint32,bytes32)", eid, peer);
    }

    // ============ intentHash ============

    function test_intentHash_isDeterministic() public view {
        bytes memory data = _setPeerCalldata(EID_ETH, PEER_ETH_LEGIT);
        bytes32 a = adapter.intentHash(oapp, 0, data);
        bytes32 b = adapter.intentHash(oapp, 0, data);
        assertEq(a, b);
        assertTrue(a != bytes32(0));
    }

    function test_intentHash_bindsEid() public view {
        bytes32 a = adapter.intentHash(oapp, 0, _setPeerCalldata(EID_ETH, PEER_ETH_LEGIT));
        bytes32 b = adapter.intentHash(oapp, 0, _setPeerCalldata(EID_ARB, PEER_ETH_LEGIT));
        assertTrue(a != b, "different eids must produce different intents");
    }

    function test_intentHash_bindsPeer() public view {
        bytes32 a = adapter.intentHash(oapp, 0, _setPeerCalldata(EID_ETH, PEER_ETH_LEGIT));
        bytes32 b = adapter.intentHash(oapp, 0, _setPeerCalldata(EID_ETH, PEER_ETH_MALICIOUS));
        assertTrue(a != b, "different peers must produce different intents");
    }

    function test_intentHash_bindsTarget() public view {
        bytes memory data = _setPeerCalldata(EID_ETH, PEER_ETH_LEGIT);
        bytes32 a = adapter.intentHash(oapp, 0, data);
        bytes32 b = adapter.intentHash(oappAlt, 0, data);
        assertTrue(a != b, "different oapps must produce different intents");
    }

    function test_intentHash_revertsOnUnknownSelector() public {
        bytes memory data = abi.encodeWithSignature("foo()");
        vm.expectRevert(CrossChainPeerAdapter.BadSelector.selector);
        adapter.intentHash(oapp, 0, data);
    }

    // ============ validate ============

    function test_validate_passesForRegisteredEidAndPeer() public view {
        bytes memory data = _setPeerCalldata(EID_ETH, PEER_ETH_LEGIT);
        adapter.validate(oapp, 0, data, bytes32(0));
    }

    function test_validate_passesForOpenEid_anyPeer() public view {
        // EID_ARB has no peer pinned (expectedPeer == 0); any peer is OK
        bytes memory data = _setPeerCalldata(EID_ARB, PEER_ARB_LEGIT);
        adapter.validate(oapp, 0, data, bytes32(0));
    }

    function test_validate_revertsOnUnregisteredEid() public {
        bytes memory data = _setPeerCalldata(EID_BLOCKED, PEER_ETH_LEGIT);
        vm.expectRevert(CrossChainPeerAdapter.EidNotAllowed.selector);
        adapter.validate(oapp, 0, data, bytes32(0));
    }

    function test_validate_revertsOnPeerMismatch_pinnedEid() public {
        // EID_ETH is pinned to PEER_ETH_LEGIT; PEER_ETH_MALICIOUS must fail
        bytes memory data = _setPeerCalldata(EID_ETH, PEER_ETH_MALICIOUS);
        vm.expectRevert(CrossChainPeerAdapter.PeerMismatch.selector);
        adapter.validate(oapp, 0, data, bytes32(0));
    }

    function test_validate_revertsForUnregisteredOapp() public {
        bytes memory data = _setPeerCalldata(EID_ETH, PEER_ETH_LEGIT);
        // oappAlt has no policy registered for any EID — defaults to disallowed
        vm.expectRevert(CrossChainPeerAdapter.EidNotAllowed.selector);
        adapter.validate(oappAlt, 0, data, bytes32(0));
    }

    function test_validate_revertsAfterEidDisabled() public {
        vm.prank(owner);
        adapter.setPeerPolicy(oapp, EID_ETH, false, PEER_ETH_LEGIT);

        bytes memory data = _setPeerCalldata(EID_ETH, PEER_ETH_LEGIT);
        vm.expectRevert(CrossChainPeerAdapter.EidNotAllowed.selector);
        adapter.validate(oapp, 0, data, bytes32(0));
    }

    // ============ access control ============

    function test_setPeerPolicy_revertsForNonOwner() public {
        vm.expectRevert(CrossChainPeerAdapter.NotOwner.selector);
        adapter.setPeerPolicy(oapp, EID_ETH, true, PEER_ETH_LEGIT);
    }

    // ============ adversarial: zero-address & invalid-EID checks ============

    /// @notice Adversarial review finding: deploying with `owner = address(0)`
    /// would brick the adapter (no peer policies could ever be set). Must
    /// fail closed at construction.
    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(CrossChainPeerAdapter.ZeroOwner.selector);
        new CrossChainPeerAdapter(address(0));
    }

    /// @notice Adversarial review finding: LayerZero V2 reserves EID 0 as
    /// invalid (the protocol treats it as "no chain"). Allowing the owner
    /// to register a policy for EID 0 is a foot-gun: it would let signers
    /// approve a `setPeer(0, peer)` call which is at best a no-op and at
    /// worst leaves a phantom policy slot. Adapter rejects EID 0 at
    /// policy-set time so it never enters the policy mapping.
    function test_setPeerPolicy_revertsOnZeroEid() public {
        vm.prank(owner);
        vm.expectRevert(CrossChainPeerAdapter.ZeroEid.selector);
        adapter.setPeerPolicy(oapp, 0, true, PEER_ETH_LEGIT);
    }

    /// @notice Adversarial review finding (corollary): without an
    /// owner-set policy for EID 0, validate() must still reject any
    /// `setPeer(0, peer)` calldata. Confirmed by the existing
    /// EidNotAllowed default — this test just locks the behavior.
    function test_validate_revertsOnZeroEid_noPolicySet() public {
        bytes memory data = _setPeerCalldata(0, PEER_ETH_LEGIT);
        vm.expectRevert(CrossChainPeerAdapter.EidNotAllowed.selector);
        adapter.validate(oapp, 0, data, bytes32(0));
    }
}
