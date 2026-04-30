// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntegrationBase, AttestPayload} from "./helpers/IntegrationBase.t.sol";
import {IntentGuardModule} from "../contracts/IntentGuardModule.sol";
import {CrossChainPeerAdapter} from "../contracts/CrossChainPeerAdapter.sol";

/// @notice Mock OApp target — records setPeer calls.
contract MockOApp {
    mapping(uint32 => bytes32) public peers;
    uint256 public callCount;

    function setPeer(uint32 eid, bytes32 peer) external {
        peers[eid] = peer;
        callCount += 1;
    }
}

contract IntegrationCrossChainPeerTest is IntegrationBase {
    CrossChainPeerAdapter adapter;
    MockOApp oapp;

    address adapterOwner = address(0xDEAF);

    uint32 constant EID_ETH = 30101;
    bytes32 constant PEER_ETH_LEGIT = bytes32(uint256(uint160(0x1111)));
    bytes32 constant PEER_ETH_MALICIOUS = bytes32(uint256(uint160(0x9999)));

    function setUp() public {
        _setUpBase();

        oapp = new MockOApp();
        adapter = new CrossChainPeerAdapter(adapterOwner);

        // EID_ETH allowlisted with peer pinned to PEER_ETH_LEGIT
        vm.prank(adapterOwner);
        adapter.setPeerPolicy(address(oapp), EID_ETH, true, PEER_ETH_LEGIT);

        _registerAdapter(address(oapp), address(adapter));
    }

    function _setPeerData(uint32 eid, bytes32 peer) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setPeer(uint32,bytes32)", eid, peer);
    }

    function _queueSetPeer(uint32 eid, bytes32 peer)
        internal
        returns (bytes32 proposalId, bytes memory data)
    {
        data = _setPeerData(eid, peer);
        bytes32 intent = adapter.intentHash(address(oapp), 0, data);
        AttestPayload memory p = _buildPayload(
            address(oapp), 0, address(adapter), intent, data,
            uint64(block.timestamp), uint64(block.timestamp) + 200
        );
        uint64 proposalExpiresAt = uint64(block.timestamp) + MIN_PROPOSAL_LIFETIME + 100;

        proposalId = module.queue(
            VAULT_ID, address(oapp), 0, data, intent, address(adapter),
            proposalExpiresAt, _twoSortedAttestations(p)
        );
    }

    function test_endToEnd_setPeerToPinnedSucceeds() public {
        (bytes32 proposalId, bytes memory data) = _queueSetPeer(EID_ETH, PEER_ETH_LEGIT);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);
        module.execute(proposalId, data);

        assertEq(oapp.peers(EID_ETH), PEER_ETH_LEGIT);
        assertEq(oapp.callCount(), 1);
    }

    function test_endToEnd_setPeerToMaliciousBlockedAtExecute() public {
        // Signers approve a peer-substitution attack: malicious peer on
        // an allowlisted EID. Adapter validate() catches it because the
        // EID is pinned to the legit peer.
        (bytes32 proposalId, bytes memory data) = _queueSetPeer(EID_ETH, PEER_ETH_MALICIOUS);

        vm.warp(block.timestamp + COOLOFF + EXECUTE_DELAY + 1);

        vm.expectRevert(CrossChainPeerAdapter.PeerMismatch.selector);
        module.execute(proposalId, data);

        assertEq(oapp.callCount(), 0);
        assertEq(oapp.peers(EID_ETH), bytes32(0));
    }
}
