// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IActionAdapter} from "./IntentGuardModule.sol";

/// @notice Adapter for LayerZero V2 OApp peer configuration. Targets the
/// canonical admin function:
///
///     setPeer(uint32 eid, bytes32 peer)
///
/// `setPeer` is the highest-leverage cross-chain admin surface: it
/// declares which contract on a remote chain the local OApp will trust
/// for inbound messages. Compromising this call lets an attacker
/// substitute a malicious peer and have the local OApp accept its
/// messages as authentic.
///
/// The adapter binds (eid, peer) into the signed intent and at execute
/// time enforces:
///
///   1. The EID is on a per-OApp allowlist (no peering to unknown chains)
///   2. The peer address matches the expected peer registered for that
///      (oapp, eid) pair, if one is set. A zero expected peer skips this
///      check (not recommended; allows changing peers within the EID's
///      allowlist).
///
/// Together with the intent binding, this means:
///   - Signers approve a specific (eid, peer)
///   - The adapter rejects unknown EIDs entirely
///   - The adapter rejects peer-substitution attacks even if signers were
///     fooled, when expectedPeer is registered
contract CrossChainPeerAdapter is IActionAdapter {
    bytes4 public constant SET_PEER_SELECTOR = bytes4(keccak256("setPeer(uint32,bytes32)"));

    bytes32 public constant SET_PEER_INTENT_TYPEHASH = keccak256(
        "LayerZeroSetPeer(address target,uint256 value,uint32 eid,bytes32 peer)"
    );

    struct PeerPolicy {
        bool eidAllowed;
        // Expected peer for (oapp, eid). Zero means "no peer binding"
        // (allowed but uncapped — the oapp owner chooses peer freely
        // within the EID allowlist). Setting a non-zero value pins the
        // peer to a specific value.
        bytes32 expectedPeer;
    }

    address public immutable owner;
    // peerPolicy[oappAddress][eid]
    mapping(address => mapping(uint32 => PeerPolicy)) public peerPolicy;

    event PeerPolicySet(address indexed oapp, uint32 indexed eid, bool allowed, bytes32 expectedPeer);

    error NotOwner();
    error BadSelector();
    error EidNotAllowed();
    error PeerMismatch();
    error ZeroOwner();
    error ZeroEid();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroOwner();
        owner = owner_;
    }

    /// @notice Register the policy for a given OApp + EID pair.
    /// @param oapp The local OApp contract address (the `target` in queue calls).
    /// @param eid The LayerZero V2 endpoint ID being peered to. EID 0 is
    /// reserved/invalid in LayerZero V2 and is always rejected here.
    /// @param allowed Whether peering to this EID is permitted at all.
    /// @param expectedPeer The expected remote-chain peer address for this EID.
    /// Zero allows any peer (subject only to intent binding). Non-zero pins.
    function setPeerPolicy(address oapp, uint32 eid, bool allowed, bytes32 expectedPeer) external onlyOwner {
        if (eid == 0) revert ZeroEid();
        peerPolicy[oapp][eid] = PeerPolicy({eidAllowed: allowed, expectedPeer: expectedPeer});
        emit PeerPolicySet(oapp, eid, allowed, expectedPeer);
    }

    /// @inheritdoc IActionAdapter
    function intentHash(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        (uint32 eid, bytes32 peer) = _decode(data);
        return keccak256(abi.encode(SET_PEER_INTENT_TYPEHASH, target, value, eid, peer));
    }

    /// @inheritdoc IActionAdapter
    function validate(address target, uint256, bytes calldata data, bytes32) external view {
        (uint32 eid, bytes32 peer) = _decode(data);
        PeerPolicy memory pol = peerPolicy[target][eid];
        if (!pol.eidAllowed) revert EidNotAllowed();
        if (pol.expectedPeer != bytes32(0) && pol.expectedPeer != peer) revert PeerMismatch();
    }

    function _decode(bytes calldata data) internal pure returns (uint32 eid, bytes32 peer) {
        if (data.length != 4 + 32 * 2) revert BadSelector();
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        if (selector != SET_PEER_SELECTOR) revert BadSelector();
        return abi.decode(data[4:], (uint32, bytes32));
    }
}
